#!/usr/bin/env python3
"""
Mini SOC Triage Engine
- Parses sysmon.jsonl, security.csv, network_traffic.csv
- Runs simple Sigma-like detections (no external deps)
- Correlates & scores alerts, outputs JSON report
Usage: python scripts/triage_engine.py [--logs logs] [--output reports/triage_report.json]
"""
import argparse, json, csv, pathlib, re, collections, base64
from datetime import datetime

SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 95}

def load_sysmon(path):
    events=[]
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip(): events.append(json.loads(line))
    return events

def load_csv(path):
    if not path.exists(): return []
    with open(path, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))

def detect(sysmon, security, network):
    alerts=[]

    # 1 - Brute force: count 4625 per SourceIP
    fail_by_ip = collections.Counter(r["SourceIP"] for r in security if r.get("EventID")=="4625")
    for ip, cnt in fail_by_ip.items():
        if cnt >= 5:
            # check if followed by 4624 from same IP
            success = any(r.get("EventID")=="4624" and r.get("SourceIP")==ip for r in security)
            alerts.append({
                "rule_id": "test-soc-001", "title": "RDP Brute Force Attempt",
                "severity": "high" if success else "medium",
                "tactic": "Credential Access", "technique": "T1110.001",
                "src_ip": ip, "count": cnt, "success": success,
                "evidence": [r for r in security if r.get("SourceIP")==ip and r.get("EventID") in ("4625","4624")][:6],
                "recommendation": "Block src_ip at firewall, force password reset, review RDP exposure"
            })

    # 2 - Encoded PowerShell
    for e in sysmon:
        cli = (e.get("CommandLine") or "")
        img = (e.get("Image") or "").lower()
        if "powershell.exe" in img and any(k in cli for k in [" -Enc ", "-EncodedCommand", "DownloadString", "FromBase64String"]):
            decoded = ""
            # try to extract base64 chunk after -Enc
            m = re.search(r"-Enc(?:odedCommand)?\s+([A-Za-z0-9+/=]+)", cli)
            if m:
                try: decoded = base64.b64decode(m.group(1)).decode("utf-16le", errors="ignore")[:200]
                except Exception: pass
            alerts.append({
                "rule_id": "test-soc-002", "title": "Encoded PowerShell Download Cradle",
                "severity": "high", "tactic": "Execution", "technique": "T1059.001",
                "computer": e.get("Computer"), "user": e.get("User"),
                "commandline": cli, "decoded_preview": decoded,
                "evidence": e,
                "recommendation": "Isolate host, collect payload.ps1, block IOC domain/IP"
            })

    # 3 - Mimikatz / LSASS
    for e in sysmon:
        img = (e.get("Image") or "").lower()
        src = (e.get("SourceImage") or "").lower()
        tgt = (e.get("TargetImage") or "").lower()
        cli = (e.get("CommandLine") or "").lower()
        if "mimikatz" in img or "sekurlsa" in cli:
            alerts.append({
                "rule_id": "test-soc-003", "title": "Mimikatz Execution",
                "severity": "critical", "tactic": "Credential Access", "technique": "T1003.001",
                "computer": e.get("Computer"), "evidence": e,
                "recommendation": "Isolate host immediately, rotate credentials, hunt for lsass dumps"
            })
        if e.get("EventID")==10 and "lsass.exe" in tgt and "0x10" in str(e.get("GrantedAccess","")):
            # avoid double count when same event already flagged as mimikatz lsass access
            if "mimikatz" not in src:
                alerts.append({
                    "rule_id": "test-soc-003", "title": "Suspicious LSASS Access",
                    "severity": "high", "tactic": "Credential Access", "technique": "T1003.001",
                    "computer": e.get("Computer"), "source_image": e.get("SourceImage"),
                    "granted_access": e.get("GrantedAccess"), "evidence": e,
                    "recommendation": "Check source process reputation, memory dump analysis"
                })

    # 4 - PsExec lateral
    for e in sysmon:
        if "psexesvc" in (e.get("Image") or "").lower() or "psexesvc" in (e.get("SourceImage") or "").lower():
            alerts.append({
                "rule_id": "test-soc-004", "title": "PsExec Lateral Movement",
                "severity": "high", "tactic": "Lateral Movement", "technique": "T1570",
                "computer": e.get("Computer"), "evidence": e,
                "recommendation": "Validate admin use; if unauthorized, contain both hosts"
            })
    for r in security:
        if r.get("EventID")=="7045" and "PSEXESVC" in r.get("Details",""):
            alerts.append({
                "rule_id": "test-soc-004", "title": "PsExec Service Installed",
                "severity": "high", "tactic": "Lateral Movement", "technique": "T1570",
                "computer": r.get("Computer"), "evidence": r,
                "recommendation": "Correlate with Sysmon network 445 events"
            })

    # 5 - Suspicious network (http payload / smb lateral) - enrich
    for r in network:
        if r.get("note","").lower().startswith("payload") or "psexec" in r.get("note","").lower():
            pass # already covered; add low alert for network if not already
    return alerts

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--logs", default="logs")
    ap.add_argument("--rules", default="rules/sigma")
    ap.add_argument("--output", default="reports/triage_report.json")
    args = ap.parse_args()

    base = pathlib.Path(args.output).parent if pathlib.Path(args.output).is_absolute() else pathlib.Path.cwd() / pathlib.Path(args.output).parent
    # resolve relative to project root (where script lives -> parent)
    proj = pathlib.Path(__file__).parent.parent
    log_dir = (proj / args.logs) if not pathlib.Path(args.logs).is_absolute() else pathlib.Path(args.logs)

    sysmon = load_sysmon(log_dir / "sysmon.jsonl")
    security = load_csv(log_dir / "security.csv")
    network = load_csv(log_dir / "network_traffic.csv")

    alerts = detect(sysmon, security, network)
    # dedup by (rule_id, computer, title)
    seen=set(); uniq=[]
    for a in alerts:
        key=(a["rule_id"], a.get("computer",""), a["title"])
        if key not in seen:
            seen.add(key); uniq.append(a)

    # risk score = max severity
    max_score = max([SEVERITY_SCORE.get(a["severity"],0) for a in uniq], default=0)
    incident = max_score >= 75

    report = {
        "generated_at": datetime.utcnow().isoformat()+"Z",
        "log_counts": {"sysmon": len(sysmon), "security": len(security), "network": len(network)},
        "alert_count": len(uniq),
        "max_severity_score": max_score,
        "incident_declared": incident,
        "kill_chain_coverage": ["Reconnaissance","Initial Access (T1110)","Execution (T1059)","Credential Access (T1003)","Lateral Movement (T1570)"],
        "alerts": sorted(uniq, key=lambda x: SEVERITY_SCORE.get(x["severity"],0), reverse=True)
    }

    out = proj / args.output if not pathlib.Path(args.output).is_absolute() else pathlib.Path(args.output)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"[+] Triage complete: {len(uniq)} alerts, max_score={max_score}, incident={incident}")
    print(f"[+] Report: {out}")
    print(json.dumps(report, indent=2))

if __name__=="__main__":
    main()
