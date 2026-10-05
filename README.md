# Mini SOC Pipeline — Detection → Triage → Response

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://www.python.org/)
[![MITRE ATT&CK](https://img.shields.io/badge/MITRE-ATT%26CK-red?style=flat-square)](https://attack.mitre.org/)
[![Sigma](https://img.shields.io/badge/Sigma-Rules-yellow?style=flat-square)](https://sigmahq.io/)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![SOC Lab](https://img.shields.io/badge/Lab-SOC%20Pipeline-orange?style=flat-square)](#)

> Lightweight, dependency-free SOC lab that simulates a full attack chain and automates detection, triage, and incident scoring using synthetic Sysmon, Windows Security, and Network logs + Sigma rules.

Perfect for **SOC Analyst portfolios, interviews, and Blue Team training** — clone, run, and get a triaged incident report in 10 seconds.

---

## 📸 Demo

```
[+] Triage complete: 6 alerts, max_score=95, incident=True
[+] Report: reports/triage_report.json

RDP Brute Force Attempt (T1110.001) ............ HIGH
Encoded PowerShell Download Cradle (T1059.001) .. HIGH
Mimikatz Execution (T1003.001) .................. CRITICAL
PsExec Lateral Movement (T1570) ................ HIGH
```

Full JSON report generated at `reports/triage_report.json` — sorted by severity, with evidence, MITRE mapping, and remediation recommendations.

---

## 🎯 What It Simulates

End-to-end attack scenario timeline (`192.168.1.105` → `DC01` → `WS01` → `WS02`):

| Time | Phase | Event |
|------|-------|-------|
| T+3-5m | **Recon / Initial Access** | RDP Brute Force — 5x `4625` Failed Logons (LogonType 10) |
| T+6m | **Initial Access Success** | `4624` Successful RDP + `4672` SeDebugPrivilege assigned |
| T+7m | **Execution** | Encoded PowerShell `-Enc` download cradle → `payload.ps1` |
| T+9m | **Credential Access** | `mimikatz.exe sekurlsa::logonpasswords` + LSASS `0x1010` access (Sysmon EID 10) |
| T+12m | **Lateral Movement** | `PSEXESVC` service install (`7045`) + SMB `445` to `WS02` |

---

## ✨ Features

- **Zero dependencies** — pure Python 3, no `pip install` needed
- **3 Log Sources:** `sysmon.jsonl` (EVTX-like), `security.csv` (4624/4625/4688/7045/4672), `network_traffic.csv` (Zeek/NetFlow style)
- **5 Sigma Rules** — `rules/sigma/` (brute_force, mimikatz, powershell_encoded, psexec)
- **Triage Engine** — correlation, deduplication, severity scoring, incident declaration (`max_score >= 75`)
- **Base64 Decoding** — auto-decodes PowerShell `-EncodedCommand` preview
- **3 Incident Playbooks** — `playbooks/PB-0x_*.md` with triage → containment → recovery steps
- **Regeneratable Logs** — `generate_logs.py` with deterministic seed for consistent demos

---

## 🏗️ Architecture

```
Detection (Sigma Rules) → Parsing (Sysmon/Security/Network) → Correlation & Scoring → JSON Report → Playbook Response
```

```
mini-soc-pipeline/
├── logs/
│   ├── sysmon.jsonl            # Synthetic Sysmon events (EID 1, 3, 10, 11)
│   ├── security.csv            # Windows Security Events
│   └── network_traffic.csv     # Network flows (RDP 3389, SMB 445, HTTP 80)
├── rules/
│   └── sigma/                  # Sigma YAML detections
│       ├── brute_force_rdp.yml
│       ├── mimikatz_lsass.yml
│       ├── powershell_encoded.yml
│       └── psexec_lateral.yml
├── scripts/
│   ├── generate_logs.py        # Regenerate synthetic logs
│   └── triage_engine.py        # Detection + triage + scoring engine
├── playbooks/
│   ├── PB-01_brute_force.md
│   ├── PB-02_malware_execution.md
│   └── PB-03_lateral_movement.md
└── reports/
    └── triage_report.json      # Generated output (gitignored recommended)
```

---

## 🧠 Detection Coverage

| Alert | Log Source | Event IDs | MITRE ATT&CK | Severity |
|-------|------------|-----------|--------------|----------|
| RDP Brute Force Attempt | Security | 4625 (x5) + 4624 | **T1110.001** Brute Force | Medium → High* |
| Encoded PowerShell Download Cradle | Sysmon | 1 (powershell -Enc) | **T1059.001** PowerShell | High |
| Mimikatz Execution | Sysmon | 1 (mimikatz.exe) | **T1003.001** LSASS Memory | Critical |
| Suspicious LSASS Access | Sysmon | 10 (GrantedAccess 0x1010) | **T1003.001** | High |
| PsExec Lateral Movement | Sysmon | 1, 3 (PSEXESVC) | **T1570** Lateral Tool Transfer | High |
| PsExec Service Installed | Security | 7045 | **T1570** | High |

\* `High` if followed by `4624` success, otherwise `Medium`. Incident declared when `max_score >= 75`.

Kill Chain Coverage: `Reconnaissance → Initial Access (T1110) → Execution (T1059) → Credential Access (T1003) → Lateral Movement (T1570)`

---

## ✅ Prerequisites

- **Python 3.8+** (`python --version`)
- **Git** (for cloning)
- No external Python packages required

---

## 🚀 How to Run

### 1. Clone

```bash
git clone https://github.com/ayoub-abdelouahab/mini-soc-pipeline.git
cd mini-soc-pipeline
```

### 2. (Optional) Regenerate Logs

Logs are already included. Regenerate to reset to a clean attack scenario:

```powershell
# Windows PowerShell
python scripts/generate_logs.py
```

```bash
# Linux / macOS
python3 scripts/generate_logs.py
```
Output:
```
Generated 13 sysmon, 12 security, 10 network events -> logs/
```

### 3. Run Triage Engine

```powershell
# Windows PowerShell
python scripts/triage_engine.py --logs logs --rules rules/sigma --output reports/triage_report.json
```

```bash
# Linux / macOS
python3 scripts/triage_engine.py --logs logs --rules rules/sigma --output reports/triage_report.json
```

**CLI Options:**

| Flag | Default | Description |
|------|---------|-------------|
| `--logs` | `logs` | Path to log directory |
| `--rules` | `rules/sigma` | Path to Sigma rules (reserved for future use) |
| `--output` | `reports/triage_report.json` | Output report path |

### 4. Review the Report

```powershell
# Windows
type reports\triage_report.json
# or
Get-Content reports/triage_report.json | ConvertFrom-Json | Format-List

# Linux / macOS
cat reports/triage_report.json | jq .
cat reports/triage_report.json
```

Expected output:
```
[+] Triage complete: 6 alerts, max_score=95, incident=True
[+] Report: C:\...\mini-soc-pipeline\reports\triage_report.json
```

### 5. Investigate with Playbooks

After triage, follow the matching playbook:

- `PB-01_brute_force.md` — for `test-soc-001` (T1110.001)
- `PB-02_malware_execution.md` — for `test-soc-002` / `test-soc-003` (T1059.001 / T1003.001)
- `PB-03_lateral_movement.md` — for `test-soc-004` (T1570)

---

## 📄 Example Report (`reports/triage_report.json`)

```json
{
  "generated_at": "2026-10-04T22:52:17Z",
  "log_counts": { "sysmon": 13, "security": 12, "network": 10 },
  "alert_count": 6,
  "max_severity_score": 95,
  "incident_declared": true,
  "kill_chain_coverage": [
    "Reconnaissance",
    "Initial Access (T1110)",
    "Execution (T1059)",
    "Credential Access (T1003)",
    "Lateral Movement (T1570)"
  ],
  "alerts": [
    {
      "rule_id": "test-soc-003",
      "title": "Mimikatz Execution",
      "severity": "critical",
      "technique": "T1003.001",
      "computer": "WS01.corp.local",
      "recommendation": "Isolate host immediately, rotate credentials..."
    }
  ]
}
```

---

## 🛠️ Customization

**Add a new detection:** Edit `scripts/triage_engine.py` → `detect()` function, then add a Sigma YAML in `rules/sigma/`.

**Change thresholds:** Edit `SEVERITY_SCORE` and `cnt >= 5` brute-force threshold in `triage_engine.py`.

**Create new logs:** Modify `scripts/generate_logs.py` arrays (`sysmon_events`, `sec_rows`, `net_rows`) and re-run.

---

## 🧪 Troubleshooting

| Issue | Fix |
|-------|-----|
| `python not found` | Use `python3` or `py -3` on Windows |
| `No alerts found` | Regenerate logs: `python scripts/generate_logs.py` then re-run triage |
| `FileNotFoundError: logs/...` | Run from project root, not from `scripts/` |
| Report not updating | Delete `reports/triage_report.json` and re-run |

---

## 🗺️ Roadmap

- [ ] Add Sigma rule parser (pySigma) instead of hardcoded detections
- [ ] Export to Splunk / Elastic SIEM format
- [ ] Add MITRE Navigator layer JSON
- [ ] SOAR playbook automation (block IP via API mock)
- [ ] Add Wazuh / Sysmon XML EVTX ingestion

---

## 🤝 Contributing

PRs welcome! For major changes, open an issue first.

```bash
git checkout -b feature/my-detection
git commit -m "feat: add detection for X"
git push origin feature/my-detection
```

---

## 📜 License

MIT — free for personal and educational use.

---

## 👤 Author

**Ayoub Abdelouahab Boucetta** — SOC Analyst | Blue Team Enthusiast

- GitHub: [@ayoub-abdelouahab](https://github.com/ayoub-abdelouahab)
- Project: `mini-soc-pipeline`

> Built to demonstrate SIEM fundamentals: Windows Event Logs (4624/4625/4688), Sysmon, Network Traffic Analysis, and Alert Theory — mapped to MITRE ATT&CK.

---

### Push to GitHub (if not already pushed)

```bash
git add README.md
git commit -m "docs: add comprehensive README with run instructions"
git push origin main
```
