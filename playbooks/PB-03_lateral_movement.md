# PB-03 — Lateral Movement via PsExec

**Trigger:** `test-soc-004` — PSEXESVC (7045 + Sysmon 1/3 on 445/135)
**Severity:** High | **MITRE:** T1570 / T1021.002

## 1. Triage
- Security 7045 `Service PSEXESVC installed` on WS02 + Sysmon PSEXESVC.exe as child of services.exe
- Network 445/135 from WS01 (10.0.1.10 -> 10.0.1.12) — confirm timeframe after mimikatz (credential reuse)
- Validate: legitimate admin? Check change ticket / admin workstation

## 2. Containment
- Isolate both WS01 and WS02
- Disable reused credential (Administrator), revoke sessions
- Block SMB lateral if not business-justified between workstations

## 3. Investigation
- Timeline: brute force (14:03) -> RDP success (14:06) -> Enc PS (14:07) -> Mimikatz (14:09) -> PsExec (14:12) — full kill chain
- Hunt: `EventID=7045 ServiceName=*PSEXESVC*` last 30d, `DestinationPort=445` from non-admin hosts

## 4. Recovery
- Remove PSEXESVC service, forensic image, credential rotation
- Harden: restrict PsExec via AppLocker, disable SMBv1, segment workstation VLANs

## 5. Reporting
- Link alerts together in case: triage_report.json shows incident_declared=true, max_score 95
