# PB-01 — RDP Brute Force Response

**Trigger:** Sigma `test-soc-001` — ≥5 EventID 4625 (LogonType 10) + 4624 success
**Severity:** High (Critical if success) | **MITRE:** T1110.001

## 1. Triage (5 min)
- Verify `security.csv` / SIEM: `EventID=4625 | stats count by SourceIP` — confirm burst <5min
- Check `network_traffic.csv`: RDP 3389 from external IP `192.168.1.105`
- Check for success 4624 + 4672 (SeDebugPrivilege) → confirms compromise

## 2. Containment
- Block SrcIP at perimeter FW / VPN
- Disable TargetUserName (`Administrator`) or force reset + MFA
- Isolate `DC01.corp.local` / `WS01.corp.local` if RDP session active (`mstsc.exe`)

## 3. Investigation
- Sysmon: parent of `mstsc.exe`, any `powershell -Enc` after logon
- Hunt: `4625` across 7d for same IP/user

## 4. Recovery
- Review RDP exposure — restrict to jump host, enforce account lockout (5 attempts/15min)

## 5. Close
- Alert note: false positive if single user typo (<3 fails, no success)
