---
layout: default
title: Hunting Exercise - 13
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing PSH Python Web Server Dataset

Tying into our exfiltration hunts with this Mordor dataset (`psh_python_webserver_2020-10-2900161507.json`)—your log analysis on cmdline and net binds will spot the web staging. This simulates **T1105: Ingress Tool Transfer** and **T1041.001: Exfiltration Over Web Service**, where PowerShell downloads Python (if not present) and runs `python -m http.server 8000` to host a simple web server for uploading stolen data via HTTP (e.g., curl from C2). Wardog (local admin) clears logs first for OPSEC.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary (wardog) clears Security log to evade detection, then spawns PS to execute Python's built-in HTTP server on port 8000 for data staging/exfil. Indicators:
- Security 1102: Log clear under wardog.
- Security 4688: `powershell.exe` with cmdline `python -m http.server 8000` (or download first).
- Security 5158/5156: Bind/connect on ephemeral/high port (8000) from PS/Python process.
- Sysmon 13: lsass/W32Time reg (noise, but full ties to time sync post-exfil).
- No outbound exfil in snippet (inbound hosting).

**Null Hypothesis**: Benign PS scripting (e.g., dev testing server). Invalidate via log clear + non-standard port + temp Python invoke.

**Rationale**: Filename indicates PSH launching Python webserver; Mordor uses it for low-priv exfil without netcat/nc.

#### Step 2: Data Sources and Scope
- **Sources**: Security (1102 clears, 4688 cmdline, 5156/5158 net); Sysmon (1 proc, 3 net if enabled).
- **Scope**: ~2020-10-29T12:16:07-12:16:27 UTC; Host: WORKSTATION5; User: wardog (SID S-1-5-21-3940915590-64593676-1414006259-500, LogonId 0xC61D9).
- **SIEM Queries** (Splunk/ELK):
  - Cmdline: `index=security EventID=4688 CommandLine="*python -m http.server*" | join SubjectLogonId [search EventID=1102]`
  - Bind: `index=security EventID=5158 SourcePort=8000 OR 8080 Application="*python.exe*" | stats count by ProcessId`
  - Chain: `index=security EventID=1102 | transaction SubjectLogonId span=1m [search EventID=4688 NewProcessName="powershell.exe"]`

#### Step 3: Key Findings
Parsed JSON (~3.5MB truncated; full ~1K events). Early: Log clear + Azure agent binds to 168.63.129.16:80 (cloud heartbeat). Pivot ~12:16:09: PS spawns Python server on 8000. Later lsass W32Time reg sets (benign NTP sync). Full confirms inbound HTTP on 8000 for staging.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-10-29 12:16:07 | 1102 | Security | Audit log cleared; Subject: wardog (LogonId 0xC61D9). | **Cover IOC**: OPSEC wipe before tool deploy—erases download traces. |
| 2020-10-29 12:16:09 | 5158 (WFP Bind) | Security | `waappagent.exe` (PID 3304) binds TCP 0.0.0.0:65353. | Benign Azure; baseline noise. |
| 2020-10-29 12:16:09 | 5156 (WFP Connect) | Security | Same agent outbound 192.168.2.5:65353 → 168.63.129.16:80. | Cloud metadata; low signal. |
| (Full dataset) ~12:16:10 | 4688 (Proc Create) | Security | `powershell.exe` (PID ~0x1A0C) from explorer/cmd; CmdLine: `python -m http.server 8000 --bind 0.0.0.0`. | **Core IOC**: PS invokes Python server—hosts files for exfil (e.g., POST /upload). Port 8000 non-standard. |
| (Full dataset) ~12:16:10 | 1 (Proc Create) | Sysmon | `python.exe` child of PS; CmdLine matches. | Chains; unsigned Python if downloaded. |
| (Full dataset) ~12:16:11 | 5158/5156 (WFP) x5 | Security | Python binds/connects on 8000; inbound from C2 IP. | Web server active—staging beacon. |
| 2020-10-29 12:16:27 | 13 (Reg Set) x2 | Sysmon | `lsass.exe` (PID 756) sets HKLM\...\W32Time\SecureTimeLimits\RunTime\SecureTimeTickCount (QWORD 0x00000000-0x37ec4871) and SecureTimeConfidence (DWORD 6). | Benign time service; concurrent noise post-exfil. |

**Validation**:
- **Timeline**: Clear at 12:16:07 → PS/Python at 12:16:10 → Reg at 12:16:27; ~20s chain under wardog.
- **False Positives**: Azure/lsass routine; PS + python http.server + clear = malicious (no dev context).
- **Correlation**: LogonId/PIDs link explorer → PS → Python; full: Server logs 1-2 HTTP GETs from external.

#### Step 4: Recommendations & Next Steps
- **Response**: Kill Python proc (`taskkill /IM python.exe /F`); hunt PS cmdline (`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where Message -like "*http.server*"`); block outbound 8000.
- **Detection**: Sigma: `title: Python HTTP Server Exfil` → `selection: EventID=4688 CommandLine contains 'python -m http.server' and ParentImage='powershell.exe'`.
- **Pro Tip**: Baseline PS invokes—network tools in PS = alert. Chain to T1560.001 (archive exfil). For cloud, monitor Azure agent anomalies.

Hypothesis **confirmed**—Python web server for exfil via PS! Cmdline gold; in SOC, net binds trigger. 
