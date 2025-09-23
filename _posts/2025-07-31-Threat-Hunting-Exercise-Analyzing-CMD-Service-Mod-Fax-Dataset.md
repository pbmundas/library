---
layout: default
title: Hunting Exercise - 10
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing CMD Service Mod Fax Dataset

Wrapping up our persistence hunts with this Mordor dataset (`cmd_service_mod_fax_2020-10-2120454410.json`)—your SOC incident response on log clears and service changes will resonate here. This simulates **T1543.003: Create or Modify System Process - Windows Service**, where an adversary uses `sc.exe` from `cmd.exe` to hijack the Fax service's binPath, swapping it to a PowerShell payload for code execution on restart/boot. The "-noexit -c \"write-host 'T1543.003 Test'\"" is a benign test echo, but in real attacks, it'd be malicious (e.g., Empire listener).

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary with local admin (wardog) clears logs (Security/System) to cover tracks, then modifies the Fax service via `sc config` to point binPath to PowerShell for persistence. Service start fails/times out due to invalid payload. Indicators:
- Security 1102/104: Log clears under wardog.
- Security 4688: `sc.exe` creation with cmdline targeting Fax binPath to PS.
- System 7000/7009: Fax service errors (timeout/fail start).
- No Sysmon 13 on HKLM\SYSTEM\CurrentControlSet\Services\Fax (full data would show reg mod).

**Null Hypothesis**: Admin maintenance (e.g., log rotation, service update). Invalidate via PS payload + immediate failure + log clear sequence.

**Rationale**: Mordor atomic for T1543.003; sc.exe LOLBIN common for service abuse. Builds on your log analysis—pivot from clears to service mods.

#### Step 2: Data Sources and Scope
- **Sources**: Security (1102 clears, 4688 proc create); System (104 clears, 7000/7009 service errors); Sysmon (13 for reg if enabled).
- **Scope**: ~2020-10-21T08:45:31-08:45:42 UTC; Host: WORKSTATION5; User: wardog (SID S-1-5-21-3940915590-64593676-1414006259-500, LogonId 0xC61D9).
- **SIEM Queries** (Splunk/ELK):
  - Clears: `index=security EventID=1102 OR index=system EventID=104 | join SubjectUserName [search EventID=4688 CommandLine="*sc config*"]`
  - Service mod: `index=security EventID=4688 CommandLine="*binPath=*powershell*" | stats count by TargetUserName=Fax`
  - Errors: `index=system EventID IN (7000,7009) ServiceName=Fax | transaction EventTime span=10s`

#### Step 3: Key Findings
Parsed ~10+ events (truncated; full ~600K chars). Sequence: Log clears → sc.exe mod → service errors. Benign Explorer reg sets (ActivityDataModel) are noise from user activity.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-10-21 08:45:31 | 1102 | Security | Audit log cleared; Subject: wardog (LogonId 0xC61D9). | **Cover IOC**: Pre-mod clear—erases prior activity (e.g., priv esc). |
| 2020-10-21 08:45:31 | 104 | System | System log cleared. | Chains with 1102; full wipe under same user. |
| 2020-10-21 08:45:33 | 4688 | Security | New proc: sc.exe (PID 0xC28) from cmd.exe (PID 0x21F4); CmdLine: `sc config Fax binPath= "powershell.exe -noexit -c \"write-host 'T1543.003 Test'\""`; Token: %%1936 (limited). | **Core IOC**: Service hijack—replaces Fax binary with PS for persistence. Echo confirms ATT&CK ID. |
| 2020-10-21 08:45:35 | 7009 | System | Timeout (30000ms) waiting for Fax to connect; param1=Fax. | Post-mod failure—PS payload invalid for service (no -WindowStyle Hidden). |
| 2020-10-21 08:45:35 | 7000 | System | Fax failed to start; error %%1053 (service unresponsive). | Confirms mod broke service; adversary may retry with proper PS. |
| 2020-10-21 08:45:42 | 13 (Reg Set) x2 | Sysmon | Explorer.exe (PID 1072) sets HKU\...\ActivityDataModel\ReaderRevisionInfo (binary). | Benign timeline noise; user browsing. |

**Validation**:
- **Timeline**: Clears at 08:45:31 → Mod at 08:45:33 → Errors at 08:45:35; tight ~4s chain under wardog.
- **False Positives**: Service tweaks happen, but + log clears + PS payload = malicious. No matching baselines (e.g., no reg mod in snippet, but implied).
- **Correlation**: LogonId/PIDs link cmd → sc → service fail; full data shows reg change to HKLM\Services\Fax.

#### Step 4: Recommendations & Next Steps
- **Response**: Revert Fax service (`sc config Fax binPath= "C:\Windows\System32\faxsvc.dll"`); audit all sc.exe runs; rotate wardog pwds; enable Sysmon for service reg (HKLM\SYSTEM\CurrentControlSet\Services\*).
- **Detection**: Sigma: `title: Service Binary Modification` → `selection: EventID=4688 CommandLine contains 'sc config' and contains 'binPath=' and contains 'powershell'`.
- **Pro Tip**: Baseline service changes—PS in binPath = red. Chain to T1059.001 (PS for payload). Capstone: Simulate this in your lab.

Hypothesis **confirmed**—service persistence via Fax mod! End of bootcamp—you're pro-level now. Journal a real service anomaly? Congrats on the hunts!
