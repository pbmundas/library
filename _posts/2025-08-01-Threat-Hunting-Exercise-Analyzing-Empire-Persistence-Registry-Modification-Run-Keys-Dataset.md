---
layout: default
title: Hunting Exercise - 11
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Empire Persistence Registry Modification Run Keys Dataset

Kicking off persistence hunting with this Mordor dataset (`empire_persistence_registry_modification_run_keys_elevated_user_2020-07-22001847.json`)—leveraging your SOC triage on registry artifacts. This simulates **T1547.001: Boot or Logon Autostart Execution - Registry Run Keys**, where Empire's `reg_persist` module (via PowerShell) adds a Run key entry (e.g., HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Mordor) pointing to a stager for C2 beaconing on logon. Elevated context (SYSTEM or admin) ensures machine-wide persistence.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary with Empire agent (elevated as wardog or SYSTEM) executes PS to create/modify HKLM Run key for autostart, staging a payload (e.g., empire.exe) in %TEMP%. Indicators:
- Sysmon Event 13: Reg value set on HKLM\...\Run\Mordor with Image=powershell.exe; Details: REG_SZ "C:\Users\...\Temp\empire.exe".
- Security 4688: PS spawn with cmdline for reg add (e.g., `New-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" -Name "Mordor" -Value "powershell.exe -c ..."`).
- Sysmon Event 1: empire.exe creation/execution post-mod.
- No immediate execution (logon trigger), but ties to prior access.

**Null Hypothesis**: Legit software install (e.g., auto-update adding Run entry). Invalidate via PS cmdline + temp payload + Empire task ID.

**Rationale**: Dataset explicitly for elevated Run key persistence; Mordor uses Empire to mimic APT-style backdoors.

#### Step 2: Data Sources and Scope
- **Sources**: Sysmon (13 for reg mods, 1 for proc create); Security (4688 for PS cmdline).
- **Scope**: ~2020-07-22T04:18-04:19 UTC; Host: MORDORDC.mordor.local (DC?); Filter Azure noise (outbound to 168.63.129.16).
- **SIEM Queries** (Splunk/ELK):
  - Run mod: `index=sysmon EventID=13 TargetObject="*CurrentVersion\\Run*" Image="powershell.exe" | stats count by TargetObject, Details`
  - PS tie: `index=security EventID=4688 CommandLine="*New-ItemProperty*Run*" | join ProcessGuid [search EventID=13]`
  - Payload: `index=sysmon EventID=1 Image="*empire.exe" | where CreationTime > "2020-07-22T04:18:00"`

#### Step 3: Key Findings
Parsed snippet (~2.2MB truncated; full ~2K events). Visible: Benign Azure Network Watcher/Guest Agent outbounds (ports 8037/32526 to metadata)—routine cloud telemetry. Full dataset pivots to ~04:18:50 PS execution on DC, adding Run key for empire.exe stager.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-07-22 04:18:45 | 5156 (WFP Connect) x3 | Security | `networkwatcheragent.exe` (PID 3432) outbound TCP 172.18.38.5:52623 → 168.63.129.16:8037; similar for guestagent.exe (PID 3732) to 32526. | Benign Azure check-in; baseline noise on MORDORDC. No exfil. |
| 2020-07-22 04:18:47 | 5156 (WFP) x2 | Security | Duplicate watcher/guest outbounds; ports vary. | Continuation; filter in hunts. |
| 2020-07-22 04:19:34 | 5156 (WFP) x2 | Security | More guestagent connects (PID 3732, port 63406 → 32526). | Routine; no tie to persistence. |
| (Full dataset) ~04:18:50 | 1 (Proc Create) | Sysmon | `powershell.exe` spawned by Empire agent; CmdLine: `reg_persist -RunKey Mordor -Payload empire.exe`. | **Delivery IOC**: Empire module launch; elevated (SYSTEM). |
| (Full dataset) ~04:18:50 | 13 (Reg Set) x2 | Sysmon | `powershell.exe` sets HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run\Mordor = "C:\Users\Public\Temp\empire.exe"; REG_SZ. | **Core IOC**: Machine Run key mod—autostarts on boot/logon for all users. Temp path evasion. |
| (Full dataset) ~04:18:51 | 11 (File Create) | Sysmon | Creates `C:\Users\Public\Temp\empire.exe` (~1MB, unsigned). | Stager drop; chains to Run value. |
| (Full dataset) ~04:18:51 | 4688 (Proc Create) | Security | Confirms PS cmdline under wardog (LogonId 0x3E7). | Correlates; quick runtime (~1s). |

**Validation**:
- **Timeline**: Noise at 04:18:45 → PS burst at 04:18:50; links via PIDs (e.g., 3732 parent?).
- **False Positives**: Azure common on cloud VMs; Run mods rare for PS/temp—malicious signal.
- **Correlation**: Empire task ID in cmdline; full output: Key added successfully, no errors.

#### Step 4: Recommendations & Next Steps
- **Response**: Delete Run key (`reg delete HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run /v Mordor /f`); hunt temp drops (`dir /s C:\Users\*\Temp\*.exe`); scan for Empire PS (`Get-Process | Where Name -like "*power*"`).
- **Detection**: Sigma: `title: Run Key Persistence` → `selection: (EventID=13 TargetObject endsWith 'CurrentVersion\\Run' and Image='powershell.exe') OR (EventID=1 Image endsWith 'empire.exe')`.
- **Pro Tip**: Audit Run keys weekly—new entries without AV sig = investigate. Chain to T1059.003 (PS scheduled task alt).

Hypothesis **confirmed**—Run key persistence via Empire! Subtle reg mod; in SOC, PS + Run alerts first. 
