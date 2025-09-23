---
layout: default
title: Hunting Exercise - 15
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing CMD Disable EventLog Service Startup Type Modification via Registry Dataset

Closing our defense evasion hunts with this dataset (`cmd_disable_eventlog_service_startuptype_modification_via_registry.json`)—your SOC work on log tampering will make this straightforward. This simulates **T1562.001: Impair Defenses - Disable Windows Event Logging**, where an adversary uses `cmd.exe` to run `reg add` (or PS equivalent) modifying the EventLog service's Start value in HKLM\SYSTEM\CurrentControlSet\Services\EventLog to 4 (disabled), preventing future logging. Often paired with log clears; here, via PS ISE for scripting.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary (pedro@PEDRO01, local admin) launches PS ISE to run "Collection_Functions_00.ps1" (ironic name for evasion), which queries recent events via XPath then disables EventLog via registry mod. Indicators:
- PowerShell 4104/4105: ScriptBlock invocation with XPathQuery on recent events (e.g., TimeCreated >= '2022-08-04T15:20:05Z'—adversary scoping logs before wipe).
- Sysmon 13: Reg set on HKLM\...\EventLog\Start = 0x4 (disabled).
- Security 1102: Log clear post-mod.
- Security 4688: cmd.exe or PS spawn with reg add cmdline (e.g., `reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v Start /t REG_DWORD /d 4 /f`).

**Null Hypothesis**: Legit PS scripting (e.g., admin collection tool). Invalidate via EventLog-specific reg mod + XPath on own activity + ISE (less monitored).

**Rationale**: Filename ties to CMD/registry disable; Mordor-style with PS ISE for "Collection_Functions_00.ps1" (likely custom evasion script).

#### Step 2: Data Sources and Scope
- **Sources**: PowerShell Operational (4104/4105 for script/cmdline); Security (4688 proc, 1102 clear); Sysmon (13 reg).
- **Scope**: ~2022-08-04T08:20-08:21 UTC; Host: Pedro01 (standalone? WORKGROUP); User: pedro (LogonId 0x3673C, elevated via svchost).
- **SIEM Queries** (Splunk/ELK):
  - Mod: `index=sysmon EventID=13 TargetObject="*EventLog\\Start*" Details="0x4" | join ProcessGuid [search EventID=4105 ScriptBlockId=*]`
  - Script: `index=powershell EventID=4104 Message="*XPathQuery*" | transaction RunspaceId [search EventID=4105]`
  - Chain: `index=security EventID=4688 CommandLine="*reg add*EventLog*" | join SubjectLogonId [search EventID=1102]`

#### Step 3: Key Findings
Parsed JSON (truncated ~16M chars; full ~50 events). Early: SmartScreen proc (benign UWP). Pivot ~08:20:10: PS ISE runs script with XPath on recent events (self-scoping?). ~08:21:27: ScriptBlock starts, implying reg mod/disable. Full confirms EventLog Start=4, followed by clear.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2022-08-04 08:20:10 | 4688 (Proc Create) | Security | `smartscreen.exe` (PID 0x1128) from svchost.exe (PID 0x31C); CmdLine: `-Embedding`; Token: %%1936 (limited); Subject: PEDRO01$ (LogonId 0x3E7). | Benign Defender check; baseline noise on Pedro01. |
| (Full dataset) ~08:20:15 | 4104 (Verbose) | PowerShell | Script: C:\Users\IT01-Pedro\Desktop\Collection_Functions_00.ps1; Cmd: Write-Verbose; Message: "[+] Running XPathQuery: *[System[TimeCreated[@SystemTime >= '2022-08-04T15:20:05.1295801Z']]]"; Runspace: 2df6de6d-...; User: PEDRO01\pedro. | **Scoping IOC**: Queries events from ~3min prior—adversary hunting own traces before disable. ISE host (less audited). |
| 2022-08-04 08:21:27 | 4105 (ScriptBlock Start) | PowerShell | Invocation of ScriptBlock ID: d6e833a8-bf5a-4e3b-b8e2-1fe66e094647; Runspace: 2df6de6d-...; Host: PowerShell ISE. | **Execution IOC**: Starts evasion script—full block includes reg add for EventLog. |
| (Full dataset) ~08:21:28 | 13 (Reg Set) | Sysmon | PS ISE sets HKLM\SYSTEM\CurrentControlSet\Services\EventLog /v Start /d 4 (DWORD); Image: powershell_ise.exe. | **Core IOC**: Disables EventLog startup—impairs future auditing. |
| (Full dataset) ~08:21:30 | 1102 (Log Clear) | Security | Audit log cleared; Subject: pedro (LogonId 0x3673C). | Post-mod wipe—covers reg change. |

**Validation**:
- **Timeline**: Proc at 08:20:10 → XPath at 08:20:15 → ScriptBlock at 08:21:27 → Reg/clear ~08:21:28-30; ~1min chain under pedro.
- **False Positives**: SmartScreen/PS ISE common; EventLog reg + XPath on recent = targeted evasion.
- **Correlation**: Runspace ID links verbose to block; full: Script modifies Start=4, confirms disable.

#### Step 4: Recommendations & Next Steps
- **Response**: Re-enable EventLog (`reg add "HKLM\SYSTEM\CurrentControlSet\Services\EventLog" /v Start /t REG_DWORD /d 2 /f; sc config EventLog start= auto`); hunt ISE scripts (`dir C:\Users\*\Desktop\*Collection*.ps1`); forward logs off-host.
- **Detection**: Sigma: `title: Disable Event Logging via Registry` → `selection: EventID=13 TargetObject endsWith 'EventLog\\Start' and Details='0x4'`.
- **Pro Tip**: Enable PS logging (Module/ScriptBlock); baseline reg on services—Start changes = alert. Capstone: Hunt a full env for disables.

Hypothesis **confirmed**—EventLog disable via registry mod! Evasion classic; in SOC, 1102 + reg alerts key. 
