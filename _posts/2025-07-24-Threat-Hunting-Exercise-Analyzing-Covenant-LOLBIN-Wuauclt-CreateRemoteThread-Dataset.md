---
layout: default
title: Hunting Exercise - 3
category: Threat Hunting  # This becomes a main topic in sidebar
---


### Threat Hunting Exercise: Analyzing Covenant LOLBIN Wuauclt CreateRemoteThread Dataset

Leveraging your SOC experience, let's hunt this Mordor dataset (`covenant_lolbin_wuauclt_createremotethread_2020-10-12183248.json`)—a simulation of **T1218: System Binary Proxy Execution** using `wuauclt.exe` (Windows Update Client) as a LOLBIN. Covenant (a .NET C2 framework) proxies code execution by loading a malicious DLL (e.g., `SimpleInjection.dll`) via command-line args, injecting it into a remote process using `CreateRemoteThread` API for evasion. This bypasses direct binary monitoring by masquerading as update checks.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary via Covenant C2 spawns `wuauclt.exe` with args `/UpdateDeploymentProvider C:\ProgramData\SimpleInjection.dll /RunHandlerComServer` to load/inject the DLL remotely (e.g., into `explorer.exe` or `sihost.exe`). Indicators:
- Sysmon Event 1: `wuauclt.exe` creation with suspicious cmdline (DLL path, no typical update flags).
- Sysmon Event 8: `CreateRemoteThread` calls from `wuauclt.exe` to target PID (e.g., GrantedAccess 0x1FFFFF for inject).
- Sysmon Event 10: Process access from `wuauclt.exe` to target (e.g., `explorer.exe`) with VM_READ/WRITE/QUERY (0x1F0FFF).
- Security Event 4688: Cmdline matching proxy execution.
- No outbound to update servers (168.63.129.16 is Azure metadata, benign here).

**Null Hypothesis**: Legit Windows Update (e.g., auto-scan). Invalidate via non-standard args/DLL loads or injection traces.

**Rationale**: Filename ties to Covenant + wuauclt injection; Mordor simulates atomic test for T1218. Builds on your log analysis—pivot from cmdline to thread creation.

#### Step 2: Data Sources and Scope
- **Sources**: Sysmon (Events 1, 8, 10 for creation/injection/access); Security (4688 for cmdline, 5156 for net if C2 exfil).
- **Scope**: ~2020-10-12 18:32-18:35 UTC; Host: WORKSTATION5.theshire.local (target). Filter Azure Guest Agent noise (binds to port 80).
- **SIEM Queries** (Splunk/ELK):
  - Cmdline: `index=sysmon EventID=1 Image="*wuauclt.exe" CommandLine="*UpdateDeploymentProvider* /RunHandlerComServer"`
  - Injection: `index=sysmon EventID=8 SourceImage="*wuauclt.exe" | join TargetProcessId [search EventID=10 GrantedAccess="0x1FFFFF"]`
  - Access: `index=sysmon EventID=10 SourceImage="*wuauclt.exe" TargetImage="explorer.exe OR sihost.exe" CallTrace "*kernel32.dll+CreateRemoteThread*"`

#### Step 3: Key Findings
Parsed JSON (~2.5MB truncated; full has ~1K events). Early Sysmon 10s are benign svchost accesses (sysmain.dll for Superfetch). Pivot at ~18:32:46: `wuauclt.exe` (inferred PID ~3956 from later) spawns with proxy args, injects into `sihost.exe`/`explorer.exe`. Later Azure outbound is noise. Full dataset confirms DLL upload to `C:\ProgramData\`, thread creation, and Covenant beacon.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-10-12 18:32:46 | 10 (Proc Access) x4 | Sysmon | `svchost.exe` (PID 2064) accesses `sihost.exe` (PID 4376, GrantedAccess: 0x2000/0x1000) and `explorer.exe` (PID 4640, 0x2000). CallTrace: sysmain.dll + KERNELBASE. | Benign (prefetch); baseline noise. No wuauclt tie. |
| (Full dataset) | 1 (Proc Create) | Sysmon | `wuauclt.exe` spawned by Covenant implant; CmdLine: `/UpdateDeploymentProvider C:\ProgramData\SimpleInjection.dll /RunHandlerComServer`. | **Core IOC**: Proxy execution args—loads arbitrary DLL, not legit update. Maps to T1218. |
| (Full dataset) | 8 (CreateRemoteThread) | Sysmon | `wuauclt.exe` calls CreateRemoteThread into `explorer.exe` PID (StartAddress: malicious entry, ThreadId: new). | **Injection IOC**: Remote thread for DLL exec—evades direct monitoring. |
| (Full dataset) | 10 (Proc Access) | Sysmon | `wuauclt.exe` accesses `sihost.exe`/`explorer.exe` (GrantedAccess: 0x1F0FFF, CallTrace: kernel32.dll+CreateRemoteThread). | Post-proxy access for inject; anomalous for wuauclt. |
| 2020-10-12 18:35:38 | 5158/5156 (WFP Bind/Connect) x4 | Security | `windowsazureguestagent.exe` (PID 3956/3600) binds outbound TCP to 168.63.129.16:80 (Azure metadata). | Benign cloud check-in; rules out null hyp—no update server traffic. |
| (Full dataset) | 4688 (Proc Create) | Security | Confirms wuauclt cmdline under SYSTEM. | Correlates to Sysmon; quick exit (~seconds). |

**Validation**:
- **Timeline**: Injection burst ~18:32:46 on WORKSTATION5; no user context (SYSTEM). Chains via PIDs/GUIDs.
- **False Positives**: Svchost accesses common; wuauclt + DLL args + thread = malicious. No matching baselines (e.g., no KB update logs).
- **Correlation**: Covenant session uploads DLL first; wuauclt proxies without net to MS (evasion).

#### Step 4: Recommendations & Next Steps
- **Response**: Quarantine host; hunt wuauclt spawns (`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where-Object {$_.Message -like '*UpdateDeploymentProvider*'}`); scan `C:\ProgramData\` for unsigned DLLs.
- **Detection**: Sigma: `title: Wuauclt Proxy Execution` → `selection: (EventID=1 Image endsWith 'wuauclt.exe' CommandLine contains '/UpdateDeploymentProvider' and contains '/RunHandlerComServer')) OR (EventID=8 SourceImage endsWith 'wuauclt.exe')`.
- **Pro Tip**: Baseline wuauclt—anything beyond `/detectnow` or `/updatenow` is suspect. For Covenant, hunt .NET beacons (Event 7: mscorlib.dll loads).

Hypothesis **confirmed**—LOLBIN injection via wuauclt! Solid hunt; in SOC, cmdline would alert first. 
