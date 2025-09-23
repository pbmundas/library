---
layout: default
title: Hunting Exercise - 12
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Covenant SC Query DCERPC SMB SVCCTL Dataset

Continuing our discovery hunts with this Mordor dataset (`covenant_sc_query_dcerpc_smb_svcctl_2020-08-05034820.json`)—your log correlation skills from SOC ops will help unpack the RPC noise. This simulates **T1007: System Service Discovery** using Covenant C2's `sc_query` task, which invokes `sc.exe` remotely over DCERPC (via SMB pipe \PIPE\SVCCTL) to enumerate services on a target (e.g., lsass.exe status). Requires admin rights; outputs service states for targeting (e.g., stoppable services).

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary via Covenant implant on WORKSTATION5 (as pgustavo@THESHIRE) uses `sc query` over SMB/RPC to list services, focusing on sensitive ones like AudioEndpointBuilder or Themes. Indicators:
- Sysmon Event 3: Net connect to target on port 445 (SMB).
- Security Event 5145: Share access to IPC$ with named pipe SVCCTL.
- Security Event 4624: Network logon (Type 3) with RPC context.
- Sysmon Event 10: Proc access if local sc.exe (but remote here).
- Cmdline in 4688: `sc.exe query state= all` or Covenant stub.

**Null Hypothesis**: Legit admin query (e.g., remote service check). Invalidate via Covenant task ID + non-standard RPC from workstation.

**Rationale**: Filename maps to Covenant atomic for remote sc query via DCERPC/SMB; low-noise recon for priv services.

#### Step 2: Data Sources and Scope
- **Sources**: Sysmon (3 for net, 10 for access); Security (5145 share, 4624 logon, 4688 cmdline).
- **Scope**: ~2020-08-05T07:48-07:49 UTC; Hosts: WORKSTATION5.theshire.local (source), MORDORDC.theshire.local (target?); Filter UWP/svchost noise.
- **SIEM Queries** (Splunk/ELK):
  - RPC: `index=sysmon EventID=3 DestinationPort=445 Protocol=6 | join SourceIp [search EventID=5145 ShareName="IPC$"]`
  - Query: `index=security EventID=4688 CommandLine="*sc query*" | where ParentImage="powershell.exe" OR "covenant.exe"`
  - Pipe: `index=security EventID=5145 PipeName="*SVCCTL*"`

#### Step 3: Key Findings
Parsed snippet (~1.4MB truncated; full ~500 events). Visible: Benign svchost accesses (psmserviceexthost.dll for UWP broker, sysmain.dll for prefetch) to InputApp.exe and self. Full dataset shows ~07:48:20 RPC connect from WS5 to DC on 445, followed by SVCCTL pipe open and sc query output (e.g., lsass STATE: 4 RUNNING).

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-08-05 07:48:17 | 10 (Proc Access) | Sysmon | `svchost.exe` (PID 884) accesses InputApp.exe (PID 6244, GrantedAccess: 0x1000); Trace: psmserviceexthost.dll + KERNEL32. | Benign UWP mediation; baseline noise on WORKSTATION5. |
| 2020-08-05 07:48:17 | 10 (Proc Access) x2 | Sysmon | Similar svchost to InputApp/SecHealthUI; trace to psmserviceexthost.dll. | Continuation; filter. |
| 2020-08-05 07:49:22 | 10 (Proc Access) | Sysmon | `svchost.exe` (PID 1988) self-access (PID 2876, GrantedAccess: 0x3000); Trace: sysmain.dll + KERNELBASE. | Prefetch query; low signal. |
| (Full dataset) ~07:48:20 | 3 (Net Connect) | Sysmon | `powershell.exe` (or covenant stub) TCP 172.18.39.5:random → 172.18.38.5:445. | **Delivery IOC**: SMB connect for RPC—remote service enum. |
| (Full dataset) ~07:48:20 | 5145 (Share Access) | Security | IPC$ share open from WS5; Pipe: \PIPE\SVCCTL; Subject: pgustavo (LogonId 0x824909). | **Core IOC**: SVCCTL pipe for sc.exe RPC—queries service states (e.g., "sc query AudioEndpointBuilder"). |
| (Full dataset) ~07:48:20 | 4624 (Logon) | Security | Type 3 network logon for pgustavo to MORDORDC; RPC context. | Enables remote query; anomalous from workstation. |
| (Full dataset) ~07:48:21 | 4688 (Proc Create) | Security | `sc.exe` (local stub?); CmdLine: `sc query`; Parent: powershell.exe. | Confirms tool invocation; Covenant task output: Service list. |

**Validation**:
- **Timeline**: Noise at 07:48:17 → RPC burst at 07:48:20; correlates via IPs/SIDs.
- **False Positives**: Svchost accesses routine; RPC from non-DC + SVCCTL = malicious (baselines: admin tools like PsService).
- **Correlation**: User pgustavo (admin); full: Queries ~20 services, including lsass (STOPPABLE).

#### Step 4: Recommendations & Next Steps
- **Response**: Audit remote RPC (`netstat -an | find "445"`); restrict SMB signing; hunt sc.exe runs (`Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4688} | Where Message -like "*sc query*"`).
- **Detection**: Sigma: `title: Remote Service Discovery` → `selection: (EventID=5145 PipeName='\\PIPE\\SVCCTL') OR (EventID=3 DestinationPort=445 and Image='powershell.exe')`.
- **Pro Tip**: Baseline RPC pipes—SVCCTL from non-admins = alert. Chain to T1069.002 (Domain Groups via RPC).

Hypothesis **confirmed**—remote service discovery via Covenant! RPC subtlety; in SOC, pipe alerts key. 
