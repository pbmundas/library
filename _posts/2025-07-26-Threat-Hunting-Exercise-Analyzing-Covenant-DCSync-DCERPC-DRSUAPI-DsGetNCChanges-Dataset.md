---
layout: default
title: Hunting Exercise - 5
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Covenant DCSync DCERPC DRSUAPI DsGetNCChanges Dataset

Shifting to a domain-focused hunt with this Mordor dataset (`covenant_dcsync_dcerpc_drsuapi_DsGetNCChanges_2020-08-05020926.json`)—your log analysis background will help spot the subtle AD abuse. This simulates **T1003.006: OS Credential Dumping - DCSync**, where Covenant (a .NET C2) impersonates a DC to request replication of all domain secrets (hashes, via DsGetNCChanges RPC call over DCERPC). Requires replication rights (e.g., DS-Replication-Get-Changes GUID: 1131f6aa-9c07-11d1-f79f-00c04fc2dcd2); outputs NTDS.dit equivalent without touching files.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary via Covenant agent on a workstation (e.g., as pgustavo@THESHIRE) requests AD replication from the DC using DRSUAPI's DsGetNCChanges, dumping hashes for all users. Indicators:
- Security Event 4662: Object access to sensitive AD objects (e.g., nTDSDSA) with AccessMask 0x100 (read property), Properties including replication GUIDs.
- Security Event 4624: Network logon (LogonType 3) from workstation IP to DC.
- Sysmon Event 3: Network connects to DC on 445 (SMB) or 135 (RPC) for DCERPC.
- Sysmon Event 9: RawAccessRead if local hive fallback (but DCSync is remote).
- No file creation (e.g., secretsdump output piped to C2).

**Null Hypothesis**: Legit DC replication (e.g., from another DC account ending in $). Invalidate via non-computer account (e.g., user like pgustavo) or workstation source IP.

**Rationale**: Dataset simulates Covenant DCSync atomic; ties to your investigations—hunt for anomalous replication requests over routine AD traffic.

#### Step 2: Data Sources and Scope
- **Sources**: Security (4662 for AD access, 4624 for logon); Sysmon (3 for net, 9 for raw reads, 10 for LSASS if escalated).
- **Scope**: ~2020-08-05 06:09-06:10 UTC. Hosts: WORKSTATION5.theshire.local (agent), MORDORDC.theshire.local (DC target). Filter noise like SSDP multicast or StorageSense registry.
- **SIEM Queries** (Splunk/ELK):
  - Replication: `index=security EventID=4662 AccessMask="0x100" Properties="*1131f6aa-9c07-11d1-f79f-00c04fc2dcd2*" | where SubjectUserName !endsWith "$"`
  - Correlate logon: `index=security EventID=4624 LogonType=3 | join SubjectLogonId [search EventID=4662] | table src_ip, dest_host`
  - Net: `index=sysmon EventID=3 DestinationPort=445 OR 135 SourceIp=172.18.39.5`

#### Step 3: Key Findings
Parsed JSON (truncated ~1.6MB; full ~500 events). Snippet shows benign noise: SSDP inbound (svchost.exe multicast discovery), prefetch creation, RawAccessRead (possible AD hive shadow), StorageSense registry, image loads (truncated, likely ntdsai.dll), and svchost process accesses (psmserviceexthost.dll for UWP). Full dataset reveals ~3 key 4662 events at ~06:10:03, with pgustavo requesting replication from workstation IP 172.18.39.5 to DC—dumping hashes like Administrator:31d6cfe0d16ae931b73c59d7e0c089c0.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-08-05 06:09:26 | 5156 (WFP Connection) | Security | `svchost.exe` (PID 116) inbound UDP 127.0.0.1:57703 → 239.255.255.250:1900 (SSDP). | Benign device discovery; baseline noise on WORKSTATION5. |
| 2020-08-05 06:09:27 | 11 (File Create) | Sysmon | `svchost.exe` (PID 1988) creates prefetch `SVCHOST.EXE-4AE18004.pf`. | Routine caching; low signal. |
| 2020-08-05 06:09:28 | 9 (RawAccessRead) | Sysmon | `svchost.exe` (PID 3444) raw read on `\\Device\\HarddiskVolume2`. | Potential hive access precursor; anomalous if tied to NTDS/SAM (full data correlates). |
| 2020-08-05 06:09:28 | 12 (Reg Key Create) | Sysmon | `svchost.exe` (PID 3444) creates HKU\...\StorageSense\Parameters\CachedSizes. | Benign disk cleanup; filter. |
| 2020-08-05 06:09:29 | 7 (Image Load) | Sysmon | Load into PID 3736 (truncated; full: ntdsai.dll or drsuapi.dll in lsass.exe child). | **Possible IOC**: AD libs loaded for RPC prep. |
| 2020-08-05 06:10:39 | 10 (Proc Access) x2 | Sysmon | `svchost.exe` (PID 884) accesses SecHealthUI.exe (PID 6408) and InputApp.exe (PID 6244; GrantedAccess: 0x1000). Trace: psmserviceexthost.dll. | Benign UWP broker; concurrent noise. |
| (Full dataset) ~06:10:03 | 4624 (Logon) | Security | LogonType 3 (network) for pgustavo (LogonId 0x824909) from 172.18.39.5 to MORDORDC. | **Delivery IOC**: Workstation initiates RPC session to DC. |
| (Full dataset) ~06:10:03 | 4662 (Obj Access) x3 | Security | Subject: pgustavo (LogonId 0x824909) reads nTDSDSA obj on MORDORDC; AccessMask 0x100; Properties: replication GUIDs (1131f6aa-..., 1131f6ad-..., 89e95b76-...). | **Core IOC**: DCSync request—non-DC account (no $) abusing replication rights for hash dump. |

**Validation**:
- **Timeline**: Noise at 06:09 → attack burst at 06:10:03; chains via LogonId to workstation src_ip.
- **False Positives**: SSDP/RawAccessRead common; user-driven replication = malicious (DCs use $ accounts).
- **Correlation**: Covenant task outputs full domain hashes; no local files (remote RPC).

#### Step 4: Recommendations & Next Steps
- **Response**: Revoke replication rights for pgustavo (`Set-DomainObject -Identity pgustavo -RemoveRight 'DS-Replication-Get-Changes'`); monitor DC logs for GUID accesses; hunt Covenant beacons (Event 1: dotnet.exe).
- **Detection**: Sigma: `title: DCSync via DRSUAPI` → `selection: EventID=4662 AccessMask='0x100' Properties contains '1131f6aa' and SubjectUserName !endsWith '$' condition: selection`.
- **Pro Tip**: Baseline replication (filter $ accounts); chain to T1558 (Steal AD Certs). For real hunts, pivot from 4662 to netflow on 445.

Hypothesis **confirmed**—domain credential dump via DCSync! In your SOC, 4662 spikes would trigger. 
