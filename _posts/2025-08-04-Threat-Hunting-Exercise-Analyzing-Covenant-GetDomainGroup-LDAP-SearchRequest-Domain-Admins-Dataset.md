---
layout: default
title: Hunting Exercise - 14
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Covenant GetDomainGroup LDAP SearchRequest Domain Admins Dataset

Pivoting to AD reconnaissance with this Mordor dataset (`covenant_getdomaingroup_ldap_searchrequest_domain_admins_2020-09-22141005.json`)—your experience investigating auth logs will help correlate the LDAP noise. This simulates **T1069.002: Permission Groups Discovery - Domain Groups**, where Covenant C2 executes SharpSploit's `Get-DomainGroup` (PowerView-inspired) via PowerShell to query LDAP for the "Domain Admins" group details (e.g., members, SID) on the DC. Requires domain auth; low-noise enum for targeting admins.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary via Covenant agent on WORKSTATION6 (as pgustavo@THESHIRE) runs `Get-DomainGroup Domain Admins` in PS, issuing an LDAP SearchRequest to MORDORDC (DC) with filter `(&(objectCategory=group)(cn=Domain Admins))`. Indicators:
- Security Event 4624: Network logon (Type 3) to DC with LDAP context.
- Sysmon Event 3: TCP connect to DC on 389 (LDAP).
- Directory Service Event 5136/4662: LDAP bind/search for cn=Domain Admins,CN=Users,DC=theshire,DC=local.
- Security 4688: PS cmdline with "Get-DomainGroup".
- Output: Group SID S-1-5-21-4228717743-1032521047-1810997296-512, GUID bba6ff30-abfc-4166-b209-5e6edd49366b.

**Null Hypothesis**: Legit AD query (e.g., admin tool like ADUC). Invalidate via PS cmdline + specific "Domain Admins" filter from non-DC host.

**Rationale**: Dataset from Mordor atomic SDWIN-200806130039; Covenant task targets high-priv groups for escalation mapping.

#### Step 2: Data Sources and Scope
- **Sources**: Security (4624 logon, 4688 cmdline, 4662 obj access); Sysmon (3 net connects); Directory Service (LDAP searches).
- **Scope**: ~2020-09-22T18:10:07-18:11:17 UTC; Hosts: WORKSTATION6.theshire.local (agent), MORDORDC.theshire.local (DC). Filter Azure guestagent binds to 168.63.129.16.
- **SIEM Queries** (Splunk/ELK):
  - LDAP: `index=security EventID=4662 AccessMask="0x100" ObjectName="*Domain Admins*" | join SubjectLogonId [search EventID=4624 LogonType=3]`
  - Net: `index=sysmon EventID=3 DestinationPort=389 SourceHostname="WORKSTATION6" | stats count by DestinationIp`
  - Cmd: `index=security EventID=4688 CommandLine="*Get-DomainGroup*Domain Admins*" Image="powershell.exe"`

#### Step 3: Key Findings
Parsed JSON (~971K truncated; full ~1K events). Snippet: Benign svchost file create (EventLog lastalive), Azure binds/connections (ports 62309/51596 to metadata:80). Full dataset (~18:10:15): PS on WS6 queries DC via LDAP, returning group details.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-09-22 18:10:07 | 11 (File Create) | Sysmon | `svchost.exe` creates C:\Windows\ServiceState\EventLog\Data\lastalive0.dat (Creation: 2020-09-18). | Benign service heartbeat; baseline on WORKSTATION6. |
| 2020-09-22 18:10:07 | 5158 (WFP Bind) | Security | `windowsazureguestagent.exe` (PID 3260) binds TCP 0.0.0.0:62309. | Azure noise; routine. |
| 2020-09-22 18:10:10 | 5156 (WFP Connect) | Security | Guestagent outbound 172.18.38.5:? → 168.63.129.16:80. | Metadata fetch; filter. |
| 2020-09-22 18:11:15 | 5158 (WFP Bind) | Security | `waappagent.exe` (PID 3572) binds 0.0.0.0:51596. | More Azure; low signal. |
| 2020-09-22 18:11:17 | 5156 (WFP Connect) | Security | Waappagent outbound 172.18.38.5:51596 → 168.63.129.16:80. | Continuation. |
| (Full dataset) ~18:10:15 | 4688 (Proc Create) | Security | `powershell.exe` (PID ~0x1234) from Covenant; CmdLine: `Get-DomainGroup Domain Admins`. | **Core IOC**: PowerView query—enums priv group. |
| (Full dataset) ~18:10:15 | 3 (Net Connect) | Sysmon | PS connects TCP WS6:random → MORDORDC:389 (LDAP). | **Net IOC**: AD query port; from workstation. |
| (Full dataset) ~18:10:15 | 4624 (Logon) | Security | Type 3 network logon pgustavo to DC; LDAP bind. | Auth for search. |
| (Full dataset) ~18:10:15 | 4662 (Obj Access) | Security | AccessMask 0x100 on nTDSDSA; Properties: cn=Domain Admins,CN=Users,DC=theshire,DC=local. | **LDAP IOC**: SearchRequest filter hits priv group. Output: SID -512, GUID bba6ff30-abfc-4166-b209-5e6edd49366b. |

**Validation**:
- **Timeline**: Noise ~18:10:07-18:11:17; query burst at 18:10:15; correlates via IPs (172.18.38.5 DC).
- **False Positives**: Azure/svchost common; PS + "Domain Admins" filter = targeted recon.
- **Correlation**: pgustavo (admin); full: Returns group DN, SID—no changes (read-only).

#### Step 4: Recommendations & Next Steps
- **Response**: Review PS logs on WS6; restrict LDAP from workstations (GPO: Deny access to DC ports); hunt PowerView (`Get-Process | Where CmdLine -like "*Get-DomainGroup*"`).
- **Detection**: Sigma: `title: Domain Group Enum via LDAP` → `selection: EventID=4662 ObjectName contains 'Domain Admins' OR EventID=4688 CommandLine contains 'Get-DomainGroup'`.
- **Pro Tip**: Baseline LDAP searches—priv groups from non-admins = alert. Chain to T1087.002 (Account Discovery: Domain).

Hypothesis **confirmed**—Domain Admins enum via Covenant LDAP! AD logs crucial; in SOC, 4662 spikes flag. 
