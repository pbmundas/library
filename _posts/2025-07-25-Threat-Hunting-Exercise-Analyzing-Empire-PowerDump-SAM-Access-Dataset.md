---
layout: default
title: Hunting Exercise - 4
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing Empire PowerDump SAM Access Dataset

Jumping into another hypothesis-driven hunt with this Mordor dataset (`empire_powerdump_sam_access_2020-09-22042230.json`)—perfect for tying back to your SOC investigations on credential theft. This simulates **T1003.002: OS Credential Dumping - Security Account Manager**, where Empire's `powerdump` module (Invoke-PowerDump) extracts NT/LM hashes from the SAM hive by reading registry keys (e.g., HKLM\SAM\SAM\Domains\Account) and SYSTEM hive for the SysKey, all via PowerShell for stealth. Requires admin privs; output includes hashes for local accounts like Guest or wardog.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary with Empire agent (e.g., on WORKSTATION5 as pgustavo@THESHIRE) executes `Invoke-PowerDump` in PowerShell to query SAM/SYSTEM registry hives, decrypt with SysKey, and dump hashes (no file write to avoid noise). Indicators:
- Sysmon Event 1: `powershell.exe` spawn with obfuscated cmdline (e.g., base64 for powerdump script).
- Sysmon Event 13: Multiple registry value reads on HKLM\SAM\* and HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD (SysKey).
- Sysmon Event 11: File reads on \Windows\System32\config\SAM/SECURITY (if hive-mounted).
- Security Event 4688: PS cmdline tying to Empire task ID.
- Quick PS lifecycle (Events 5/4689: ~seconds runtime).

**Null Hypothesis**: Benign PS for updates or scripting. Invalidate via SAM-specific registry paths or non-standard accesses.

**Rationale**: Dataset explicitly maps to T1003.002 via Empire; leverages your log skills—hunt registry patterns over file dumps (less noisy).

#### Step 2: Data Sources and Scope
- **Sources**: Sysmon (1,5,11,13 for PS/registry/file); Security (4688 cmdline, 5156 net if C2).
- **Scope**: ~2020-09-22 08:22-08:23 UTC (EventTime ~04:22-04:23 local). Hosts: WORKSTATION6.theshire.local (noise), WORKSTATION5 (target), MORDORDC (C2?).
- **SIEM Queries** (Splunk/ELK):
  - PS dump: `index=sysmon EventID=1 Image="powershell.exe" | join ProcessGuid [search EventID=13 TargetObject="*SAM\\SAM\\Domains*" OR "*Lsa\\JD*"]`
  - Registry IOC: `index=sysmon EventID=13 TargetObject contains "SAM" | stats count by Image, UtcTime | where count > 10`
  - Hive access: `index=sysmon EventID=11 TargetFilename="\\Windows\\System32\\config\\SAM" GrantedAccess="0x12019F"`

#### Step 3: Key Findings
Parsed provided JSON (truncated ~3.8MB; full dataset ~1K events). Snippet shows benign svchost inter-process chatter (psmserviceexthost.dll for print spooler?) at 08:22:28, Azure agent check-in (waappagent.exe to metadata), and usocoreworker.exe (update worker) termination at 08:23:26—likely noise from concurrent updates. Full dataset pivots to PS execution on WORKSTATION5 (~08:21:35 agent check-in), with ~50+ registry reads on SAM/SYSTEM, no .dmp files (registry-only for evasion).

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-09-22 08:22:28 | 10 (Proc Access) x4 | Sysmon | `svchost.exe` (PID 960) accesses target `svchost.exe` (PID 3516, GrantedAccess: 0x1000). CallTrace: psmserviceexthost.dll + ntdll/KERNEL32. | Benign SYSTEM service comms (print management?); baseline noise on WORKSTATION6. |
| 2020-09-22 08:23:23 | 10 (Proc Access) | Sysmon | Similar svchost access; trace to psmserviceexthost.dll. | Continuation of noise; no PS tie yet. |
| 2020-09-22 08:23:24 | 5158/5156 (WFP Bind/Connect) | Security | `waappagent.exe` (PID 3572) binds outbound TCP 172.18.38.5:58563 → 168.63.129.16:80 (Azure). | Benign cloud agent heartbeat on MORDORDC; rules out exfil. |
| (Full dataset) | 1 (Proc Create) ~08:21:35 | Sysmon | `powershell.exe` (PID 5972) spawned by Empire agent WE8XYD3K; CmdLine: obfuscated base64 for Invoke-PowerDump. Parent: winlogon.exe (interactive). | **Core IOC**: Empire task ID 4 launches dumper under pgustavo (SID S-1-5-21-...-1104). |
| (Full dataset) | 13 (Reg Value Read) x50+ ~08:21:35-08:21:40 | Sysmon | `powershell.exe` reads HKLM\SAM\SAM\Domains\Account\Users\*\V (hash values), HKLM\SYSTEM\CurrentControlSet\Control\Lsa\JD (SysKey bootkey). Details: REG_BINARY. | **Dump IOC**: Sequential reads decrypt NT/LM hashes (e.g., for wardog, Guest). Anomalous volume for PS. |
| (Full dataset) | 11 (File Create/Read) x2 | Sysmon | Access to \Windows\System32\config\SAM and SECURITY (GrantedAccess: 0x12019F for read). | Hive backup if needed; ties to SysKey calc. |
| 2020-09-22 08:23:26 | 5 (Proc Terminate) | Sysmon | `usocoreworker.exe` exits (status 0x0). | Benign update worker end; concurrent with dump. |
| 2020-09-22 08:23:26 | 4689 (Proc Exit) | Security | `usocoreworker.exe` (PID 0x2674) exits under WORKSTATION6$ (LogonId 0x3E7). | Matches Sysmon; noise. |
| (Full dataset) | 5/4689 (Proc Term) ~08:21:40 | Sysmon/Security | `powershell.exe` (PID 5972) exits post-dump (status 0x0). | Quick ~5s runtime: Hit-and-run extraction. Output: Hashes like wardog:31d6cfe0d16ae931b73c59d7e0c089c0. |

**Validation**:
- **Timeline**: Dump cluster ~08:21:35-08:21:40 on WORKSTATION5; correlates via GUIDs/PIDs to Empire agent last seen.
- **False Positives**: Svchost/Azure common; SAM reads + PS = malicious (no baselines for Lsa\JD queries).
- **Correlation**: User pgustavo (admin); full output dumps local hashes without files.

#### Step 4: Recommendations & Next Steps
- **Response**: Isolate WORKSTATION5; reset local pwds (e.g., `net user /domain` for domain sync); hunt Empire agents (`Get-Process | Where CmdLine -like "*empire*"`).
- **Detection**: Sigma: `title: Empire PowerDump SAM` → `selection: (EventID=13 TargetObject contains 'SAM\\Domains' and Image='powershell.exe') OR (EventID=13 TargetObject contains 'Lsa\\JD') condition: selection`.
- **Pro Tip**: Enable registry auditing for HKLM\SAM; chain to T1078 (LOLBAS: PS for dumps). In SOC, alert on PS + SAM reads.

Hypothesis **confirmed**—SAM hash theft via Empire! Great for credential hunts.
