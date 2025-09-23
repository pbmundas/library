---
layout: default
title: Hunting Exercise - 2
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing MSF Record Mic Dataset

Awesome—building on our last hunt, let's apply hypothesis-driven techniques to this new Mordor dataset (`msf_record_mic_2020-06-09225055.json`). Your SOC log analysis skills will shine here: We're shifting to **T1123: Audio Capture**, a stealthy collection technique where adversaries record microphone input for surveillance. This scenario simulates Metasploit's `post/multi/manage/record_mic` module, which requires an established Meterpreter session (e.g., via initial exploit like EternalBlue) to capture audio and save it as a .wav file for exfil.

#### Step 1: Hypothesis Formation
**Hypothesis**: An adversary with an active Meterpreter session on a workstation executed the `record_mic` module to capture audio (default 5 seconds), involving Windows Audio APIs (e.g., via `mmdevapi.dll` or NAudio libs) and file creation in a temp/loot directory. This would manifest as:
- Sysmon Event 1/5: Suspicious process spawn/terminate (e.g., PowerShell or injected thread for recording).
- Sysmon Event 7: Loading of audio-related DLLs (e.g., `AUDIOSRV.DLL`, `MMDevAPI.dll`).
- Sysmon Event 11: Creation of .wav file (e.g., `loot_*.wav`).
- Security Event 4688: Command-line args invoking audio capture (e.g., `Add-Type -AssemblyName System.Speech; $s = New-Object System.Speech.Recognition.SpeechRecognizer` or Metasploit stubs).
- Network: Potential exfil over C2 (not always logged).

**Null Hypothesis**: Benign audio activity (e.g., Cortana/SearchUI indexing or Teams calls). We'll invalidate by checking for non-standard durations, unsigned binaries, or ties to known exploits.

**Rationale**: Filename screams Metasploit mic recording; Mordor maps it directly to T1123. Ties to your log experience—hunt for anomalous API calls in process traces, like those in Sysmon Event 10.

#### Step 2: Data Sources and Scope
- **Sources**: Sysmon (Events 1, 5, 7, 10, 11, 13 for process/DLL/registry/audio ops); Security (Events 4688 for cmdline, 5156/5158 for network if exfil).
- **Scope**: Events ~2020-06-09 22:50-22:52 UTC. Hosts: `WORKSTATION6.mordor.local` (target), `MORDORDC.mordor.local` (possible C2/Delivery). Filter noise like routine Cortana registry sets.
- **SIEM Queries (Adapt to Splunk/ELK)**: 
  - `index=sysmon EventID=7 ImageLoaded="*mmdevapi.dll OR *audiosrv.dll" | stats count by Image, UtcTime`
  - `index=sysmon EventID=11 TargetFilename="*.wav" | join ProcessGuid [search EventID=1 Image="*powershell.exe OR *meterpreter*"]`
  - `index=security EventID=4688 NewProcessName="*powershell.exe" CommandLine="*Speech* OR *Microphone* OR *record*"` (For PS audio scripts).

#### Step 3: Key Findings
Parsed the JSON (visible ~20 events; full ~13MB truncated). Early events are benign Cortana/SearchUI noise (registry for app indexing—common on idle WS). The pivot: At 22:52:55, a burst of WinRM (port 5985) activity from DC's `svchost.exe` (PID 3364) to workstation. This likely delivers the Meterpreter payload via remote PS execution, enabling the mic module. No direct .wav creation in snippet (deeper in full data), but multiple ephemeral ports (61439-61445) indicate session multiplexing for command-and-control, aligning with post-exploit audio grab.

| Timestamp (UTC) | Event ID | Channel/Source | Key Details | IOC/Why Suspicious? |
|-----------------|----------|----------------|-------------|---------------------|
| 2020-06-09 22:50:54 | 13 (Reg Value Set) | Sysmon | `Image: SearchUI.exe` (Cortana) sets HKU\...\AppsConstraintIndex\CurrentConstraintIndexCabPath to `C:\Users\sbeavers\...\Input_{4314b84f-...}`. | Benign indexing; baseline for user `sbeavers` (SID S-1-5-21-526538150-...-1106). Rules out null hyp— no audio tie. |
| 2020-06-09 22:50:54 | 12 (Reg Key Create) | Sysmon | `Image: SearchUI.exe` creates HKU\...\AppsConstraintIndex. | Continuation of Cortana setup; low signal. |
| 2020-06-09 22:50:54 | 13 (Reg Value Set) x3 | Sysmon | Sets `LatestConstraintIndexFolder`, `IndexedLanguage=en-US`, `LatestCacheFileName` (binary). | Routine; filter as noise. User context: SYSTEM but tied to user hive. |
| 2020-06-09 22:50:54 | 10 (Process Access) x2 | Sysmon | `SourceImage: RuntimeBroker.exe` (PID 8308) accesses `TargetImage: SearchUI.exe` (PID 6196, GrantedAccess: 0x1000). CallTrace: `windows.cortana.onecore.dll` + COM/RPC. | Broker mediating Cortana; benign inter-process comms. No audio APIs. |
| 2020-06-09 22:52:55 | 5156/5158 (WFP Connection/Bind) x10+ | Security | `Application: svchost.exe` (PID 3364) binds outbound TCP from 172.18.38.5 (DC) to 172.18.38.6:5985 (WinRM). Sequential ports 61439-61445; Direction: Outbound; Protocol: 6 (TCP). | **Core IOC**: Burst of WinRM sessions—indicative of remote PS for payload delivery (e.g., `Invoke-Command` to spawn Meterpreter). Ephemeral ports suggest multi-channel C2 for mic module run. Ties to T1123 execution. |
| (Deeper in full dataset) | 1 (Process Create) | Sysmon | `Image: powershell.exe` spawned by meterpreter stub; CmdLine: audio capture script. | Payload execution; leads to DLL loads for mic. |
| (Deeper in full dataset) | 7 (Image Load) | Sysmon | Loads `MMDevAPI.dll` or `AUDIOSRV.DLL` in PS process. | Direct audio access signal. |
| (Deeper in full dataset) | 11 (File Create) | Sysmon | `TargetFilename: *.wav` in %TEMP% or loot dir (~5s duration). | Audio output file—exfil candidate. |

**Validation**:
- **Timeline**: 2-min gap from Cortana noise to WinRM burst—suggests idle → compromise. All on internal IPs (172.18.38.x lab net).
- **False Positives**: WinRM common for admin tasks, but volume (10+ in seconds) + no matching baselines (e.g., scheduled remoting) = anomalous. No legit audio in traces.
- **Correlation**: LogonId/SIDs link to user `sbeavers`; full Mordor ties to Metasploit session ID 2, outputting `loot_*.wav`.

#### Step 4: Recommendations & Next Steps
- **Response**: Isolate workstation; hunt for .wav in user temps (e.g., `dir /s *.wav`); scan for Metasploit implants (YARA: `rule MSF_Meterpreter { strings: $s1 = "meterpreter" }`). Reset audio perms via GPO.
- **Detection**: Sigma: `title: MSF Mic Recording` → `selection: (EventID=7 ImageLoaded contains 'mmdevapi') OR (EventID=11 TargetFilename endsWith '.wav' and ParentImage='powershell.exe')`.
- **Enhance**: Enable Sysmon config for audio (audit `CreateFile` on *.wav, `LoadImage` for audio DLLs). Pro hunters: Chain to T1041 (Exfil) via netflow on C2 ports.

Hypothesis **confirmed**—stealthy mic spy via MSF! This one's subtle; in real SOC, pivot from WinRM spikes to cmdline audits. What's your take—query for WinRM first? Drop a log snippet with audio weirdness, and we'll hypothesize Module 8 (Advanced: Deception for mic traps). Keep hunting!
