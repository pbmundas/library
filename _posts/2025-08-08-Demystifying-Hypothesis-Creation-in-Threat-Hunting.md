---
layout: default
title: Hypothesis Creation
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Demystifying Hypothesis Creation in Threat Hunting

Hey, totally normal to feel confused at first—hypothesis-driven hunting is like detective work: You start with clues (logs) and build a story (hypothesis) to test. The good news? You don't need to memorize every attack vector (there are thousands of variants). Instead, focus on **patterns and TTPs** (Tactics, Techniques, Procedures) from frameworks like MITRE ATT&CK. Our past exercises (e.g., LSASS dumps via TaskMgr or S3 probes) showed this in action: Logs → IOCs → Hypothesis → Validation.

No, it's **not necessary to know all attacks**. Hunters succeed by recognizing **anomalies** (e.g., unusual process access) and mapping them to common TTPs (e.g., credential dumping). With practice, you'll pattern-match faster. Below, I'll break it down: Process, learning tips, and why it's accessible.

#### The Hypothesis Creation Process
Hypothesis-driven hunting (from SANS FOR578) flips reactive alerting: Assume a threat exists, then prove/disprove. For a dataset, scan for **signals** (e.g., anomalous events), form a testable story, and iterate.

| Step | Description | Example from Our Hunts | Tools/Tips |
|------|-------------|------------------------|------------|
| **1. Baseline the Data** | Review the dataset for normal vs. anomalous: Timestamps, volumes, patterns. Ask: "What's weird?" (e.g., high-volume events, odd cmdlines). | In RDP LSASS dump: TaskMgr accessing lsass.exe (anomalous for UI tool). | Use SIEM filters (e.g., `EventID=10 GrantedAccess>0x1000`); baselines from your env (e.g., avg PS spawns/day). |
| **2. Identify Signals/IOCs** | Spot indicators: Processes, IPs, paths, errors. Categorize: Execution (proc creates), Persistence (reg mods), etc. | In MSF Mic: WinRM bursts (port 5985) + audio DLL loads. | Map to MITRE (e.g., Sigma rules: "TaskMgr LSASS" for T1003.001). No full attack knowledge—start with top 10 TTPs. |
| **3. Form the Hypothesis** | Craft a testable story: "Adversary [TTP] via [tool] on [host] at [time], evidenced by [IOCs]." Keep null hyp (benign alt). | "Adversary dumped LSASS via TaskMgr (T1003.001) interactively via RDP, shown by Event 10 GrantedAccess=0x1F0FFF." | Use Pyramid of Pain: Escalate from IOCs (IP) to TTPs (dumping). Limit to 1-3 per hunt. |
| **4. Test & Iterate** | Query for confirmation (e.g., correlate timelines); falsify null. Refine if partial match. | Correlated LogonId in RDP hunt—confirmed chain. | Labs: Atomic Red Team (simulate TTPs); datasets: Mordor/HELK. If wrong, pivot (e.g., "Not dump—maybe recon?"). |
| **5. Document & Pivot** | Journal: What worked? Pivot to related TTPs (e.g., from dump to lateral). | Our capstone: Chain to exfil queries. | Tools: Hunting journal (Notion/OneNote); playbooks (SANS/Elastic). |

This process is **iterative**—start broad ("Anomalous access"), narrow with data ("Credential dump"). For any dataset: 80% from signals, 20% from ATT&CK knowledge.

#### How to Learn Hypothesis Creation (Without Knowing "All Attacks")
You build intuition via **patterns, not encyclopedias**. Focus on 20-30 core TTPs covering 80% threats (e.g., PS execution, reg persistence). No need for every variant—attackers reuse basics.

- **Resources (Progressive)**:
  1. **Basics (1-2 weeks)**: MITRE ATT&CK Navigator—filter by Enterprise, tag TTPs to logs from our hunts. Read "Hunting with ATT&CK" (free PDF).
  2. **Practice (Ongoing)**: 
     - Datasets: Mordor (tagged TTPs—replay our exercises).
     - Labs: Atomic Red Team (GitHub: Run tests, hunt logs).
     - CTFs: Blue Team Labs Online (BTLO) or TryHackMe hunts.
  3. **Deep Dives**: SANS FOR578 course (or free papers); "Threat Hunting with Elastic" book.
  4. **Communities**: r/threathunting, Threat Hunter Playbook (GitHub)—real playbooks for TTPs.

- **Pro Tip**: For a new dataset, always ask: "What MITRE tactic does this smell like?" (e.g., net connect = C2/Exfil). Use ATT&CK as a cheat sheet—search "credential access logs" for ideas. With 10-20 hunts, you'll auto-formulate.

