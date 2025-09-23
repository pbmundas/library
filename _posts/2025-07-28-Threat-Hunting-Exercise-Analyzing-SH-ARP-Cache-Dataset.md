---
layout: default
title: Hunting Exercise - 7
category: Threat-Hunting  # This becomes a main topic in sidebar
---


### Threat Hunting Exercise: Analyzing SH ARP Cache Dataset

Expanding our hunts to Linux with this Mordor auditd log (`sh_arp_cache_2020-11-10074812.log`)—your log analysis skills apply seamlessly to auditd SYSCALLs. This simulates **T1018: Remote System Discovery**, where an adversary enumerates the ARP cache (`arp -a`) to map local network devices (IPs/MACs), often piped to `grep` for cleanup (filtering incomplete entries starting with "?"). It's a stealthy recon step post-initial access (e.g., via SSH as wardog).

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary in a compromised Linux host (user: wardog) runs `arp -a | grep -v "^?"` to dump and filter the ARP table, identifying live local hosts for lateral movement. Indicators:
- Auditd SYSCALL 59 (execve): Success for `/usr/sbin/arp -a` and `/bin/grep -v "^?"`.
- PROCTITLE: Hex-encoded cmdline (e.g., "arp-a" and "grep-v^?").
- CWD: `/home/wardog` (user home, post-compromise staging).
- No elevated privs (uid=1000); tty=pts0 (interactive, e.g., SSH).

**Null Hypothesis**: Benign network troubleshooting (e.g., admin checking connectivity). Invalidate via pipe chaining (arp|grep) without output redirect or non-root context.

**Rationale**: Mordor atomic for Linux T1018; arp -a reveals broadcast domain without noisy tools like nmap.

#### Step 2: Data Sources and Scope
- **Sources**: Auditd (SYSCALL/EXECVE for cmds, PROCTITLE for args, PATH for binaries).
- **Scope**: Timestamp 1604994496.155 (~2020-11-10 07:48:16 UTC); User: wardog (auid=1000); PIDs 1631/1632 (children of shell PID 29002); ses=104 (SSH session?).
- **SIEM Queries** (ELK/Splunk for auditd):
  - Recon: `syscall=59 comm="arp" OR comm="grep" a1="-a" OR a1="-v"`
  - Chain: `msg.auditd.syscall=59 | stats count by comm, auid | where auid=1000 and cwd="/home/wardog"`
  - Pivot: `proctitle~="arp.*grep" | join ppid [search open path~="/proc/net/arp"]`

#### Step 3: Key Findings
Single block with two chained execves (full dataset ~5 events, including shell spawn). Core: Interactive recon dumping ARP table (~entries for local net, filtered for complete MACs).

| Timestamp (UTC) | Event Type | Key Details | IOC/Why Suspicious? |
|-----------------|------------|-------------|---------------------|
| 2020-11-10 07:48:16 | SYSCALL (59: execve) | arch=x86_64, success=yes, exit=0; pid=1631, ppid=29002; auid=1000 (wardog); comm="arp", exe="/usr/sbin/arp"; items=2 (/usr/sbin/arp, ld-linux.so). | **Core IOC**: Execve for arp—network recon tool. Non-root + pts0 = potential adversary shell. |
| 2020-11-10 07:48:16 | EXECVE | argc=2; args: "arp", "-a". | Dumps full ARP cache; reveals local IPs/MACs for discovery. |
| 2020-11-10 07:48:16 | CWD | cwd="/home/wardog". | User home; common for post-access enum (e.g., after T1133). |
| 2020-11-10 07:48:16 | PATH (item=0/1) | Legit paths/modes for arp and loader. | Rules out tampering; benign binary. |
| 2020-11-10 07:48:16 | PROCTITLE | proctitle=arp -a (hex: 617270002D61). | Confirms args; hex in title evades basic proc monitoring. |
| 2020-11-10 07:48:16 | SYSCALL (59: execve) | pid=1632, ppid=29002; comm="grep", exe="/bin/grep". | Pipe child: Filters arp output. |
| 2020-11-10 07:48:16 | EXECVE | argc=3; args: "grep", "-v", "^?". | **Filtering IOC**: Excludes incomplete entries (e.g., ? (incomplete))—cleans recon data for analysis. Anomalous combo for benign use. |
| 2020-11-10 07:48:16 | PROCTITLE | proctitle=grep -v ^? (hex: 67726570002D76005E3F). | Matches; chain confirms arp|grep pipeline. |

**Validation**:
- **Timeline**: Simultaneous execves (same msg.audit id); correlates to shell (ppid=29002).
- **False Positives**: arp -a common for diagnostics, but | grep -v "^?" = targeted (baselines show plain arp or to file).
- **Correlation**: ses=104 (persistent); full output: IPs like 192.168.1.x with MACs—local net map.

#### Step 4: Recommendations & Next Steps
- **Response**: Review SSH logs for wardog (~07:48); hunt ARP changes (`watch -n1 cat /proc/net/arp`); block anomalous enum via auditd rules.
- **Detection**: Auditd: `-a always,exit -F arch=b64 -S execve -F path=/usr/sbin/arp -k net_recon`; Sigma: `title: Linux ARP Recon` → `selection: (syscall=59 and comm='arp' and a1='-a') OR (comm='grep' and a2='^?')`.
- **Pro Tip**: Baseline arp execs—pipe to grep = red. Chain to T1046 (net recon). For Linux, enable auditd on net syscalls (e.g., socket).

Hypothesis **confirmed**—ARP cache recon for local discovery! In your SOC, syscall chaining would alert. Got a Linux audit snippet? Let's hunt it. Module 9: Cross-OS case studies?
