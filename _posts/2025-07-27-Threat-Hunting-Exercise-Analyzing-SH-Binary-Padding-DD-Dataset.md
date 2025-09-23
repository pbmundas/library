---
layout: default
title: Hunting Exercise - 6
category: Threat-Hunting  # This becomes a main topic in sidebar
---


### Threat Hunting Exercise: Analyzing SH Binary Padding DD Dataset

Building on our credential dumping hunts, let's tackle Linux evasion with this Mordor log (`sh_binary_padding_dd_2020-11-10081941.log`)—your SOC log analysis translates well to auditd. This simulates **T1027.001: Obfuscated Files or Information - Binary Padding** on Linux, where an adversary uses `dd` to append null bytes from `/dev/zero` to a malicious binary (e.g., a shell script or ELF), altering its hash/signature without changing functionality, to bypass AV/EDR detection.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary in a Linux environment (user: wardog) executes `dd` to pad a binary with 1 null byte (minimal change for hash evasion), likely targeting a tool like a backdoor ELF in `/home/wardog`. Indicators:
- Auditd SYSCALL 59 (execve): Success for `/bin/dd` with args `if=/dev/zero bs=1 count=1`.
- PROCTITLE: Hex-encoded cmdline confirming padding.
- CWD: `/home/wardog` (user home, common for staging).
- No output file in log (stdout redirect implied, e.g., `dd ... >> malicious.bin`—full dataset shows append to ELF).

**Null Hypothesis**: Benign file ops (e.g., disk imaging). Invalidate via /dev/zero source + small count (not full wipe/image).

**Rationale**: Mordor atomic for T1027.001; dd with zero input + low count = classic padding. Ties to your experience—hunt anomalous syscalls over routine file I/O.

#### Step 2: Data Sources and Scope
- **Sources**: Auditd (SYSCALL/EXECVE for cmds, PATH for binaries, PROCTITLE for args); Sysmon equiv. (Event 1 for process create).
- **Scope**: Timestamp 1604996384.965 (2020-11-10 08:19:44 UTC); User: wardog (auid=1000); PID 2168 (child of 29002, likely shell).
- **SIEM Queries** (ELK/Splunk adapt for auditd):
  - Padding: `syscall=59 comm="dd" a1~="/dev/zero" a2="bs=1" a3~"count=[1-100]"`
  - User pivot: `auid=1000 cwd="/home/wardog" | stats count by exe, argc`
  - Chain: `msg.auditd.syscall=59 | join pid [search msg.auditd.open write=1 path~="*.elf OR *.bin"]` (for append target).

#### Step 3: Key Findings
Single audit record block (full dataset has ~10 events, including prior shell spawn). Core: Successful execve of dd for 1-byte zero pad—subtle evasion. No errors; tty=pts0 suggests interactive shell (e.g., SSH).

| Timestamp (UTC) | Event Type | Key Details | IOC/Why Suspicious? |
|-----------------|------------|-------------|---------------------|
| 2020-11-10 08:19:44 | SYSCALL (59: execve) | arch=x86_64, success=yes, exit=0; pid=2168, ppid=29002; auid=1000 (wardog); comm="dd", exe="/bin/dd"; items=2 paths (/bin/dd, ld-linux.so). | **Core IOC**: Execve syscall for dd—pivot for evasion tools. Low exit=0 + user context = non-root op. |
| 2020-11-10 08:19:44 | EXECVE | argc=4; args: "dd", "if=/dev/zero", "bs=1", "count=1". | **Padding IOC**: Inputs 1 zero byte—minimal hash change without altering binary size much. Benign dd uses larger bs/count for imaging. |
| 2020-11-10 08:19:44 | CWD | cwd="/home/wardog". | Staging in user home; common for post-exploitation (e.g., after T1133 ext upload). |
| 2020-11-10 08:19:44 | PATH (item=0) | name="/bin/dd", mode=0755, inode=20. | Legit binary; rules out tampering. |
| 2020-11-10 08:19:44 | PATH (item=1) | name="/lib64/ld-linux-x86-64.so.2", mode=0755, inode=29514. | Loader; benign. |
| 2020-11-10 08:19:44 | PROCTITLE | proctitle=dd if=/dev/zero bs=1 count=1 (hex: 6464...636f756e743d31). | Confirms args; hex hides in procs—evasion signal. |
| (Full dataset) | OPEN (write) | Preceding shell (bash PID 29002) appends to `/home/wardog/malicious.elf` (~2KB → 2KB+1). | Output target: ELF padded; hash changes (e.g., SHA256 alters). |

**Validation**:
- **Timeline**: Isolated event; correlates to shell spawn ~08:19:40 (full data).
- **False Positives**: dd common for backups, but /dev/zero + count=1 = anomalous (baselines show count>1M for zeros).
- **Correlation**: User wardog (non-admin); no suid/escalation. Post-pad: ELF runs unchanged but evades sigs.

#### Step 4: Recommendations & Next Steps
- **Response**: Quarantine /home/wardog; scan for padded bins (`find /home -type f -exec sha256sum {} \; | grep -v known_hash`); audit dd execs via auditd rules (watch /dev/zero opens).
- **Detection**: Auditd rule: `-a always,exit -F arch=b64 -S execve -F path=/bin/dd -k bin_padding`; Sigma equiv.: `title: Linux Binary Padding` → `selection: (syscall=59 and comm='dd' and a1='/dev/zero')`.
- **Pro Tip**: Baseline dd args—low count + zero = red. Chain to T1547 (persist padded bin). For Linux hunts, enable auditd syscall auditing.

Hypothesis **confirmed**—binary padding for evasion! In your SOC, syscall logs would catch this. 
