---
layout: default
title: Linux Queries - Top 50
category: Threat-Hunting-Queries  # This becomes a main topic in sidebar
---


### Essential Threat Hunting Hypotheses for Linux Environments - Top 50

Threat hunting in Linux environments focuses on proactive detection using tools like Auditd, Osquery, Sysmon for Linux, or ELK/Splunk. These hypotheses are mapped to MITRE ATT&CK techniques and leverage common telemetry sources (e.g., audit logs, process events, file changes). Each entry includes:

- **Hypothesis**: A testable assumption about malicious activity.
- **Rationale**: Relevance to threats like persistence or lateral movement.
- **Sample Query**: A ready-to-use query (Osquery SQL or Auditd rule/ausearch; adjust for your toolset, e.g., time ranges).
- **Expected Indicators**: Anomalies warranting investigation.

Run these regularly to baseline your environment. Prioritize based on exposure (e.g., web servers for shell hypotheses).

| #  | Hypothesis | Rationale | Sample Query | Expected Indicators |
|----|------------|-----------|------------------|---------------------|
| 1  | Adversaries are creating or modifying cron jobs for persistence (T1053.003). | Cron allows scheduled execution of payloads, common for recurring C2 or data exfil. | Osquery: `SELECT * FROM crontab WHERE command NOT LIKE '%known_good%';` | Unusual paths (e.g., /tmp/scripts) or commands like curl/wget to external IPs. |
| 2  | Suspicious command execution by web server users like www-data (T1059). | Web shells run commands under non-privileged users for evasion. | Auditd Rule: `-a always,exit -F arch=b64 -F euid=33 -S execve -k detect_execve_www` <br> Ausearch: `ausearch -k detect_execve_www --start recent` | Commands like whoami, netcat, or bash from Apache/Nginx processes. |
| 3  | Outbound network connections from web server users (T1071). | Reverse shells or tool downloads via web compromises. | Auditd Rule: `-a always,exit -F arch=b64 -S socket -F a0=2 -F euid=33 -k www_data_connect` <br> Ausearch: `ausearch -k www_data_connect` | Connections to non-standard IPs/ports from www-data. |
| 4  | File modifications in web directories indicating web shells (T1505.003). | Attackers drop PHP/ASP shells in /var/www for persistence. | Auditd Rule: `-w /var/www/html -p wa -k www_changes` <br> Ausearch: `ausearch -k www_changes` | New .php files with encoded content or from curl/wget. |
| 5  | Anomalous systemd services or timers for persistence (T1543.002). | Malicious services ensure reboot survival. | Osquery: `SELECT * FROM systemd_units WHERE unit_file_state = 'enabled' AND path LIKE '%/home/%';` | Services in user dirs or with suspicious exec_start (e.g., bash -c revshell). |
| 6  | SSH key modifications for unauthorized access (T1098.004). | Attackers add keys to ~/.ssh/authorized_keys. | Osquery: `SELECT * FROM file WHERE path LIKE '/home/%/.ssh/authorized_keys' AND mtime > (strftime('%s','now')-86400);` | Recent changes or unknown public keys. |
| 7  | SUID/SGID binaries abused for privilege escalation (T1548.001). | Setuid bits on custom binaries allow root execution. | Osquery: `SELECT * FROM suid_bin WHERE permissions LIKE '%4%';` | Non-standard binaries like /tmp/bash with SUID. |
| 8  | LD_PRELOAD environment variables for hooking (T1574.006). | Shared objects preload to intercept calls. | Osquery: `SELECT * FROM process_envs WHERE key = 'LD_PRELOAD';` | .so files in /etc/ld.so.preload or env vars pointing to suspicious libs. |
| 9  | Kernel module loading for rootkits (T1014). | LKMs hide processes or provide backdoors. | Osquery: `SELECT * FROM kernel_modules WHERE loaded = 1 AND name NOT IN (known_modules);` | Unknown modules in /proc/modules or dmesg logs. |
| 10 | Anomalous bash history entries (T1059.004). | Attackers use shell history for recon or execution. | Osquery: `SELECT * FROM shell_history WHERE command LIKE '%wget%curl%';` | Commands downloading from malicious domains. |
| 11 | Access to /proc/<pid>/maps for credential dumping (T1003.002). | Reading process memory for creds. | Auditd Rule: `-w /proc -p r -k proc_access` <br> Ausearch: `ausearch -k proc_access` | Non-system processes reading /proc/[pid]/mem or maps. |
| 12 | Modifications to /etc/passwd or /etc/shadow (T1003.008). | Altering user accounts for access. | Auditd Rule: `-w /etc/passwd -p wa -k identity` <br> Ausearch: `ausearch -k identity` | Changes not from useradd/usermod. |
| 13 | Use of gcore or gdb for memory dumps (T1003). | Dumping process memory like lsass equiv (sshd). | Osquery: `SELECT * FROM processes WHERE name IN ('gcore', 'gdb');` | Attachments to sshd or sudo processes. |
| 14 | Mimipenguin-like tools for cred dumping (T1003). | Extracts creds from memory. | Osquery: `SELECT * FROM process_memory_map WHERE path LIKE '%gnome-keyring%';` | Suspicious child processes under sudo/bash. |
| 15 | 3snake tool usage for tracing (T1003). | Ptrace on sshd/sudo for passwords. | Osquery: `SELECT * FROM processes WHERE cmdline LIKE '%ptrace%';` | Multiple generations of tracing processes. |
| 16 | Kernel crash dumping enabled (T1003). | kdump for memory extraction. | Osquery: `SELECT * FROM services WHERE name = 'kdump';` | Unexpected enabling via systemctl. |
| 17 | Access to core dump files (T1003). | /var/crash dumps for creds. | Auditd Rule: `-w /var/crash -p r -k dump_access` <br> Ausearch: `ausearch -k dump_access` | User access not from abrt. |
| 18 | Anomalous execve syscalls (T1059). | Command execution monitoring. | Auditd Rule: `-a always,exit -S execve -k command_execution` <br> Ausearch: `ausearch -k command_execution` | High-volume or unusual args from non-interactive shells. |
| 19 | Network connect syscalls (T1071). | Outbound C2 detection. | Auditd Rule: `-a always,exit -S connect -k network_activity` <br> Ausearch: `ausearch -k network_activity` | Connections from root or unusual processes. |
| 20 | File deletions or renames (T1070.004). | Anti-forensics. | Auditd Rule: `-a always,exit -S rmdir -S unlink -S rename -k file_deletion` <br> Ausearch: `ausearch -k file_deletion` | Deletions in /var/log or /etc. |
| 21 | Auditd config changes (T1562.001). | Disabling logging. | Auditd Rule: `-w /etc/audit/audit.rules -p wa -k audit_config` <br> Ausearch: `ausearch -k audit_config` | Modifications by non-admins. |
| 22 | APT config modifications (T1546). | Persistence via apt hooks. | Osquery: `SELECT * FROM file WHERE path LIKE '/etc/apt/apt.conf.d/%';` | Malicious DPkg::Post-Invoke commands. |
| 23 | Sudoers file alterations (T1548.003). | Passwordless sudo for escalation. | Osquery: `SELECT * FROM file WHERE path = '/etc/sudoers';` | NOPASSWD entries for unexpected users. |
| 24 | Group modifications (T1068). | Adding users to sudo/adm groups. | Osquery: `SELECT * FROM groups WHERE gid IN (0, 27);` | Unexpected members in wheel or sudo. |
| 25 | Hidden processes via mount (T1564.001). | Namespace hiding. | Osquery: `SELECT * FROM mounts WHERE path LIKE '%/proc%';` | Anomalous mounts over /proc. |
| 26 | Rootkit signatures in logs (T1014). | LKM insertion logs. | Osquery: `SELECT * FROM file WHERE path = '/var/log/kern.log';` | "insmod" or unknown module loads. |
| 27 | Suspicious shared objects (T1574.006). | LD_PRELOAD hooks. | Osquery: `SELECT * FROM file WHERE path = '/etc/ld.so.preload';` | Non-system .so entries. |
| 28 | Anomalous ldd outputs (T1574). | Hooked binaries. | Osquery: `SELECT * FROM process_open_files WHERE path LIKE '%ldd%';` | Unexpected libraries in common bins. |
| 29 | Hidden ports or processes (T1564). | Rootkit evasion. | Osquery: `SELECT * FROM listening_ports WHERE port > 1024;` | Ports without associated processes. |
| 30 | Bashrc/zshrc modifications (T1546.004). | Shell config backdoors. | Osquery: `SELECT * FROM file WHERE path LIKE '/home/%/.bashrc';` | Aliases or exports running revshells. |
| 31 | MOTD backdoors (T1546). | Execution on login. | Osquery: `SELECT * FROM file WHERE path LIKE '/etc/update-motd.d/%';` | Scripts with netcat or curl. |
| 32 | Anomalous user creation (T1136). | New accounts for access. | Osquery: `SELECT * FROM users WHERE uid >= 1000 AND directory NOT LIKE '/home/%';` | Users with /bin/false but active. |
| 33 | WMI equivalents via dbus (T1047). | Systemd-run for remote exec. | Osquery: `SELECT * FROM processes WHERE name = 'dbus-daemon';` | Unusual child processes. |
| 34 | DNS tunneling queries (T1071.004). | Exfil via DNS. | Osquery: `SELECT * FROM dns_resolvers;` | Long or encoded domain queries. |
| 35 | Brute-force SSH failures (T1110). | Credential stuffing. | Osquery: `SELECT * FROM last WHERE type = 'login';` | Multiple failed logins from single IP. |
| 36 | Volume shadow equiv via snapshots (T1003.002). | LVM snapshots for dumps. | Osquery: `SELECT * FROM block_devices;` | Unexpected snapshot creations. |
| 37 | Ptrace injections (T1055.008). | Process hollowing. | Auditd Rule: `-a always,exit -S ptrace -k injection` <br> Ausearch: `ausearch -k injection` | Ptrace on non-debug processes. |
| 38 | Firewall rule additions (T1562.004). | iptables mods for access. | Osquery: `SELECT * FROM iptables;` | Allow rules for unusual ports. |
| 39 | Anomalous log clearing (T1070.001). | Rm on /var/log. | Auditd Rule: `-w /var/log -p x -k log_delete` <br> Ausearch: `ausearch -k log_delete` | Executions of rm or echo > logs. |
| 40 | Suspicious mounts (T1564.005). | Bind mounts for hiding. | Osquery: `SELECT * FROM mounts WHERE type = 'bind';` | Mounts over /etc or /proc. |
| 41 | Kernel tracing anomalies (T1014). | Hooked functions. | Osquery: `SELECT * FROM file WHERE path = '/sys/kernel/tracing/available_filter_functions';` | Missing standard functions. |
| 42 | High-entropy files in /tmp (T1027). | Obfuscated payloads. | Osquery: `SELECT * FROM file WHERE directory = '/tmp' AND size > 100000;` | Files with random names or content. |
| 43 | Unusual child of sshd (T1055). | Injected sessions. | Osquery: `SELECT * FROM processes WHERE parent = (SELECT pid FROM processes WHERE name = 'sshd');` | Non-bash children. |
| 44 | APT post-invoke hooks (T1546). | Execution on updates. | Osquery: `SELECT * FROM deb_packages;` | Suspicious packages with hooks. |
| 45 | Root connections (T1071). | C2 from privileged procs. | Auditd Rule: `-a always,exit -S socket -F euid=0 -k root_connection` <br> Ausearch: `ausearch -k root_connection` | Java or other apps connecting out. |
| 46 | Memory map anomalies (T1055.001). | Injected code. | Osquery: `SELECT * FROM process_memory_map WHERE permissions = 'rwx';` | RWX regions in user procs. |
| 47 | Suspicious env vars (T1059). | Proxy execution. | Osquery: `SELECT * FROM process_envs WHERE value LIKE '%http_proxy%';` | Unexpected proxies or preload. |
| 48 | File creation in /dev/shm (T1204.002). | In-memory execution. | Auditd Rule: `-w /dev/shm -p wa -k shm_changes` <br> Ausearch: `ausearch -k shm_changes` | Executables in shared memory. |
| 49 | Failed logins from anomalous IPs (T1110). | Brute-forcing. | Osquery: `SELECT * FROM last WHERE type = 'login' AND success = 0 GROUP BY host HAVING COUNT(*) > 5;` | >5 failures per IP. |
| 50 | Anomalous package installs (T1195). | Supply chain via apt/rpm. | Osquery: `SELECT * FROM rpm_packages WHERE install_time > (strftime('%s','now')-86400);` | Unknown packages recently installed.
