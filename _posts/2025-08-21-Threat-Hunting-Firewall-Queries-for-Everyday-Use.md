---
layout: default
title: Firewall Queries - Top 50
category: Threat-Hunting-Queries  # This becomes a main topic in sidebar
---

### Essential Threat Hunting Hypotheses for Firewall Environments

Threat hunting on firewalls focuses on analyzing logs from network or host-based firewalls (e.g., Palo Alto, Cisco ASA, iptables, Windows Firewall) to detect anomalies, policy evasions, and advanced threats. These hypotheses align with MITRE ATT&CK tactics like Discovery (TA0007), Exfiltration (TA0010), and Command and Control (TA0011). Use tools like Splunk, ELK Stack, or firewall-specific consoles for querying. Each entry includes:

- **Hypothesis**: A testable assumption about malicious activity.
- **Rationale**: Relevance to firewall-specific threats (e.g., scanning, exfiltration).
- **Sample Query**: Example in Splunk SPL (adapt for your tool; assumes index=firewall, sourcetype=firewall_logs; time range e.g., earliest=-7d).
- **Expected Indicators**: Anomalies to investigate.

Run these periodically to baseline traffic. Focus on high-risk rules or zones (e.g., DMZ).

| #  | Hypothesis | Rationale | Sample Query | Expected Indicators |
|----|------------|-----------|------------------|---------------------|
| 1  | Excessive denied inbound connections from a single external IP (T1595). | Indicates port scanning or reconnaissance attempts to map vulnerabilities. | `index=firewall action=deny direction=inbound \| stats count by src_ip \| where count > 100 \| sort -count` | >100 denies per IP in short bursts; correlate with OSINT for malicious IPs. |
| 2  | Unusual outbound traffic spikes during off-hours (T1041). | Suggests data exfiltration or C2 communication when monitoring is low. | `index=firewall action=allow direction=outbound earliest="0:00" latest="6:00" \| stats sum(bytes_out) by dest_ip \| where sum(bytes_out) > 1000000` | High byte volumes to rare destinations outside business hours. |
| 3  | Protocol-port mismatches (e.g., HTTP on non-80/443) (T1571). | Attackers tunnel traffic to evade detection or exploit loose policies. | `index=firewall protocol=http dest_port!=80 dest_port!=443 \| stats count by src_ip, dest_port \| where count > 10` | Non-standard ports with HTTP/SMB; check for tunneling tools. |
| 4  | Multiple MAC addresses from a single source IP (T1016). | Indicates ARP spoofing or network device compromise. | `index=firewall \| stats values(mac_src) by src_ip \| where mvcount(mac_src) > 1` | Single IP with >1 MAC; investigate for MITM attacks. |
| 5  | Connections to Geo-blocked or rare countries (T1071). | Bypassing geo-restrictions for C2 or exfil to adversary infrastructure. | `index=firewall action=allow direction=outbound country_dest IN ("rare_countries_list") \| stats count by dest_ip \| where count > 5` | Traffic to blocked regions; cross-reference threat intel. |
| 6  | High-volume ICMP traffic from unknown external IPs (T1040). | Used for tunneling, reconnaissance, or DoS amplification. | `index=firewall protocol=icmp \| stats count by src_ip \| where count > 50 and src_ip NOT IN (known_ips)` | Consecutive pings >50; large packet sizes indicating tunneling. |
| 7  | SMB outbound on non-standard ports (T1021). | Common for lateral movement or exfil in compromised networks. | `index=firewall protocol=smb dest_port NOT IN (137,138,139,445) \| stats count by src_ip, dest_ip` | SMB to external IPs; high bytes_out suggesting data theft. |
| 8  | Excessive firewall denies from internal hosts (T1595.002). | Internal scanning or misconfigured/malicious devices probing network. | `index=firewall action=deny direction=internal \| stats count by src_ip \| where count > 500` | >500 denies per host in 8min; cluster patterns for worms. |
| 9  | Connections to known malicious or bad reputation IPs (T1071.001). | C2 communication or malware beaconing to threat actor domains. | `index=firewall action=allow \| lookup threat_intel ip as dest_ip OUTPUT reputation \| where reputation="malicious" \| stats count by dest_ip` | Allowed traffic to blacklisted IPs; periodic beacons. |
| 10 | Unusual SSH inbound/outbound on port 22 (T1021.004). | Backdoors or unauthorized remote access attempts. | `index=firewall dest_port=22 action=allow \| stats count by src_ip, dest_ip \| where count > 10 and src_ip NOT IN (trusted_ips)` | Connections from unknown IPs; brute-force patterns in denies. |
| 11 | DNS traffic over non-standard ports (e.g., TCP/53) (T1071.004). | DNS tunneling for exfil or C2 evasion. | `index=firewall app=dns dest_port!=53 \| stats sum(bytes_out) by src_ip \| where sum(bytes_out) > 500000` | High outbound bytes; long sessions to suspicious resolvers. |
| 12 | Source IP violating multiple policies (T1562.004). | Policy evasion or compromised host testing boundaries. | `index=firewall action=deny \| stats dc(policy_id) by src_ip \| where dc(policy_id) > 5` | Single IP hitting >5 rules; investigate for persistence. |
| 13 | Abnormally high traffic to rare ports on HVAs (T1046). | Targeting high-value assets for exploitation or DoS. | `index=firewall dest_ip IN (hva_list) dest_port>1024 \| stats sum(bytes_in) by dest_port \| where sum(bytes_in) > 1000000` | Non-standard ports with spikes; correlate with alerts. |
| 14 | Scan followed by successful tunnel establishment (T1595.001). | Recon leading to exploitation like ngrok for C2. | `index=firewall \| search "scan_pattern" \| join src_ip [search action=allow protocol=tunnel earliest=-1h]` | Denies followed by allows to same IP; URL patterns like ngrok.io. |
| 15 | >100 distinct external IPs to same target (T1595). | Distributed scanning or DDoS precursor. | `index=firewall direction=inbound \| stats dc(src_ip) by dest_ip \| where dc(src_ip) > 100` | High unique srcs in 1min; cluster on ports. |
| 16 | Rare DHCP traffic to unregistered servers (T1016.001). | Rogue DHCP for MITM or network disruption. | `index=firewall dest_port=67 protocol=udp dest_ip NOT IN (dhcp_servers) \| stats count by src_ip` | Internal/external UDP 67 to unknown dests. |
| 17 | Specific scan types (e.g., PING, TCP Half-Open) (T1595.001). | Common recon techniques like NULL/FIN/XMAS scans. | `index=firewall protocol=tcp flags IN ("NULL","FIN","XMAS") \| stats count by src_ip, dest_port` | Distinct dest ports from same src; stealth patterns. |
| 18 | Source of previous attack now as destination (T1071). | Infected host pivoting or callback. | `index=firewall \| search src_ip IN (past_attack_dests) \| stats count by dest_ip` | Traffic reversal within 1d; high severity alerts. |
| 19 | DMZ jumping via lateral movement (T1021). | Hopping across DMZ for deeper access. | `index=firewall zone=dmz \| stats count by src_ip, dest_ip \| where src_ip IN (dmz_ips) and dest_ip IN (internal_ips)` | Unusual port access or process grouping in DMZ. |
| 20 | Circumvention after block (non-standard ports) (T1562). | Retries on high ports after denial. | `index=firewall action=deny dest_port>1024 \| join src_ip [search action=allow earliest=-5m]` | Block followed by allow to same IP/port shortly after. |
| 21 | Rare IP generating ICMP to multiple hosts (T1040). | Recon or tunneling across network. | `index=firewall protocol=icmp \| stats dc(dest_ip) by src_ip \| where dc(dest_ip) > 10 and src_ip NOT IN (known)` | Multi-host pings from uncommon src. |
| 22 | Allowed inbound from rare country to DMZ (T1071). | Geo-evasion targeting exposed servers. | `index=firewall action=allow direction=inbound zone=dmz country_src="rare" \| stats count by src_ip` | Multiple ports from same foreign IP. |
| 23 | Decoy engagement with public IPs (T1188). | Adversary interacting with honeypots. | `index=firewall dest_ip IN (decoy_ips) \| stats count by src_ip, action` | Probes or exploits to decoys; analyze TTPs. |
| 24 | Private src to distinct dest ports quickly (T1595). | Internal port scanning for vulnerabilities. | `index=firewall src_zone=internal \| stats dc(dest_port) by src_ip \| where dc(dest_port) > 50` | >50 ports in short time; non-standard. |
| 25 | Communications to suspicious ports (e.g., backdoors) (T1571). | Known trojan ports like 1234 (Ultors). | `index=firewall dest_port IN (suspicious_ports_list) \| stats count by dest_port, src_ip` | Traffic to ports associated with malware (e.g., 6667 SubSeven). |
| 26 | Unusual SMB from rare to critical servers (T1021.002). | Lateral exfil or movement to HVAs. | `index=firewall protocol=smb dest_ip IN (critical_servers) src_ip NOT IN (known) \| stats count` | Rare srcs with high bytes; non-standard ports. |
| 27 | High severity alarms to public dests (T1046). | Repeated attacks in short windows. | `index=firewall severity=high dest_zone=public \| stats count by src_ip, dest_ip \| where count > 10` | >10 in 10min; group on policy hits. |
| 28 | Web shell access and movement in DMZ (T1505.003). | Post-exploit lateral from exposed servers. | `index=firewall zone=dmz app=web dest_port=22 \| stats count by src_ip` | SSH to DMZ after web traffic; upload patterns. |
| 29 | Outbound to TOR or crypto ports (T1090.002). | Anonymization for C2 or mining. | `index=firewall direction=outbound dest_port IN (9001,9050,8333) \| stats count by dest_port` | Connections to anonymity networks; persistent sessions. |
| 30 | Increased packet volume to nonstandard port (T1041). | Potential DoS or exfil bursts. | `index=firewall dest_port>1024 \| stats sum(packets) by dest_ip \| where sum(packets) > 10000` | Matching src/dest ports with spikes. |
| 31 | Authorized DNS via TCP with high volume (T1071.004). | Tunneling or DGA over DNS. | `index=firewall app=dns protocol=tcp \| stats sum(packets) by dest_ip \| where sum(packets) > 5000` | Public DNS with unusual bytes; non-UDP. |
| 32 | Odd RDP/LDAP/FTP activity to HVAs (T1021.001). | Unauthorized remote access to critical assets. | `index=firewall app IN (rdp,ldap,ftp) dest_ip IN (hva_list) src_ip NOT IN (known) \| stats count` | Rare machines; off-hours access. |
| 33 | Traffic from past attack srcs as dests (T1071). | Callback from infected systems. | `index=firewall src_ip IN (past_attack_srcs) \| stats count by dest_ip` | Role reversal; correlate with IOCs. |
| 34 | Private IPs to public bad reps (T1071.001). | Outbound C2 from internal compromise. | `index=firewall src_zone=private dest_zone=public reputation=bad \| stats count by dest_ip` | Allowed to malicious; beacon intervals. |
| 35 | Consecutive ICMP for long duration (T1040). | Sustained tunneling or recon. | `index=firewall protocol=icmp \| timechart span=1h count by src_ip \| where count > 100` | Long sessions; rare srcs. |
| 36 | Allowed comms to same subnet post-block (T1562). | Geo or IP evasion retries. | `index=firewall action=allow country_dest="blocked" \| stats count by dest_ip` | Post-deny allows; subnet clustering. |
| 37 | Multiple src addrs to same blocked public IP (T1562.004). | Distributed evasion of controls. | `index=firewall action=deny dest_ip="blocked_ip" \| stats dc(src_ip) by dest_ip \| where dc(src_ip) > 10` | High unique srcs in short time. |
| 38 | Rare IP ICMP to single host (T1040). | Targeted recon. | `index=firewall protocol=icmp dest_ip="target" src_ip NOT IN (known) \| stats count` | Unusual srcs; packet anomalies. |
| 39 | Communications to IP proxy servers (T1090). | Bypassing for malicious payloads. | `index=firewall dest_ip IN (proxy_list) \| stats count by src_ip` | Suspicious domains/IPs; high volume. |
| 40 | Unusually long connection durations (T1041). | Persistent C2 or exfil sessions. | `index=firewall \| stats avg(duration) by src_ip, dest_ip \| where avg(duration) > 3600` | Sessions >1hr; investigate bytes. |
| 41 | An IP using same dest port to multiple dests (T1595). | Horizontal scanning. | `index=firewall \| stats dc(dest_ip) by dest_port, src_ip \| where dc(dest_ip) > 20` | Fixed port, varying dests; short time. |
| 42 | Firewall policy changes or mods (T1562.004). | Unauthorized rule alterations for access. | `index=firewall event=policy_change \| stats count by user, policy_id` | Non-admin changes; correlate audits. |
| 43 | Brute-force on firewall auth (T1110). | Credential stuffing for admin access. | `index=firewall event=auth_fail \| stats count by src_ip \| where count > 20` | >20 fails per IP; lockouts. |
| 44 | Anomalous VPN tunnel establishments (T1133). | Unauthorized remote access post-recon. | `index=firewall app=vpn action=allow \| stats count by src_ip \| where src_ip NOT IN (trusted)` | Tunnels after scans; unusual users. |
| 45 | High entropy in packet payloads (T1027). | Obfuscated exfil or malware traffic. | `index=firewall \| eval entropy=if(high_entropy_payload,1,0) \| stats sum(entropy) by src_ip` | High entropy scores; non-HTTP traffic. |
| 46 | Connections to young domains (T1071.004). | C2 via recently registered domains. | `index=firewall app=http \| lookup domain_age domain as dest_domain OUTPUT age \| where age < 30 \| stats count` | Low-age domains with beacons. |
| 47 | Failed then successful policy hits (T1562). | Testing and evading rules. | `index=firewall action=deny \| join policy_id [search action=allow earliest=-10m]` | Deny followed by allow on same rule. |
| 48 | Unusual user-agent strings in traffic (T1071.001). | Malware or tools mimicking browsers. | `index=firewall app=http \| stats count by user_agent \| where user_agent NOT IN (known_agents)` | Rare or malformed UAs; high volume. |
| 49 | Spike in error messages or drops (T1499). | DoS or exploitation attempts. | `index=firewall event=error \| timechart span=1h count \| where count > baseline*2` | Off-baseline spikes; source clustering. |
| 50 | Anomalous multicast or broadcast traffic (T1200). | Network discovery or worms spreading. | `index=firewall dest_ip IN ("224.0.0.0/4","255.255.255.255") \| stats count by src_ip` | Internal broadcasts; unusual protocols. |

These hypotheses draw from common firewall log analysis practices, covering reconnaissance, evasion, and exfiltration. For expansions, refer to resources like Sigma rules or vendor-specific hunts.
