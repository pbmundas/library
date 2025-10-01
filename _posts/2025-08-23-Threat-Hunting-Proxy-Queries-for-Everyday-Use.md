---
layout: default
title: Proxy Queries - Top 50
category: Threat-Hunting-Queries  # This becomes a main topic in sidebar
---

### Essential Threat Hunting Hypotheses for Web Proxy / Secure Web Gateway Logs

Threat hunting in web proxy or secure web gateway logs is essential for detecting web-based adversaries, including C2 communications, data exfiltration, phishing, and malware delivery. These hypotheses map to MITRE ATT&CK tactics like Command and Control (TA0011), Exfiltration (TA0010), and Initial Access (TA0001). Use tools like Splunk, ELK Stack, or proxy-specific dashboards (e.g., Zscaler, Blue Coat) for analysis. Each entry includes:

- **Hypothesis**: A testable assumption about malicious activity.
- **Rationale**: Relevance to threats (e.g., beaconing, evasion).
- **Sample Query**: Splunk SPL example (assumes `index=proxy`, `sourcetype=proxy_logs`; adjust `earliest=-7d` and fields like `src_ip`, `dest_ip`, `url`, `domain`, `user_agent`, `method`, `status`, `bytes_sent`, `bytes_received`, `category`, `mime_type`).
- **Expected Indicators**: Anomalies to investigate.

Run these regularly to baseline traffic. Prioritize based on exposure (e.g., user browsing patterns).

| #  | Hypothesis | Rationale | Sample Query | Expected Indicators |
|----|------------|-----------|------------------|---------------------|
| 1  | High connection duration to external domains (T1071.001). | Malware beacons keep connections open or use jitter for C2 check-ins. | `index=proxy earliest=-7d \| stats sum(duration) by src_ip, dest_ip \| where sum(duration) > 3600 \| sort -sum(duration)` | Total duration >1hr per src-dest pair; periodic patterns. |
| 2  | Anomalous HTTP error codes from single source (T1071.004). | DGA malware generates failed domains, leading to frequent errors. | `index=proxy earliest=-7d status>=400 \| stats count by src_ip, status \| where count > 50 \| sort -count` | >50 errors per src_ip; clustered on 404/503 codes. |
| 3  | Consistent inbound byte sizes indicating beaconing (T1071.001). | Idle malware downloads fixed-size responses from C2. | `index=proxy earliest=-7d \| stats count by src_ip, dest_ip, bytes_received \| where count > 20 and stdev(bytes_received) < 100` | Low variance in bytes_received; >20 requests. |
| 4  | High outbound byte volumes suggesting exfiltration (T1041). | Attackers upload data via POST/PUT to cloud or C2. | `index=proxy earliest=-7d \| stats sum(bytes_sent) by src_ip, dest_ip \| where sum(bytes_sent) > 10000000 \| sort -sum(bytes_sent)` | >10MB sent per pair; off-hours spikes. |
| 5  | Unusual ratio of POST/PUT to GET methods (T1071.001). | Beaconing or exfil uses more uploads than normal browsing. | `index=proxy earliest=-7d \| stats count by method, src_ip, dest_ip \| eval ratio=if(method IN ("POST","PUT"), count, 0)/if(method="GET", count, 1) \| where ratio > 0.5` | Ratio >0.5; non-file upload contexts. |
| 6  | Access to low-popularity hostnames (T1071.001). | Malicious sites have few visits vs. top domains. | `index=proxy earliest=-7d \| stats dc(src_ip) as hit_count by domain \| where hit_count < 5 and domain NOT IN (top_1m_domains)` | Hit count <5; non-top 1M domains. |
| 7  | Repeated URL paths to same domain (T1071.001). | Compromised sites use fixed paths for C2. | `index=proxy earliest=-7d \| stats count by src_ip, domain, path \| where count > 50 \| sort -count` | >50 repeats; suspicious paths like /api/. |
| 8  | Long or encoded URL queries (T1027). | Malware encodes commands or IDs in queries for C2. | `index=proxy earliest=-7d \| eval query_len=len(query) \| where query_len > 100 or query LIKE "%=%" \| stats count by src_ip, url` | Queries >100 chars; base64-like strings. |
| 9  | Downloads with high-entropy filenames (T1027). | Malware droppers use random names to evade. | `index=proxy earliest=-7d mime_type="application/octet-stream" \| eval entropy=entropy(filename) \| where entropy > 5 \| stats count by filename` | Entropy >5; EXE/JS from non-trusted. |
| 10 | Anomalous MIME types for URLs (T1566). | Phishing/malware serves EXE as image/PDF. | `index=proxy earliest=-7d mime_type NOT MATCH url \| stats count by src_ip, mime_type, url \| where count > 10` | Mismatch like EXE on .jpg URL. |
| 11 | Connections to uncategorized domains (T1071.001). | New/malicious sites evade categorization. | `index=proxy earliest=-7d category="uncategorized" \| stats count by src_ip, domain \| where count > 5` | >5 accesses; check reputation. |
| 12 | User-agents from scripting tools (T1059). | Malware uses curl/Python for C2, not browsers. | `index=proxy earliest=-7d user_agent IN ("curl*","python*") \| stats count by src_ip, user_agent \| where count > 20` | Non-browser UAs; high volume. |
| 13 | Access to newly registered domains (T1071.004). | Fresh domains for agile C2 infrastructure. | `index=proxy earliest=-7d \| lookup domain_age domain OUTPUT age \| where age < 30 \| stats count by src_ip, domain` | Domains <30 days; low TTL. |
| 14 | Direct IP in URLs bypassing DNS (T1071). | Evasion of DNS monitoring for malicious access. | `index=proxy earliest=-7d url LIKE "http*://[0-9]*.[0-9]*.[0-9]*.[0-9]*" \| stats count by src_ip, url` | URLs with IPs; no domain. |
| 15 | Suspicious file extensions in URLs (T1105). | Malware delivery via EXE/JAR in paths. | `index=proxy earliest=-7d url LIKE "*.exe" OR url LIKE "*.jar" \| stats count by src_ip, url \| where count > 5` | Downloads from non-trusted; unusual sources. |
| 16 | Beaconing intervals in requests (T1071.001). | Periodic C2 check-ins with fixed timing. | `index=proxy earliest=-7d \| timechart span=5m count by domain \| where stdev(count) < 1 and avg(count) > 10` | Low variance; requests every 5-60min. |
| 17 | Access to known phishing categories (T1566). | Blocked/allowed phishing sites indicate compromise. | `index=proxy earliest=-7d category="phishing" \| stats count by src_ip, domain \| where count > 10` | Repeated access; correlate with alerts. |
| 18 | High entropy in URL queries (T1027). | Obfuscated exfil or commands in queries. | `index=proxy earliest=-7d \| eval entropy=entropy(query) \| where entropy > 6 \| stats count by src_ip, url` | Entropy >6; random strings. |
| 19 | Anomalous referrer URLs (T1071). | Malicious redirects from compromised sites. | `index=proxy earliest=-7d referrer NOT MATCH domain \| stats count by src_ip, referrer \| where count > 5` | Mismatched referrers; suspicious chains. |
| 20 | Off-hours high-volume traffic (T1041). | Exfil during low activity periods. | `index=proxy earliest="0:00" latest="6:00" \| stats sum(bytes_sent) by src_ip \| where sum(bytes_sent) > 5000000` | >5MB sent off-hours; rare domains. |
| 21 | Connections to rare TLDs (T1071.004). | Malicious domains use obscure TLDs like .top. | `index=proxy earliest=-7d \| eval tld=replace(domain,".*\\.([^.]+)$","\\1") \| where tld IN ("top","xyz","ru") \| stats count by src_ip, domain` | High access to uncommon TLDs. |
| 22 | HTTP on non-standard ports (T1571). | Tunneling or evasion via unusual ports. | `index=proxy earliest=-7d dest_port NOT IN (80,443) protocol=http \| stats count by src_ip, dest_port \| where count > 10` | HTTP on >1024 ports; high bytes. |
| 23 | Downloads from dynamic DNS (T1071.001). | DDNS for resilient C2. | `index=proxy earliest=-7d domain LIKE "*.dyndns.org" OR domain LIKE "*.no-ip.com" \| stats count by src_ip, domain` | Frequent access; non-browser UAs. |
| 24 | Suspicious user-agent mismatches (T1071). | Malware spoofs UAs inconsistently. | `index=proxy earliest=-7d \| stats values(user_agent) by src_ip \| where mvcount(user_agent) > 3 \| sort -mvcount(user_agent)` | >3 UAs per src_ip; rare combinations. |
| 25 | Access to anonymizer categories (T1090). | Proxy evasion for C2 or exfil. | `index=proxy earliest=-7d category="anonymizer" \| stats count by src_ip, domain \| where count > 20` | High access; correlate with exfil. |
| 26 | Large response sizes for GET requests (T1041). | Exfil hidden in responses. | `index=proxy earliest=-7d method=GET bytes_received > 1000000 \| stats count by src_ip, url \| sort -bytes_received` | >1MB GETs; unusual domains. |
| 27 | Repeated failures then success (T1071). | Retries after blocks indicate persistence. | `index=proxy earliest=-7d status>=400 \| join src_ip, domain [search status=200 earliest=-10m] \| stats count` | Fail followed by success shortly after. |
| 28 | Access to pastebin-like sites (T1102.002). | Staging for payloads or exfil. | `index=proxy earliest=-7d domain IN ("*.pastebin.com","*.hastebin.com") \| stats count by src_ip \| where count > 10` | Non-browser access; high bytes. |
| 29 | Unusual MIME for known domains (T1566). | Spoofed content on legit sites. | `index=proxy earliest=-7d domain IN (trusted_domains) mime_type="application/x-msdownload" \| stats count by domain` | EXE on trusted like google.com. |
| 30 | Beaconing to cloud storage (T1102.002). | Exfil via Dropbox/OneDrive. | `index=proxy earliest=-7d domain IN ("*.dropbox.com","*.onedrive.com") bytes_sent > 500000 \| stats count by src_ip` | Large uploads; off-pattern. |
| 31 | High query parameter length (T1027). | Encoded data in queries for C2. | `index=proxy earliest=-7d \| eval query_len=len(query) \| where query_len > 200 \| stats count by src_ip, url` | >200 chars; encoded patterns. |
| 32 | Access to TOR domains (T1090.002). | Anonymization for malicious activity. | `index=proxy earliest=-7d domain LIKE "*.onion" \| stats count by src_ip \| where count > 5` | Onion access; non-standard. |
| 33 | Suspicious file names in downloads (T1105). | Malware with random or disguised names. | `index=proxy earliest=-7d filename LIKE "*.tmp" OR filename LIKE "*.dat" \| stats count by src_ip, filename` | Unusual extensions; high entropy. |
| 34 | Asynchronous request intervals (T1071.001). | Malware beaconing with variable timing. | `index=proxy earliest=-7d \| timechart span=1m count by src_ip \| where stdev(count) > 5 and avg(count) > 10` | High variance; irregular bursts. |
| 35 | Access to threat intel IOCs (T1071.001). | Matches with known malicious domains/IPs. | `index=proxy earliest=-7d \| lookup threat_iocs domain OUTPUT match \| where match="true" \| stats count by src_ip, domain` | Hits on IOC lists; repeated. |
| 36 | Unusual browser versions in UAs (T1071). | Outdated/spoofed UAs for evasion. | `index=proxy earliest=-7d user_agent LIKE "*MSIE 6.0*" \| stats count by src_ip, user_agent` | Deprecated versions; mismatches. |
| 37 | High-volume to single domain (T1071.001). | Focused C2 or scraping. | `index=proxy earliest=-7d \| stats count by src_ip, domain \| where count > 100 \| sort -count` | >100 requests; low diversity. |
| 38 | Mismatched protocol-port pairs (T1571). | Tunneling like HTTPS on 80. | `index=proxy earliest=-7d protocol="https" dest_port=80 \| stats count by src_ip, dest_port` | Protocol-port mismatches. |
| 39 | Downloads during downtime (T1041). | Stealthy exfil in maintenance windows. | `index=proxy earliest="maintenance_window" \| stats sum(bytes_sent) by src_ip \| where sum(bytes_sent) > 1000000` | Activity in scheduled outages. |
| 40 | Access to homoglyph domains (T1566). | Phishing via lookalikes. | `index=proxy earliest=-7d domain LIKE "*g00gle.com*" \| stats count by src_ip, domain` | Typosquatted domains; user access. |
| 41 | Repeated same query strings (T1071.004). | Fixed parameters in C2 beacons. | `index=proxy earliest=-7d \| stats count by src_ip, domain, query \| where count > 50` | >50 identical queries. |
| 42 | Anomalous category changes (T1562.004). | Evasion by category hopping. | `index=proxy earliest=-7d \| stats values(category) by domain \| where mvcount(category) > 1` | Domains with multiple categories. |
| 43 | Brute-force like URL patterns (T1110). | Testing for vulnerabilities. | `index=proxy earliest=-7d url LIKE "*/login*" status=401 \| stats count by src_ip \| where count > 20` | >20 401s; login paths. |
| 44 | Access to proxy evasion sites (T1090). | Tools like ultrasurf for bypass. | `index=proxy earliest=-7d domain LIKE "*.ultrasurf.us" \| stats count by src_ip` | Evasion tool domains. |
| 45 | High packet entropy in payloads (T1027). | Obfuscated exfil data. | `index=proxy earliest=-7d \| eval entropy=entropy(payload) \| where entropy > 7 \| stats count by src_ip` | Entropy >7; non-text traffic. |
| 46 | Queries to young domains via proxy (T1071.004). | Recent registrations for C2. | `index=proxy earliest=-7d \| lookup domain_age domain OUTPUT age \| where age < 7 \| stats count` | Domains <7 days; high access. |
| 47 | Failed then allowed requests (T1562). | Retries after policy changes. | `index=proxy earliest=-7d status=403 \| join src_ip, url [search status=200 earliest=-5m]` | Block followed by allow. |
| 48 | Unusual UA strings (T1071.001). | Malformed or rare UAs from malware. | `index=proxy earliest=-7d user_agent NOT IN (known_uas) \| stats count by user_agent \| where count > 5` | Unknown UAs; high volume. |
| 49 | Spike in denied requests (T1499). | DoS or scanning attempts. | `index=proxy earliest=-7d status=403 \| timechart span=1h count \| where count > baseline*2` | Off-baseline spikes; clustered srcs. |
| 50 | Access to malware hosting domains (T1071.001). | Known bad domains for payloads. | `index=proxy earliest=-7d domain IN (malware_domains_list) \| stats count by src_ip, domain \| where count > 5` | Hits on malware lists; downloads.
