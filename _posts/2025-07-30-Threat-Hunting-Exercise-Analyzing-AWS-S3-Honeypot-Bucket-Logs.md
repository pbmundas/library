---
layout: default
title: Hunting Exercise - 9
category: Threat-Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing AWS S3 Honeypot Bucket Logs

Diving into cloud honeypot data with this CSV (`AWS_S3_HoneyBucketLogs.csv`)—a treasure trove for spotting **T1595.002: Active Scanning - Vulnerability Scanning** in AWS environments. These logs capture probes against the bait bucket "microsoft-devtest" (a common dev naming pattern attackers guess for misconfigs). Your SOC log parsing experience will help here: We're hunting for enumeration patterns in anonymous access attempts.

#### Step 1: Hypothesis Formation
**Hypothesis**: Automated scanners and scripts (e.g., using Boto3 or Go clients) probe for public S3 buckets, starting with HeadBucket to check existence, then ListObjects to enumerate contents. High repeated attempts (e.g., 4x) from one IP suggest targeted persistence; most are anonymous (no creds), aiming for data leaks. Ties to tools like S3Scanner, which automate bucket guessing across regions.

**Null Hypothesis**: Legit traffic (e.g., internal tools). Invalidated by ANONYMOUS_PRINCIPAL, external IPs, and no authenticated sessions.

**Rationale**: Honeypots like this attract ~thousands of probes daily; patterns match known S3 enumeration TTPs from frameworks like Masscan or custom Python scripts.

#### Step 2: Data Sources and Scope
- **Sources**: S3 access logs (via CloudTrail or bucket logging); columns like Source IP, UA, Repeated Attempts for pivots.
- **Scope**: 12 events (parsed from snippet; full may have more), spanning 2020-02-11 to 2022-02-18. Focus: Anonymous AwsApiCall events on "microsoft-devtest".
- **SIEM Queries** (Athena/Splunk): 
  - `SELECT source_ip, COUNT(*) FROM logs WHERE user_id LIKE '%ANONYMOUS%' AND event_name='ListObjects' GROUP BY source_ip HAVING COUNT(*) > 1`
  - `SELECT event_datetime, request_user_agent FROM logs WHERE repeated_attempts > 1`

#### Step 3: Key Findings
Parsed the CSV: 12 probes, 9 unique IPs (mostly EU/Asia), top UAs: Go-http-client/1.1 (3x, common in scanners), Boto3 (2x, AWS SDK abuse). One standout: 177.131.167.145 with 4 repeats in 2022. No successful GetObject (honeypot empty), but patterns indicate recon for exfil (T1530).

| Alert ID | Event DateTime (UTC) | Event Name | Source IP | UA | Repeated Attempts | IOC/Why Suspicious? |
|----------|----------------------|------------|-----------|----|-------------------|---------------------|
| 302 | 2022-02-18 17:34:57 | ListObjects | 177.131.167.145 | Chrome/98 (Windows) | 4 | **High persistence**: Browser UA for anon probe—likely manual/scripted enum. IP in Brazil; matches scanner patterns. |
| 301 | 2022-02-18 14:54:56 | ListObjects | 212.83.184.16 | Boto3/1.17.40 (CentOS) | 1 | SDK from Linux VM—automated guessing across regions (s3.amazonaws.com). IP France. |
| 300 | 2022-02-17 14:18:02 | ListObjects | 212.83.184.13 | Boto3/1.17.40 (CentOS) | 1 | Similar to above; sibling IP—coordinated scan. list-type=2 (version 2, common in tools). |
| 299 | 2022-02-17 10:34:18 | ListObjects | 109.70.66.85 | Go-http-client/1.1 | 1 | Golang client—stealthy, used in S3Scanner-like tools. IP Germany. |
| 298 | 2022-02-16 16:57:17 | HeadBucket | 194.126.177.33 | (empty) | 1 | Existence check precursor to List; no UA hides scanner. IP Germany. |
| 8 | 2020-07-12 20:19:41 | ListObjects | 43.251.92.37 | aws-cli/1.17.9 (Windows) | 1 | CLI probe; IP India (Alibaba Cloud?). |
| 7 | 2020-07-12 17:05:38 | ListObjects | 43.251.92.37 | Ruby | 1 | Same IP, Ruby script—multi-tool from one actor. Authenticated (account 451083579297). |
| 6 | 2020-06-24 10:20:33 | ListObjects | 95.217.6.207 | Go-http-client/1.1 | 1 | Go scanner; IP Germany (Hetzner). |
| 5 | 2020-06-24 10:16:51 | HeadBucket | 95.217.6.207 | Go-http-client/1.1 | 1 | Paired Head+List—classic workflow. |
| 4 | 2020-05-01 14:28:11 | HeadBucket | 103.73.151.226 | Ruby | 1 | Early probe; IP India. |
| 3 | 2020-02-11 03:33:15 | ListObjects | 34.68.153.199 | python-requests/2.22.0 | 1 | Python lib—scripted; IP US (Google Cloud). |
| 2 | 2020-02-11 03:33:11 | ListObjects | 34.68.153.199 | python-requests/2.22.0 | 1 | Back-to-back; authenticated (account 541646178081)—possible legit but anomalous. |

**Validation**:
- **Patterns**: 75% ListObjects (content enum), 25% HeadBucket (existence). All anonymous except 2 (authenticated but suspicious UAs). Spikes in 2022 suggest increased scanning post-public exploits.
- **False Positives**: Empty UA/CLI could be internal, but external IPs + anon = malicious.
- **Geos**: Mostly EU (Germany/France), some Asia/US—global scanner farms.

#### Step 4: Recommendations & Next Steps
- **Immediate**: Block top IPs (e.g., 177.131.167.145) via WAF/NACL; enable S3 access logging if not already.
- **Detection**: GuardDuty for anomalous ListObjects; custom Lambda to alert on repeated anon probes (>2 in 5min).
- **Pro Tip**: Use honeytokens in buckets (e.g., fake creds file) to track exfil. Baseline: <1 probe/day normal; >5 = alert. Chain to T1078.004 (cloud account abuse).

Hypothesis **confirmed**—S3 bucket scanning campaign! These are low-effort probes for easy wins. In your SOC, IP grouping would flag clusters. 
