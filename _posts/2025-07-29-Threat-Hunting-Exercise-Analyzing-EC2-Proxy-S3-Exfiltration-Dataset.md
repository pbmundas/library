---
layout: default
title: Hunting Exercise - 8
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Threat Hunting Exercise: Analyzing EC2 Proxy S3 Exfiltration Dataset

Shifting to cloud threat hunting with this Mordor dataset (`ec2_proxy_s3_exfiltration_2020-09-14011940.json`)—your SOC log skills extend nicely to CloudTrail. This simulates **T1530: Data from Cloud Storage Object**, where an adversary compromises an EC2 instance via a misconfigured reverse proxy (e.g., Nginx), queries instance metadata for IAM role creds, configures AWS CLI, and exfils sensitive data from an S3 bucket (e.g., "ring.txt" containing mock secrets) to their control.

#### Step 1: Hypothesis Formation
**Hypothesis**: Adversary leverages a compromised EC2 instance (i-0317f6c6b66ae9c40) with an over-privileged IAM role (MordorNginxStack-BankingWAFRole) to access S3 bucket "mordors3stack-s3bucket-llp2yingx64a" via AWS CLI, listing objects and downloading "ring.txt" (~89 bytes). Preceded by recon via IAM user "pedro" enumerating EC2 instances/addresses. Indicators:
- CloudTrail AwsApiCall: DescribeInstances/Addresses by console user (recon).
- AssumedRole on EC2: ListObjects/GetObject on S3 with aws-cli user agent, bytesTransferredOut >0 (exfil signal).
- No MFA on role session; source IP 1.2.3.4 (consistent attacker IP).

**Null Hypothesis**: Legit admin ops (e.g., dev syncing files). Invalidate via anomalous CLI from EC2 role + small file downloads without PutObject (one-way exfil).

**Rationale**: Mordor atomic maps to T1530 (data theft from S3) + T1078.004 (valid cloud accounts via role abuse). Filename highlights EC2 as proxy for stealthy S3 access.

#### Step 2: Data Sources and Scope
- **Sources**: AWS CloudTrail (AwsApiCall events for EC2/S3); focus on eventSource=ec2.amazonaws.com/s3.amazonaws.com, eventCategory=Data for exfil.
- **Scope**: ~2020-09-14T00:44-01:13 UTC; Account 123456789123; IPs: 1.2.3.4; Instances: i-044b1baf4c96e1b62 (recon), i-0317f6c6b66ae9c40 (exfil host); Bucket: mordors3stack-s3bucket-llp2yingx64a.
- **SIEM Queries** (adapt to Athena/Splunk Cloud):
  - Recon: `eventSource = 'ec2.amazonaws.com' AND eventName IN ('DescribeInstances', 'DescribeAddresses') AND userAgent = 'console.ec2.amazonaws.com'`
  - Exfil: `eventSource = 's3.amazonaws.com' AND eventName IN ('ListObjects', 'GetObject') AND userIdentity.type = 'AssumedRole' AND additionalEventData.bytesTransferredOut > 0`
  - Chain: `sourceIPAddress = '1.2.3.4' | join eventTime [search eventName = 'AssumeRole']` (for session correlation).

#### Step 3: Key Findings
Parsed ~10+ visible events (full ~100 truncated). Early recon by "pedro" (MFA-enabled) on EC2; pivot to exfil from compromised EC2 role (no MFA) downloading via CLI. "ring.txt" likely contains exfil data (e.g., creds/hashes).

| Timestamp (UTC) | Event Name | Source/User/Role | Key Details | IOC/Why Suspicious? |
|-----------------|------------|------------------|-------------|---------------------|
| 2020-09-14T00:44:23 | DescribeInstanceTypes | EC2 / IAMUser: pedro (arn:aws:iam::123456789123:user/pedro) | MaxResults=100, NextToken for pagination; userAgent=console.ec2.amazonaws.com; IP=1.2.3.4. | **Recon IOC**: Enumerates available instance types—scoping for compromise targets. MFA true, but external IP. |
| 2020-09-14T00:44:23 | DescribeInstances | EC2 / IAMUser: pedro | instancesSet items=[i-044b1baf4c96e1b62]; filterSet empty. | Targets specific instance—potential pivot for proxy setup. |
| 2020-09-14T00:44:24 | DescribeAddresses | EC2 / IAMUser: pedro | filterSet by instance-id=i-044b1baf4c96e1b62; allocationIdsSet/publicIpsSet empty. | Maps EIPs to instance—enables proxy/routing for exfil. |
| 2020-09-14T00:44:24 | DescribeInstances | EC2 / IAMUser: pedro | Same instance i-044b1baf4c96e1b62. | Duplicate query—iterative recon. |
| (Truncated ~00:48) | ModifyInstanceAttribute? | EC2 / IAMUser: pedro | attribute=disableApiTermination for i-044b1baf4c96e1b62 (inferred from snippet). | Hardens instance against termination—persistence post-compromise. |
| 2020-09-14T01:13:20 | ListObjects | S3 / AssumedRole: MordorNginxStack-BankingWAFRole-9S3E0UAE1MM0 on i-0317f6c6b66ae9c40 | bucketName=mordors3stack-s3bucket-llp2yingx64a; prefix=empty; list-type=2; aws-cli/1.18.136; bytesOut=500. | **Exfil IOC**: Lists bucket contents from EC2 role (ec2RoleDelivery=1.0)—abuses proxy for S3 enum. No MFA. |
| 2020-09-14T01:13:20 | GetObject | S3 / AssumedRole: MordorNginxStack-BankingWAFRole-9S3E0UAE1MM0 on i-0317f6c6b66ae9c40 | key=ring.txt; aws-cli; bytesOut=89; Cipher=ECDHE-RSA-AES128-GCM-SHA256. | **Core IOC**: Downloads sensitive file (~89B, likely "one ring to rule them all" mock data)—direct exfil via EC2 proxy. Consistent IP. |

**Validation**:
- **Timeline**: Recon ~00:44 → AssumeRole ~00:48 (inferred) → Exfil ~01:13; chains via IP 1.2.3.4.
- **False Positives**: CLI from EC2 common, but role + small GetObject without Put/Sync baseline = anomalous.
- **Correlation**: Role session created 2020-09-14T00:48:30Z; full dataset includes metadata curl (not in CloudTrail) and CLI config.

#### Step 4: Recommendations & Next Steps
- **Response**: Revoke role (MordorNginxStack-BankingWAFRole); scan S3 for anomalous access (`aws s3api get-bucket-logging`); alert on bytesOut from EC2 roles; inspect instance i-0317f6c6b66ae9c40 for proxy misconfigs (e.g., Nginx exposing 169.254.169.254).
- **Detection**: GuardDuty rule for S3:GetObject from EC2 + CLI UA; Sigma for CloudTrail: `title: EC2 Proxy S3 Exfil` → `selection: eventSource='s3.amazonaws.com' eventName='GetObject' userIdentity.type='AssumedRole' additionalEventData.bytesTransferredOut > 0`.
- **Pro Tip**: Baseline role sessions—external IP + no MFA = red. Chain to T1078.004 (role abuse). In your SOC, hunt CLI events from instances.

Hypothesis **confirmed**—S3 data theft via EC2 proxy! Cloud logs are gold for this. Query for S3 bytesOut in your env? Module 9: Real AWS breach cases?
