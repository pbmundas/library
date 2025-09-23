---
layout: default
title: Cybersecurity Fundamentals
category: Threat Hunting  # This becomes a main topic in sidebar
---

### Understanding Core Cybersecurity Concepts (CIA Triad)

The CIA triad—**Confidentiality**, **Integrity**, and **Availability**—is the core framework for cybersecurity, ensuring data protection across three pillars.

- **Confidentiality**: Ensures only authorized users access data. Example: Encryption protects sensitive emails from interception.
- **Integrity**: Ensures data remains accurate and unaltered. Example: Digital signatures prevent tampering with medical records.
- **Availability**: Ensures data and systems are accessible when needed. Example: Backup servers maintain access during hardware failures.

##### Breach Scenarios
- **Confidentiality Breach**: A hacker exploits weak passwords to access a company's database, causing a data leak of customer credit card details, leading to identity theft and legal penalties.
- **Integrity Breach**: Malware alters transaction logs in a banking system, changing deposit amounts, resulting in financial discrepancies and loss of trust.
- **Availability Breach**: A DDoS attack overwhelms an online retailer's servers during Black Friday, blocking customer access and causing significant revenue loss.

##### CIA Triad Diagram

```plaintext
+---------------------+
|      System         |
|                     |
|  +---------------+  |
|  | Confidentiality|  | <- Encryption & access controls prevent unauthorized access
|  +---------------+  |
|  |    Integrity  |  | <- Checksums & hashing detect/prevent unauthorized changes
|  +---------------+  |
|  |  Availability |  | <- Redundancy & backups ensure continuous access
|  +---------------+  |
|                     |
+---------------------+
```



---



### Exploring the Threat Landscape

The threat landscape encompasses diverse actors with distinct motives and methods, posing significant cybersecurity challenges.

- **Cybercrime**: Driven by financial gain, cybercrime involves illegal activities like theft or extortion. Example: The 2021 Colonial Pipeline ransomware attack by DarkSide, where a $4.4 million ransom was paid after a crippling oil supply disruption.
- **Nation-State Actors**: Backed by governments, these actors target strategic assets for espionage or disruption. Example: The 2020 SolarWinds attack, attributed to Russia, compromised U.S. agencies by injecting malware into software updates.
- **Hacktivists**: Motivated by ideology, hacktivists disrupt systems to promote causes. Example: Anonymous’s 2016 DDoS attack on the Turkish government websites to protest censorship.

##### Infographic Description
The infographic illustrates the relationships between these threats and their targets:
- **Cybercrime** targets financial institutions and businesses (e.g., banks, retailers) with arrows pointing to money symbols.
- **Nation-State Actors** target government and critical infrastructure (e.g., defense, energy) with arrows to shield and power icons.
- **Hacktivists** target organizations or governments opposing their causes (e.g., media, political sites) with arrows to megaphone symbols.
- Central node labeled "Internet" connects all threats, showing their shared digital battleground.

##### Threat Landscape Infographic

```plaintext
       +-----------+
       |  Internet |
       +-----------+
            |
            |-----------------+-----------------+-----------------
            |                 |                 |                
+-----------+         +-----------+         +-----------+
| Cybercrime |        | Nation-State|        | Hacktivists|
| (Money 💰) |        | (Shield 🛡️)|        | (Megaphone 📣)|
+-----------+         +-----------+         +-----------+
    |                     |                     |
    +--> Banks, Retail    +--> Gov, Energy      +--> Media, Gov
```

- **Cybercrime**: Targets financial gain (e.g., ransomware on businesses).
- **Nation-State Actors**: Focus on espionage/disruption (e.g., critical infrastructure).
- **Hacktivists**: Aim for ideological impact (e.g., protest sites).

---


### Identifying Common Attack Vectors

Recognizing common attack vectors is crucial for maintaining cybersecurity. Here’s a guide on three prevalent types—**phishing**, **malware**, and **social engineering**—with practical examples to help you identify and mitigate them.

- **Phishing**: Fraudulent attempts to steal sensitive information, often via email or fake websites. Example: A phishing email pretending to be from your bank, asking you to click a link and enter login credentials, which leads to a counterfeit site harvesting your data.
- **Malware**: Malicious software designed to damage or gain unauthorized access. Example: Downloading a file attachment from an unverified email that installs ransomware, locking your files and demanding payment.
- **Social Engineering**: Manipulating individuals to divulge confidential information. Example: A caller posing as IT support, convincing you to provide your password under the guise of troubleshooting.

##### Flowchart for Phishing Attack
The flowchart below outlines the steps of a phishing attack, enhancing understanding of the process.

##### Phishing Attack Flowchart

```plaintext
[Start]
   |
   v
[Attacker Crafts Fake Email] --> [Email Sent to Target]
   |                                 |
   v                                 v
[Target Receives Email] --> [Target Clicks Malicious Link]
   |                                 |
   v                                 v
[Target Enters Credentials] --> [Data Sent to Attacker]
   |                                 |
   v                                 v
[Account Compromised] --> [End]
```

- **Attacker Crafts Fake Email**: Creates a convincing message (e.g., urgent bank alert).
- **Email Sent to Target**: Delivered to inboxes, often in bulk.
- **Target Receives Email**: User sees the message.
- **Target Clicks Malicious Link**: Leads to a fake login page.
- **Target Enters Credentials**: Inputs sensitive data.
- **Data Sent to Attacker**: Credentials are captured.
- **Account Compromised**: Attacker gains access.


To protect against these, verify email senders, avoid suspicious downloads, and be cautious of unsolicited requests for information.

---


### Applying Risk Management Principles

The process of managing cybersecurity risks involves three key steps: **identifying**, **assessing**, and **mitigating**. This structured approach helps organizations protect their systems and data effectively.

- **Identifying Risks**: This step involves detecting potential threats and vulnerabilities. For example, monitoring network traffic might reveal unusual patterns indicating a malware presence.
- **Assessing Risks**: Evaluate the likelihood and impact of identified risks. A risk assessment might determine that malware could lead to data loss with a high probability due to unpatched systems.
- **Mitigating Risks**: Implement controls to reduce risk severity. This could include patching systems, deploying antivirus software, and training employees to recognize phishing.

##### Case Study: Mitigating a Malware Risk
A small business noticed slow network performance and frequent system crashes. Investigation identified a malware infection from a phishing email. The risk assessment rated it as "High" due to potential data theft and downtime. Mitigation involved isolating affected devices, updating antivirus definitions, patching vulnerabilities, and conducting staff training. Post-mitigation, the risk was reduced to "Low" with improved security measures.

##### Risk Level Comparison Table

| Risk Factor            | Before Mitigation | After Mitigation |
|-------------------------|-------------------|------------------|
| Likelihood of Attack    | High (80%)        | Low (20%)        |
| Impact on Operations    | High (Data Loss)  | Low (Minimal)    |
| Overall Risk Level      | High              | Low              |

---


### Mastering Basic Incident Response

A basic incident response (IR) process is essential for managing cybersecurity incidents like a malware outbreak. Below is a step-by-step guide using a hypothetical malware outbreak scenario, followed by a timeline diagram to illustrate the sequence of actions.

#### Step-by-Step Guide for Incident Response

- **Containment**:
  1. **Identify Affected Systems**: Detect infected devices (e.g., workstations showing unusual activity) using network monitoring tools like Wireshark.
  2. **Isolate Systems**: Disconnect affected systems from the network to prevent spread, such as unplugging a compromised PC.
  3. **Limit Damage**: Apply temporary patches or disable services (e.g., halt email servers) to minimize malware impact.

- **Eradication**:
  4. **Remove Malware**: Run antivirus scans (e.g., using Malwarebytes) to delete malicious files from infected systems.
  5. **Patch Vulnerabilities**: Update software (e.g., apply Windows updates) to close exploited weaknesses.
  6. **Verify Clean Systems**: Confirm eradication with a second scan and log review to ensure no remnants remain.

- **Recovery**:
  7. **Restore Systems**: Reconnect and restore data from clean backups (e.g., restore files from a pre-infection backup).
  8. **Test Operations**: Validate system functionality (e.g., test email and file access) to ensure normal operation.
  9. **Monitor and Report**: Continuously monitor for recurrence and document the incident (e.g., create a report for stakeholders) by 04:29 PM IST on Tuesday, September 23, 2025.

##### Hypothetical Malware Outbreak Scenario
A company detects a malware outbreak after employees report slow systems and encrypted files. The malware, likely ransomware, spread via a phishing email. The IR team follows the steps above, isolating 10 affected workstations, removing the malware with antivirus tools, patching unupdated software, and restoring data from backups taken last week.

---


##### Incident Response Timeline

```plaintext
[00:00] Start: Malware Detected
   |
   v
[00:15] Containment: Identify Affected Systems
   |
   v
[00:30] Containment: Isolate Systems
   |
   v
[01:00] Containment: Limit Damage
   |
   v
[02:00] Eradication: Remove Malware
   |
   v
[02:30] Eradication: Patch Vulnerabilities
   |
   v
[03:00] Eradication: Verify Clean Systems
   |
   v
[04:00] Recovery: Restore Systems
   |
   v
[04:30] Recovery: Test Operations
   |
   v
[05:00] Recovery: Monitor and Report
   |
   v
[05:30] End: Incident Resolved
```

- **00:00**: Malware detection triggers response.
- **00:15-01:00**: Containment actions isolate the threat.
- **02:00-03:00**: Eradication removes and secures systems.
- **04:00-05:00**: Recovery restores and monitors operations.

---

