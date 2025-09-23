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

#### Breach Scenarios
- **Confidentiality Breach**: A hacker exploits weak passwords to access a company's database, causing a data leak of customer credit card details, leading to identity theft and legal penalties.
- **Integrity Breach**: Malware alters transaction logs in a banking system, changing deposit amounts, resulting in financial discrepancies and loss of trust.
- **Availability Breach**: A DDoS attack overwhelms an online retailer's servers during Black Friday, blocking customer access and causing significant revenue loss.

#### CIA Triad Diagram

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
