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

### Exploring the Threat Landscape

The threat landscape encompasses diverse actors with distinct motives and methods, posing significant cybersecurity challenges.

- **Cybercrime**: Driven by financial gain, cybercrime involves illegal activities like theft or extortion. Example: The 2021 Colonial Pipeline ransomware attack by DarkSide, where a $4.4 million ransom was paid after a crippling oil supply disruption.
- **Nation-State Actors**: Backed by governments, these actors target strategic assets for espionage or disruption. Example: The 2020 SolarWinds attack, attributed to Russia, compromised U.S. agencies by injecting malware into software updates.
- **Hacktivists**: Motivated by ideology, hacktivists disrupt systems to promote causes. Example: Anonymous’s 2016 DDoS attack on the Turkish government websites to protest censorship.

#### Infographic Description
The infographic illustrates the relationships between these threats and their targets:
- **Cybercrime** targets financial institutions and businesses (e.g., banks, retailers) with arrows pointing to money symbols.
- **Nation-State Actors** target government and critical infrastructure (e.g., defense, energy) with arrows to shield and power icons.
- **Hacktivists** target organizations or governments opposing their causes (e.g., media, political sites) with arrows to megaphone symbols.
- Central node labeled "Internet" connects all threats, showing their shared digital battleground.

#### Threat Landscape Infographic

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
