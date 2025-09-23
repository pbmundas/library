---
layout: default
title: Documenting Hunt
category: Threat Hunting  # This becomes a main topic in sidebar
---

Threat-Hunting-Activity-Documentation-Template.md
### Threat Hunting Activity Documentation Template

This document provides a comprehensive, industry-standard format for documenting threat hunting activities, synthesized from established frameworks and best practices such as the TaHiTI methodology, PEAK framework, MITRE ATT&CK-aligned playbooks, and practical reporting structures used by cybersecurity professionals. It ensures end-to-end coverage, from planning and execution to reporting and refinement, to promote repeatability, compliance, legal defensibility, and continuous improvement. Threat hunters should use this as a living document (e.g., in tools like Markdown, Word, or Notion) during and after each hunt, logging activities in real-time to capture successes, failures, and artifacts.
The document is divided into seven core sections, with subsections for detail.

---

#### **Administrative Information**
Capture metadata for tracking, auditing, and handoffs. This ensures traceability and context.

| Field                  | Description/Example |
|------------------------|---------------------|
| **Hunt ID**           | Unique identifier (e.g., TH-2025-09-001). |
| **Hunt Title**        | Brief descriptive name (e.g., "Hypothesis-Driven Hunt for Cobalt Strike Beacon Activity"). |
| **Hunter/Author**     | Name(s) and role(s) (e.g., "Jane Doe, Senior Threat Hunter"). |
| **Date Initiated**    | Start date/time (e.g., "2025-09-23 09:00 UTC"). |
| **Date Completed**    | End date/time (e.g., "2025-09-24 16:00 UTC"). |
| **Version**           | Document version (e.g., "1.0"). |
| **Classification**    | Sensitivity level (e.g., "Internal Use Only"). |
| **Related Incidents** | Linked ticket IDs or IR numbers (e.g., "IR-2025-045"). |

---

#### **Planning and Hypothesis Development**
Document the rationale and scope to justify the hunt and enable repeatability. Base hypotheses on threat intelligence, anomalies, or TTPs from frameworks like MITRE ATT&CK.

- **Hunt Type**: Structured (hypothesis-driven), Unstructured (anomaly-based), or Query-Based.
- **Objective**: High-level goal (e.g., "Detect lateral movement TTPs in high-value assets").
- **Hypothesis**: Specific, testable statement (e.g., "Adversaries are using PsExec for lateral movement on Windows endpoints, based on recent TI feed").
- **Scope**:
  - Assets Targeted: Systems, users, networks (e.g., "Domain controllers and finance servers").
  - Timeframe: Data window (e.g., "Last 30 days").
  - Data Sources: Logs/endpoints (e.g., "SIEM, EDR, network traffic via Zeek").
- **Threat Intelligence References**: Sources used (e.g., "MITRE ATT&CK T1021.002; AlienVault OTX IOCs").
- **Risk Assessment**: Potential impacts (e.g., "Low disruption; read-only queries").

---

#### **Execution and Activity Log**
Log all actions chronologically for transparency, evidence, and lessons learned. Include timestamps, tools, and outcomes to support legal or forensic needs. Use the table below for detailed logging.

| Timestamp (UTC) | Action/Step | Tools/Technologies Used | Data Collected/Analyzed | Results/Observations | Notes/Ideas/Conclusions |
|-----------------|-------------|-------------------------|-------------------------|----------------------|-------------------------|
| 2025-09-23 09:15 | Query EDR for PsExec executions | Splunk, MITRE ATT&CK Navigator | Endpoint logs from 500 hosts | 3 suspicious events on DC-01 | Hypothesis partially supported; pivot to network logs. Screenshot attached. |
| 2025-09-23 10:30 | Analyze network traffic | Zeek, Wireshark | PCAP files from firewall | Anomalous SMB traffic to external IP | Failure: No direct IOC match; refine query for beaconing. |
| ...             | ...        | ...                    | ...                    | ...                 | ...                    |

- **Total Duration**: Estimated vs. actual time spent.
- **Interruptions/Handoffs**: Any pauses or team changes (e.g., "Shift handoff at 18:00").

---

#### **Investigation and Findings**
Detail analysis, pivots, and evidence. Focus on IoCs, TTPs, and patterns to refute/confirm the hypothesis.

- **Key Findings Summary**: TL;DR overview (e.g., "Confirmed Cobalt Strike use on 5 endpoints; no active C2").
- **Indicators of Compromise (IoCs)**:
  | IoC Type | Value | Context | Severity |
  |----------|-------|---------|----------|
  | Hash    | SHA256: abc123... | Malicious DLL on endpoint | High    |
  | IP      | 192.0.2.1        | C2 server in traffic logs | Medium  |
  | ...     | ...              | ...                | ...     |
- **TTP Mapping**: Link to MITRE ATT&CK (e.g., "TA0008: Lateral Movement via T1021.002").
- **Anomalies/Patterns**: Behavioral insights (e.g., "Unusual process spawning at 02:00 UTC").
- **Pivots Performed**: How investigation evolved (e.g., "From endpoint logs to external DNS queries").
- **Hypothesis Outcome**: Confirmed, Refuted, or Uncertain (with rationale).

- **Artifacts**: List files/screenshots (e.g., "EDR_export.csv; Wireshark.pcap" – store in secure repo).

---

#### **Threat Containment and Response**
Outline immediate actions taken, even if no threat is confirmed, to limit damage.

- **Actions Taken**: (e.g., "Isolated affected endpoints; blocked IP in firewall").
- **Escalations**: Teams notified (e.g., "IR team via ticket IR-2025-046").
- **Remediation Status**: Open/Closed (e.g., "Patch deployed; monitoring for 48 hours").

---

#### **Reporting and Communication**
Summarize for stakeholders, ensuring shareable insights.

- **Executive Summary**: 1-paragraph overview for management (e.g., "Hunt identified 3 compromised assets; containment complete").
- **Technical Details**: Deeper dive for SOC/IR teams (reference Sections 3-5).
- **Distribution List**: Recipients (e.g., "CISO, SOC Manager").
- **Follow-Up Actions**:
  | Action Item | Owner | Due Date | Status |
  |-------------|-------|----------|--------|
  | Update detection rules for T1021 | SOC Analyst | 2025-10-01 | Open  |
  | ...        | ...   | ...     | ...   |

---

#### **Recommendations and Lessons Learned**
Drive improvement by reflecting on the hunt.

- **Recommendations**: Process/tech improvements (e.g., "Integrate ML for anomaly detection").
- **Lessons Learned**:
  - Successes: What accelerated the hunt?
  - Failures: Dead ends and why (e.g., "Incomplete logs led to false negative").
  - Metrics: Hunts completed, threats found, time to detect.
- **Next Steps**: Future hunts (e.g., "Refine hypothesis for unstructured anomalies").

---

#### **Appendices**
- **A: Full Logs/Queries**: Paste raw queries/scripts.
- **B: Visuals**: Screenshots, timelines, graphs (e.g., attack path diagram).
- **C: References**: All sources cited (e.g., TI feeds, tools docs).

This document aligns with proactive, hypothesis-driven hunting while supporting unstructured exploration. Customize fields as needed for your environment, but maintain completeness to avoid gaps in information. For automation, integrate with tools like Splunk or SIEM for log ingestion. Review and archive post-hunt for training and audits.
