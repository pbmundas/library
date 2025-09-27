import re
import yaml

# Predefined mapping of technique names to IDs
TECHNIQUE_ID_MAP = {
    "ARP Cache Poisoning": "T1557.002",
    "Adversary-in-the-Middle": "T1557",
    "Archive Collected Data": "T1560",
    "Archive via Custom Method": "T1560.003",
    "Archive via Library": "T1560.002",
    "Archive via Utility": "T1560.001",
    "Audio Capture": "T1123",
    "Automated Collection": "T1119",
    "Browser Session Hijacking": "T1185",
    "Clipboard Data": "T1115",
    "Code Repositories": "T1213.003",
    "Confluence": "T1213.001",
    "Credential API Hooking": "T1056.004",
    "Customer Relationship Management Software": "T1213",
    "DHCP Spoofing": "T1557.003",
    "Data Staged": "T1074",
    "Data from Cloud Storage": "T1530",
    "Data from Configuration Repository": "T1602",
    "Data from Information Repositories": "T1213",
    "Data from Local System": "T1005",
    "Data from Network Shared Drive": "T1039",
    "Data from Removable Media": "T1025",
    "Email Collection": "T1114",
    "Email Forwarding Rule": "T1114.003",
    "Evil Twin": "T1557.004",
    "GUI Input Capture": "T1056.002",
}

try:
    with open('hunting-master/TTPS.md', 'r') as f:
        content = f.read()
except FileNotFoundError:
    print("Error: TTPS.md not found in hunting-master")
    exit(1)

# Extract tactics
tactics = re.findall(r'## ([a-z\-]+)(?!\s*\()', content)
if not tactics:
    print("Error: No tactics found in TTPS.md")
    exit(1)

# Map tactic names to MITRE ATT&CK IDs
TACTIC_ID_MAP = {
    "reconnaissance": "TA0001",
    "resource-development": "TA0002",
    "initial-access": "TA0003",
    "execution": "TA0004",
    "persistence": "TA0005",
    "privilege-escalation": "TA0006",
    "defense-evasion": "TA0007",
    "credential-access": "TA0008",
    "collection": "TA0009",
    "command-and-control": "TA0011",
    "exfiltration": "TA0010",
    "impact": "TA0040",
    "discovery": "TA0007",
    "lateral-movement": "TA0008"
}

techniques = {}
for tactic_name in tactics:
    tactic_id = TACTIC_ID_MAP.get(tactic_name, f"TA{tactic_name[:4].upper()}")
    pattern = rf'## {re.escape(tactic_name)}.*?$(.*?)(?=(## |\Z))'
    tactic_content = re.search(pattern, content, re.DOTALL | re.MULTILINE)
    if tactic_content:
        tech_list = re.findall(r'###\s+—\s+([\w\s:]+?)(?=\n|$)', tactic_content.group(1), re.DOTALL)
        techniques[tactic_id] = [
            {'name': tech_name.strip(), 'id': TECHNIQUE_ID_MAP.get(tech_name.strip(), 'T0000')} 
            for tech_name in tech_list if tech_name.strip()
        ]
    else:
        print(f"Warning: No techniques found for tactic {tactic_name} ({tactic_id})")

if not techniques:
    print("Error: No techniques parsed from TTPS.md")
    exit(1)

with open('techniques.yaml', 'w') as f:
    yaml.dump(techniques, f)

print(f"Parsed {len(tactics)} tactics with {sum(len(techs) for techs in techniques.values())} techniques to techniques.yaml")
