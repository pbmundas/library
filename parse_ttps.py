
import re
import yaml

# Read TTPS.md
try:
    with open('hunting-master/TTPS.md', 'r') as f:
        content = f.read()
except FileNotFoundError:
    print("Error: TTPS.md not found in hunting-master")
    exit(1)

# Extract tactics (e.g., ## Command and Control (TA0011))
tactics = re.findall(r'## ([\w\s]+) \((TA\d+)\)', content)

# Extract techniques/sub-techniques
techniques = {}
for tactic_name, tactic_id in tactics:
    pattern = rf'## {re.escape(tactic_name)} \({tactic_id}\).*?(?=## |$)(.*?)(?=(## |\Z))'
    tactic_content = re.search(pattern, content, re.DOTALL)
    if tactic_content:
        tech_list = re.findall(r'### ([\w\s:]+) \((T\d+(?:\.\d+)?)\)', tactic_content.group(1))
        techniques[tactic_id] = [{'name': tech_name.strip(), 'id': tech_id} for tech_name, tech_id in tech_list]

# Save to YAML
with open('techniques.yaml', 'w') as f:
    yaml.dump(techniques, f)

print("Parsed techniques to techniques.yaml")

