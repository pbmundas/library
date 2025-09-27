import yaml
import requests
import os
from datetime import datetime
import time

API_KEY = os.getenv('GROK_API_KEY')
API_URL = 'https://api.x.ai/v1/chat/completions'
SELECTED_TACTIC = os.getenv('TACTIC_ID', '')

try:
    with open('techniques.yaml', 'r') as f:
        techniques = yaml.safe_load(f)
except FileNotFoundError:
    print("Error: techniques.yaml not found")
    exit(1)

if not techniques:
    print("Error: No tactics found in techniques.yaml")
    exit(1)

existing_files = os.listdir('_posts')
print(f"Existing files in _posts: {existing_files}")
tactic_ids = [tid for tid in techniques.keys() if not any(f'-{tid.lower()}.md' in f for f in existing_files)]

if SELECTED_TACTIC and SELECTED_TACTIC in techniques:
    tactic_ids = [SELECTED_TACTIC]
elif not tactic_ids:
    print(f"All tactics already processed. Available tactics: {list(techniques.keys())}")
    exit(0)

tactic_id = tactic_ids[0]
try:
    tactic_name = next(t for t in re.findall(r'## ([a-z\-]+)(?!\s*\()', open('hunting-master/TTPS.md').read(), re.MULTILINE) if f"TA{t[:4].upper()}" == tactic_id)
except StopIteration:
    print(f"Error: Tactic {tactic_id} not found in TTPS.md")
    exit(1)

tech_list = techniques[tactic_id]
print(f"Processing tactic: {tactic_name} ({tactic_id}) with {len(tech_list)} techniques")

prompt = f"""
You are a threat hunter professional. Generate up to 15 high-quality threat hunting hypotheses for each technique/sub-technique in the MITRE ATT&CK tactic '{tactic_name}' ({tactic_id}).
Techniques: {', '.join(f"{tech['name']} ({tech['id']})" for tech in tech_list)}.
Consider:
- Log sources available (e.g., network, endpoint, cloud logs).
- Environments (Windows, Linux, cloud, etc.).
- Telemetry depth and adversary behavior (e.g., APT29, Cobalt Strike).
- Risk profile (high-risk environments).
For each technique, output a Markdown section with the technique name and ID, followed by a table:
## Technique Name (Txxxx.xxx)
| Hypothesis | Description | Data Sources | Hunting Queries |
Include Splunk, KQL, and ELK queries for each hypothesis.
Output only the Markdown content, starting with sections for each technique.
"""

response = requests.post(API_URL, headers={'Authorization': f'Bearer {API_KEY}'}, json={
    'model': 'grok-beta',
    'messages': [{'role': 'user', 'content': prompt}],
    'max_tokens': 10000
})

if response.status_code == 200:
    content = response.json()['choices'][0]['message']['content']
    if not content.strip():
        print(f"Error: Empty response from Grok API for {tactic_name} ({tactic_id})")
        exit(1)

    date_str = datetime.now().strftime('%Y-%m-%d')
    tactic_filename = tactic_name.lower().replace(' ', '-').replace(':', '')
    filename = f"_posts/{date_str}-Threat-Hunting-Queries-for-mitre-tactic-{tactic_filename}.md"

    with open(filename, 'w') as f:
        f.write(f"# Threat Hunting Queries for MITRE ATT&CK Tactic: {tactic_name} ({tactic_id})\n\n")
        f.write(content)

    print(f"Generated {filename}")
else:
    print(f"API error for {tactic_name} ({tactic_id}): {response.status_code} - {response.text}")
    exit(1)

time.sleep(5)
