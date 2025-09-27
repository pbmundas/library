import yaml
import requests
import os
from datetime import datetime
import time

API_KEY = os.getenv('GROK_API_KEY')
API_URL = 'https://api.x.ai/v1/chat/completions'
SELECTED_TACTIC = os.getenv('TACTIC_ID', '')

# Load techniques
try:
    with open('techniques.yaml', 'r') as f:
        techniques = yaml.safe_load(f)
except FileNotFoundError:
    print("Error: techniques.yaml not found")
    exit(1)

# Get list of existing files to avoid reprocessing
existing_files = os.listdir('_posts')
tactic_ids = [tid for tid in techniques.keys() if not any(f'-{tid.lower()}.md' in f for f in existing_files)]

# Process one tactic (selected or first unprocessed)
if SELECTED_TACTIC and SELECTED_TACTIC in techniques:
    tactic_ids = [SELECTED_TACTIC]
elif not tactic_ids:
    print("All tactics already processed or no tactics found")
    exit(0)

tactic_id = tactic_ids[0]  # Process first unprocessed tactic
tactic_name = next(t for t, tid in re.findall(r'## ([\w\s]+) \((TA\d+)\)', open('hunting-master/TTPS.md').read()) if tid == tactic_id)
tech_list = techniques[tactic_id]

# Prompt for Grok
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
    'max_tokens': 8000
})

if response.status_code == 200:
    content = response.json()['choices'][0]['message']['content']

    # Generate filename
    date_str = datetime.now().strftime('%Y-%m-%d')
    tactic_filename = tactic_name.lower().replace(' ', '-').replace(':', '')
    filename = f"_posts/{date_str}-Threat-Hunting-Queries-for-mitre-tactic-{tactic_filename}.md"

    with open(filename, 'w') as f:
        f.write(f"# Threat Hunting Queries for MITRE ATT&CK Tactic: {tactic_name} ({tactic_id})\n\n")
        f.write(content)

    print(f"Generated {filename}")
else:
    print(f"API error for {tactic_name} ({tactic_id}): {response.status_code}")
    exit(1)

# Rate limiting
time.sleep(5)
