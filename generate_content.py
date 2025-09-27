import yaml
import requests
import os
from datetime import datetime
import time

API_KEY = os.getenv('GROK_API_KEY')
API_URL = 'https://api.x.ai/v1/chat/completions'
SELECTED_TACTIC = os.getenv('TACTIC_ID', '')  # Optional manual tactic ID

# Load techniques
with open('techniques.yaml', 'r') as f:
    techniques = yaml.safe_load(f)

# Process one tactic (either selected or first unprocessed)
tactic_ids = list(techniques.keys())
if SELECTED_TACTIC:
    tactic_ids = [SELECTED_TACTIC] if SELECTED_TACTIC in tactic_ids else []

for tactic_id in tactic_ids[:1]:  # Process one tactic per run
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
        'max_tokens': 8000  # Increased for multiple techniques
    })

    if response.status_code == 200:
        content = response.json()['choices'][0]['message']['content']

        # Generate filename
        date_str = datetime.now().strftime('%Y-%m-%d')
        tactic_filename = tactic_name.lower().replace(' ', '-')
        filename = f"_posts/{date_str}-Threat-Hunting-Queries-for-mitre-tactic-{tactic_filename}.md"

        with open(filename, 'w') as f:
            f.write(f"# Threat Hunting Queries for MITRE ATT&CK Tactic: {tactic_name} ({tactic_id})\n\n")
            f.write(content)

        print(f"Generated {filename}")
    else:
        print(f"API error for {tactic_name} ({tactic_id}): {response.status_code}")

    # Rate limiting: Sleep to avoid hitting API limits
    time.sleep(5)
