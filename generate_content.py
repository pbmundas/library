import yaml
import requests
import os
from datetime import datetime
import time

API_KEY = os.getenv('GROK_API_KEY')
API_URL = 'https://api.x.ai/v1/chat/completions'

# Load techniques
with open('techniques.yaml', 'r') as f:
    techniques = yaml.safe_load(f)

# Process each technique/sub-technique
for tactic_id, tech_list in techniques.items():
    for tech in tech_list:
        tech_name = tech['name']
        tech_id = tech['id']
        
        # Prompt for Grok
        prompt = f"""
        You are a threat hunter professional. Generate up to 15 high-quality threat hunting hypotheses for the MITRE ATT&CK technique/sub-technique '{tech_name}' ({tech_id}).
        Consider:
        - Log sources available (e.g., network, endpoint, cloud logs).
        - Environments (Windows, Linux, cloud, etc.).
        - Telemetry depth and adversary behavior (e.g., APT29, Cobalt Strike).
        - Risk profile (high-risk environments).
        Use the format: | Hypothesis | Description | Data Sources | Hunting Queries |
        Include Splunk, KQL, and ELK queries for each hypothesis.
        Output only the Markdown table.
        """

        response = requests.post(API_URL, headers={'Authorization': f'Bearer {API_KEY}'}, json={
            'model': 'grok-beta',
            'messages': [{'role': 'user', 'content': prompt}],
            'max_tokens': 4000
        })

        if response.status_code == 200:
            content = response.json()['choices'][0]['message']['content']

            # Generate filename
            date_str = datetime.now().strftime('%Y-%m-%d')
            filename = f"_posts/{date_str}-Threat-Hunting-Queries-for-mitre-technique-{tech_id}.md"

            with open(filename, 'w') as f:
                f.write(f"# Threat Hunting Queries for MITRE ATT&CK Technique: {tech_name} ({tech_id})\n\n")
                f.write(content)

            print(f"Generated {filename}")
        else:
            print(f"API error for {tech_name} ({tech_id}): {response.status_code}")

        # Rate limiting: Sleep to avoid hitting API limits (adjust based on xAI limits)
        time.sleep(2)
