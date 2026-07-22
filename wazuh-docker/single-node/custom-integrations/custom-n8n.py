#!/usr/bin/env python3
# custom-n8n.py
# Custom Wazuh integration script to send alerts to n8n Webhook

import sys
import json
import requests
import logging
from datetime import datetime

# Configure logging
logging.basicConfig(filename='/var/ossec/logs/integrations.log', level=logging.INFO, 
                    format='%(asctime)s %(levelname)s: %(message)s', datefmt='%Y-%m-%d %H:%M:%S')

# Read parameters when integration is run
# sys.argv[1] = alert_file
# sys.argv[2] = ignored (no api key for standard webhook)
# sys.argv[3] = hook_url
if len(sys.argv) >= 4:
    alert_file = sys.argv[1]
    hook_url = sys.argv[3]
else:
    logging.error("Missing arguments. Expected alert_file and hook_url.")
    sys.exit(1)

# Read the alert file
try:
    with open(alert_file) as f:
        alert_json = json.load(f)
except Exception as e:
    logging.error(f"Failed to read alert file: {e}")
    sys.exit(1)

# Format payload
payload = {
    "timestamp": datetime.utcnow().isoformat(),
    "alert_id": alert_json.get("id"),
    "rule_id": alert_json.get("rule", {}).get("id"),
    "rule_level": alert_json.get("rule", {}).get("level"),
    "description": alert_json.get("rule", {}).get("description"),
    "agent_name": alert_json.get("agent", {}).get("name", "N/A"),
    "agent_ip": alert_json.get("agent", {}).get("ip", "N/A"),
    "mitre_tactics": alert_json.get("rule", {}).get("mitre", {}).get("tactic", []),
    "full_log": alert_json.get("full_log", ""),
    "raw_alert": alert_json
}

headers = {
    'Content-Type': 'application/json',
    'User-Agent': 'Wazuh-n8n-Integration'
}

# Send the request to n8n webhook
try:
    response = requests.post(hook_url, json=payload, headers=headers, timeout=10)
    if response.status_code >= 200 and response.status_code < 300:
        logging.info(f"Successfully sent alert {payload['alert_id']} to n8n.")
    else:
        logging.error(f"Failed to send alert to n8n. HTTP {response.status_code}: {response.text}")
except Exception as e:
    logging.error(f"Error communicating with n8n webhook: {e}")
    sys.exit(1)
