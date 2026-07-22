import json
import os

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)

def create_workflow(name, nodes, connections):
    return {
        "name": name,
        "nodes": nodes,
        "connections": connections,
        "active": False,
        "settings": {"saveExecutionProgress": True, "saveManualExecutions": True, "timezone": "Asia/Jakarta"}
    }

webhook_node = {
    "parameters": {"httpMethod": "POST", "path": "wazuh-alert", "options": {}},
    "name": "Wazuh Webhook",
    "type": "n8n-nodes-base.webhook",
    "typeVersion": 1,
    "position": [250, 300],
    "webhookId": "wazuh-soc-webhook"
}

misp_node = {
    "parameters": {"resource": "event", "operation": "search", "searchBy": "attribute", "attributeType": "ip-src,ip-dst", "attributeValue": "={{$json['body']['data']['srcip']}}"},
    "name": "MISP Enrich",
    "type": "n8n-nodes-base.misp",
    "typeVersion": 1,
    "position": [500, 300]
}

vt_node = {
    "parameters": {"resource": "ip", "operation": "report", "ip": "={{$json['body']['data']['srcip']}}"},
    "name": "VirusTotal",
    "type": "n8n-nodes-base.virustotal",
    "typeVersion": 1,
    "position": [700, 300]
}

iris_search_node = {
    "parameters": {
        "requestMethod": "GET",
        "url": "={{$env['IRIS_BASE_URL']}}/api/cases",
        "options": {},
        "queryParametersUi": {
            "parameter": [
                {"name": "cid", "value": "={{$json['body']['data']['id']}}"}
            ]
        },
        "headerParametersUi": {
            "parameter": [
                {"name": "Authorization", "value": "Bearer {{$env['IRIS_API_KEY']}}"}
            ]
        }
    },
    "name": "IRIS Check Duplicate",
    "type": "n8n-nodes-base.httpRequest",
    "typeVersion": 2,
    "position": [500, 500]
}

if_duplicate_node = {
    "parameters": {
        "conditions": {
            "boolean": [{"value1": "={{$json['data'] && $json['data'].length > 0}}", "value2": True}]
        }
    },
    "name": "Is Duplicate?",
    "type": "n8n-nodes-base.if",
    "typeVersion": 1,
    "position": [700, 500]
}

iris_create_node = {
    "parameters": {
        "requestMethod": "POST",
        "url": "={{$env['IRIS_BASE_URL']}}/api/cases/add",
        "options": {},
        "bodyParametersUi": {
            "parameter": [
                {"name": "case_name", "value": "=Wazuh Alert: {{$json['body']['rule']['description']}}"},
                {"name": "case_description", "value": "=Alert ID: {{$json['body']['id']}}\nSeverity: {{$json['body']['rule']['level']}}\nIP: {{$json['body']['data']['srcip']}}"}
            ]
        },
        "headerParametersUi": {
            "parameter": [
                {"name": "Authorization", "value": "Bearer {{$env['IRIS_API_KEY']}}"}
            ]
        }
    },
    "name": "IRIS Create Case",
    "type": "n8n-nodes-base.httpRequest",
    "typeVersion": 2,
    "position": [900, 550]
}

iris_add_note_node = {
    "parameters": {
        "requestMethod": "POST",
        "url": "={{$env['IRIS_BASE_URL']}}/api/cases/notes/add",
        "options": {},
        "bodyParametersUi": {
            "parameter": [
                {"name": "note_title", "value": "Enrichment Data"},
                {"name": "note_content", "value": "=MISP Data: {{$node[\"MISP Enrich\"].json[\"Event\"]}}\nVT Data: {{$node[\"VirusTotal\"].json[\"data\"]}}"}
            ]
        },
        "headerParametersUi": {
            "parameter": [
                {"name": "Authorization", "value": "Bearer {{$env['IRIS_API_KEY']}}"}
            ]
        }
    },
    "name": "IRIS Add Note",
    "type": "n8n-nodes-base.httpRequest",
    "typeVersion": 2,
    "position": [1100, 550]
}

wazuh_action_node = {
    "parameters": {
        "requestMethod": "PUT",
        "url": "={{$env['WAZUH_URL']}}/active-response",
        "options": {},
        "bodyParametersUi": {
            "parameter": [
                {"name": "command", "value": "firewall-drop"},
                {"name": "arguments", "value": "={{$json['body']['data']['srcip']}}"}
            ]
        }
    },
    "name": "Wazuh AR Isolate",
    "type": "n8n-nodes-base.httpRequest",
    "typeVersion": 2,
    "position": [1100, 300]
}

telegram_node = {
    "parameters": {"chatId": "YOUR_CHAT_ID", "text": "=High Severity Alert: {{$json['body']['rule']['description']}}"},
    "name": "Telegram Notification",
    "type": "n8n-nodes-base.telegram",
    "typeVersion": 1,
    "position": [900, 700]
}


# Workflow 1
wf1 = create_workflow(
    "1. Anti Duplicate Case Creation",
    [webhook_node, iris_search_node, if_duplicate_node, iris_create_node],
    {
        "Wazuh Webhook": {"main": [[{"node": "IRIS Check Duplicate", "type": "main", "index": 0}]]},
        "IRIS Check Duplicate": {"main": [[{"node": "Is Duplicate?", "type": "main", "index": 0}]]},
        "Is Duplicate?": {"main": [[], [{"node": "IRIS Create Case", "type": "main", "index": 0}]]}
    }
)

# Workflow 2
wf2 = create_workflow(
    "2. IP Reputation Enrichment",
    [webhook_node, misp_node, vt_node, iris_add_note_node],
    {
        "Wazuh Webhook": {"main": [[{"node": "MISP Enrich", "type": "main", "index": 0}]]},
        "MISP Enrich": {"main": [[{"node": "VirusTotal", "type": "main", "index": 0}]]},
        "VirusTotal": {"main": [[{"node": "IRIS Add Note", "type": "main", "index": 0}]]}
    }
)

# Workflow 3
wf3 = create_workflow(
    "3. Malware Analysis & Response",
    [
        webhook_node,
        {**misp_node, "parameters": {"resource": "event", "operation": "search", "searchBy": "attribute", "attributeType": "md5,sha1,sha256", "attributeValue": "={{$json['body']['data']['hashes']}}"}},
        {**vt_node, "parameters": {"resource": "file", "operation": "report", "hash": "={{$json['body']['data']['hashes']}}"}},
        iris_create_node,
        telegram_node
    ],
    {
        "Wazuh Webhook": {"main": [[{"node": "MISP Enrich", "type": "main", "index": 0}]]},
        "MISP Enrich": {"main": [[{"node": "VirusTotal", "type": "main", "index": 0}]]},
        "VirusTotal": {"main": [[{"node": "IRIS Create Case", "type": "main", "index": 0}]]},
        "IRIS Create Case": {"main": [[{"node": "Telegram Notification", "type": "main", "index": 0}]]}
    }
)

# Workflow 4
wf4 = create_workflow(
    "4. High Severity Auto Containment",
    [
        webhook_node,
        {
            "parameters": {"conditions": {"number": [{"value1": "={{$json['body']['rule']['level']}}", "operation": "largerEqual", "value2": 10}]}},
            "name": "Is High Severity?",
            "type": "n8n-nodes-base.if",
            "typeVersion": 1,
            "position": [500, 300]
        },
        iris_create_node,
        wazuh_action_node,
        telegram_node
    ],
    {
        "Wazuh Webhook": {"main": [[{"node": "Is High Severity?", "type": "main", "index": 0}]]},
        "Is High Severity?": {"main": [[{"node": "IRIS Create Case", "type": "main", "index": 0}, {"node": "Wazuh AR Isolate", "type": "main", "index": 0}, {"node": "Telegram Notification", "type": "main", "index": 0}], []]}
    }
)

# Workflow 5
wf5 = create_workflow(
    "5. Full SOC Pipeline (T-Guard)",
    [webhook_node, iris_search_node, if_duplicate_node, misp_node, vt_node, iris_create_node, iris_add_note_node, telegram_node],
    {
        "Wazuh Webhook": {"main": [[{"node": "IRIS Check Duplicate", "type": "main", "index": 0}]]},
        "IRIS Check Duplicate": {"main": [[{"node": "Is Duplicate?", "type": "main", "index": 0}]]},
        "Is Duplicate?": {"main": [[], [{"node": "MISP Enrich", "type": "main", "index": 0}]]},
        "MISP Enrich": {"main": [[{"node": "VirusTotal", "type": "main", "index": 0}]]},
        "VirusTotal": {"main": [[{"node": "IRIS Create Case", "type": "main", "index": 0}]]},
        "IRIS Create Case": {"main": [[{"node": "IRIS Add Note", "type": "main", "index": 0}, {"node": "Telegram Notification", "type": "main", "index": 0}]]}
    }
)

workflows = {
    "1_anti_duplicate.json": wf1,
    "2_ip_enrichment.json": wf2,
    "3_malware_analysis.json": wf3,
    "4_auto_containment.json": wf4,
    "5_full_soc_pipeline.json": wf5
}

for filename, data in workflows.items():
    with open(os.path.join(TEMPLATES_DIR, filename), "w") as f:
        json.dump(data, f, indent=2)

print("Templates generated successfully.")
