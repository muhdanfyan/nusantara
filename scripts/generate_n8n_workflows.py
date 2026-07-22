import json
import os

def create_triage():
    return {
        "name": "1. Master Triage",
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "triage", "options": {}},
                "name": "Wazuh Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 1,
                "position": [250, 300],
                "webhookId": "tguard-webhook-triage"
            },
            {
                "parameters": {
                    "jsCode": "let ip = 'unknown';\nif (item.body && item.body.data && item.body.data.srcip) {\n  ip = item.body.data.srcip;\n}\nreturn { json: { alert_id: item.body.id || 'N/A', ip: ip, desc: item.body.rule?.description || 'N/A' } };"
                },
                "name": "Extract IOC",
                "type": "n8n-nodes-base.code",
                "typeVersion": 1,
                "position": [450, 300]
            },
            {
                "parameters": {
                    "requestMethod": "POST",
                    "url": "http://n8n:5678/webhook/enrichment",
                    "jsonParameters": True,
                    "options": {},
                    "bodyParametersUi": {
                        "parameter": [
                            {"name": "ip", "value": "={{$json.ip}}"},
                            {"name": "alert_id", "value": "={{$json.alert_id}}"}
                        ]
                    }
                },
                "name": "Trigger Enrichment",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [650, 150]
            },
            {
                "parameters": {
                    "requestMethod": "POST",
                    "url": "http://n8n:5678/webhook/iris-case",
                    "jsonParameters": True,
                    "options": {},
                    "bodyParametersUi": {
                        "parameter": [
                            {"name": "ip", "value": "={{$json.ip}}"},
                            {"name": "desc", "value": "={{$json.desc}}"}
                        ]
                    }
                },
                "name": "Trigger IRIS",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [650, 300]
            },
            {
                "parameters": {
                    "requestMethod": "POST",
                    "url": "http://n8n:5678/webhook/notify",
                    "jsonParameters": True,
                    "options": {},
                    "bodyParametersUi": {
                        "parameter": [
                            {"name": "message", "value": "New Wazuh Alert! IP: {{$json.ip}} - {{$json.desc}}"}
                        ]
                    }
                },
                "name": "Trigger Notification",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [650, 450]
            }
        ],
        "connections": {
            "Wazuh Webhook": {
                "main": [
                    [{"node": "Extract IOC", "type": "main", "index": 0}]
                ]
            },
            "Extract IOC": {
                "main": [
                    [
                        {"node": "Trigger Enrichment", "type": "main", "index": 0},
                        {"node": "Trigger IRIS", "type": "main", "index": 0},
                        {"node": "Trigger Notification", "type": "main", "index": 0}
                    ]
                ]
            }
        }
    }

def create_enrichment():
    return {
        "name": "2. IP Enrichment (Anti-Dupe)",
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "enrichment", "options": {}},
                "name": "Enrichment Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 1,
                "position": [250, 300],
                "webhookId": "tguard-webhook-enrichment"
            },
            {
                "parameters": {
                    "jsCode": "const ip = item.body.ip || 'unknown';\n// Simulate Cache Anti-Duplikat Check\nlet is_scanned = false;\n// Di n8n produksi, ini bisa query Redis atau static data\nreturn { json: { ip: ip, should_enrich: !is_scanned } };"
                },
                "name": "Check Duplicate IP",
                "type": "n8n-nodes-base.code",
                "typeVersion": 1,
                "position": [450, 300]
            },
            {
                "parameters": {
                    "conditions": {
                        "boolean": [{"value1": "={{$json.should_enrich}}", "value2": True}]
                    }
                },
                "name": "IF Not Scanned",
                "type": "n8n-nodes-base.if",
                "typeVersion": 2,
                "position": [650, 300]
            },
            {
                "parameters": {
                    "url": "=https://api.abuseipdb.com/api/v2/check",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendQuery": True,
                    "queryParameters": {
                        "parameters": [
                            {"name": "ipAddress", "value": "={{$json.ip}}"},
                            {"name": "maxAgeInDays", "value": "90"}
                        ]
                    }
                },
                "name": "AbuseIPDB",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [850, 200]
            },
            {
                "parameters": {
                    "url": "=https://www.virustotal.com/api/v3/ip_addresses/{{$json.ip}}",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth"
                },
                "name": "VirusTotal",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [850, 400]
            }
        ],
        "connections": {
            "Enrichment Webhook": {
                "main": [
                    [{"node": "Check Duplicate IP", "type": "main", "index": 0}]
                ]
            },
            "Check Duplicate IP": {
                "main": [
                    [{"node": "IF Not Scanned", "type": "main", "index": 0}]
                ]
            },
            "IF Not Scanned": {
                "main": [
                    [
                        {"node": "AbuseIPDB", "type": "main", "index": 0},
                        {"node": "VirusTotal", "type": "main", "index": 0}
                    ]
                ]
            }
        }
    }

def create_iris():
    return {
        "name": "3. IRIS Anti-Dupe",
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "iris-case", "options": {}},
                "name": "IRIS Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 1,
                "position": [250, 300],
                "webhookId": "tguard-webhook-iris"
            },
            {
                "parameters": {
                    "url": "https://iris:8443/api/cases/search",
                    "authentication": "genericCredentialType",
                    "genericAuthType": "httpHeaderAuth",
                    "sendQuery": True,
                    "queryParameters": {
                        "parameters": [
                            {"name": "title", "value": "={{$json.body.ip}}"}
                        ]
                    },
                    "options": {"allowUnauthorizedCerts": True}
                },
                "name": "Search IRIS Case",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [450, 300]
            },
            {
                "parameters": {
                    "conditions": {
                        "number": [{"value1": "={{$json.count}}", "operation": "larger", "value2": 0}]
                    }
                },
                "name": "Case Exists?",
                "type": "n8n-nodes-base.if",
                "typeVersion": 2,
                "position": [650, 300]
            },
            {
                "parameters": {
                    "requestMethod": "POST",
                    "url": "https://iris:8443/api/cases/{{$json.cases[0].case_id}}/notes",
                    "options": {"allowUnauthorizedCerts": True},
                    "jsonParameters": True,
                    "bodyParametersUi": {
                        "parameter": [{"name": "note_content", "value": "Repeated attack from {{$node[\"IRIS Webhook\"].json[\"body\"][\"ip\"]}}"}]
                    }
                },
                "name": "Add Note",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [850, 200]
            },
            {
                "parameters": {
                    "requestMethod": "POST",
                    "url": "https://iris:8443/api/cases",
                    "options": {"allowUnauthorizedCerts": True},
                    "jsonParameters": True,
                    "bodyParametersUi": {
                        "parameter": [
                            {"name": "title", "value": "Incident from {{$node[\"IRIS Webhook\"].json[\"body\"][\"ip\"]}}"},
                            {"name": "description", "value": "={{$node[\"IRIS Webhook\"].json[\"body\"][\"desc\"]}}"}
                        ]
                    }
                },
                "name": "Create Case",
                "type": "n8n-nodes-base.httpRequest",
                "typeVersion": 4,
                "position": [850, 400]
            }
        ],
        "connections": {
            "IRIS Webhook": {
                "main": [
                    [{"node": "Search IRIS Case", "type": "main", "index": 0}]
                ]
            },
            "Search IRIS Case": {
                "main": [
                    [{"node": "Case Exists?", "type": "main", "index": 0}]
                ]
            },
            "Case Exists?": {
                "main": [
                    [{"node": "Add Note", "type": "main", "index": 0}],
                    [{"node": "Create Case", "type": "main", "index": 0}]
                ]
            }
        }
    }

def create_notify():
    return {
        "name": "4. Notification Dispatcher",
        "nodes": [
            {
                "parameters": {"httpMethod": "POST", "path": "notify", "options": {}},
                "name": "Notify Webhook",
                "type": "n8n-nodes-base.webhook",
                "typeVersion": 1,
                "position": [250, 300],
                "webhookId": "tguard-webhook-notify"
            },
            {
                "parameters": {
                    "chatId": "YOUR_CHAT_ID",
                    "text": "={{$json.body.message}}"
                },
                "name": "Telegram",
                "type": "n8n-nodes-base.telegram",
                "typeVersion": 1,
                "position": [450, 200]
            }
        ],
        "connections": {
            "Notify Webhook": {
                "main": [
                    [{"node": "Telegram", "type": "main", "index": 0}]
                ]
            }
        }
    }

def main():
    workflows = {
        "1_master_triage.json": create_triage(),
        "2_iris_antiduplicate.json": create_enrichment(),
        "3_malware_response.json": create_iris(),
        "4_notification_dispatcher.json": create_notify()
    }
    
    out_dir = "/home/baru/tguard/n8n/workflows"
    os.makedirs(out_dir, exist_ok=True)
    
    for filename, data in workflows.items():
        filepath = os.path.join(out_dir, filename)
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=2)
            
    print("Workflows generated successfully!")

if __name__ == "__main__":
    main()
