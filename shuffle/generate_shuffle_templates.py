import json
import os
import uuid
import sys

TEMPLATES_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "shuffle", "templates")
os.makedirs(TEMPLATES_DIR, exist_ok=True)

# === READ CREDENTIALS FROM ENVIRONMENT, .tguard.env, OR .env ===
def _read_env_file(path):
    values = {}
    if not os.path.exists(path):
        return values
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if "=" not in line:
                continue
            key, value = line.split("=", 1)
            values[key.strip()] = value.strip().strip('"').strip("'")
    return values

def read_env(key, default="", aliases=None):
    aliases = aliases or []
    for candidate in [key, *aliases]:
        val = os.environ.get(candidate, "")
        if val:
            return val

    root_dir = os.path.dirname(os.path.abspath(__file__))
    for env_name in [".tguard.env", ".env"]:
        values = _read_env_file(os.path.join(root_dir, env_name))
        for candidate in [key, *aliases]:
            if values.get(candidate):
                return values[candidate]
    return default

IP_ADDRESS     = read_env("SAVED_IP_ADDRESS", "127.0.0.1")
IRIS_API_KEY   = read_env("IRIS_API_KEY", "IRIS_API_KEY_PLACEHOLDER")
MISP_API_KEY   = read_env("MISP_API_KEY", "MISP_API_KEY_PLACEHOLDER")
VT_API_KEY     = read_env("VT_API_KEY", "VT_API_KEY_PLACEHOLDER", aliases=["TGUARD_VT_API_KEY"])
SOAR_WEBHOOK   = read_env("SOAR_WEBHOOK_UUID", str(uuid.uuid4()))
WAZUH_PASS     = read_env("WAZUH_ADMIN_PASSWORD", "SecretPassword")

IRIS_URL  = f"https://{IP_ADDRESS}:8443"
MISP_URL  = f"https://{IP_ADDRESS}:1443"
WAZUH_URL = f"https://{IP_ADDRESS}:55000"
WEBHOOK_URL = f"http://{IP_ADDRESS}:3001/api/v1/hooks/{SOAR_WEBHOOK}"

def gid():
    return str(uuid.uuid4())

def webhook_trigger():
    return {
        "id": SOAR_WEBHOOK,
        "name": "Wazuh Webhook",
        "description": "Triggered by Wazuh alerts via ossec.conf integration",
        "app_name": "Webhook",
        "app_version": "1.0.0",
        "type": "trigger",
        "status": "running",
        "position": {"x": 100, "y": 200},
        "parameters": [
            {"name": "webhook_url", "value": WEBHOOK_URL}
        ]
    }

def iris_action(name, action_type, description="", x=0, y=200):
    """Create a fully configured IRIS action node"""
    action_map = {
        "check_duplicate": {
            "app_action": "get_case_by_name",
            "params": [
                {"name": "case_name", "value": "$exec.body.rule.description"},
            ]
        },
        "create_case": {
            "app_action": "create_case",
            "params": [
                {"name": "case_name",        "value": "$exec.body.rule.description"},
                {"name": "case_description", "value": "Agent: $exec.body.agent.name | Level: $exec.body.rule.level | Rule: $exec.body.rule.id"},
                {"name": "case_soc_id",      "value": "T-GUARD-$exec.body.rule.id"},
                {"name": "case_severity",    "value": "2"},
                {"name": "case_customer",    "value": "1"},
            ]
        },
        "add_notes": {
            "app_action": "create_note",
            "params": [
                {"name": "case_id",    "value": "$Create Case.case_id"},
                {"name": "note_title", "value": "MISP + VT Enrichment"},
                {"name": "note_content", "value": "MISP Result: $MISP Enrich.data | VT Result: $VT Enrich.data"},
                {"name": "group_title", "value": "T-Guard Auto Notes"},
            ]
        },
        "create_alert": {
            "app_action": "create_alert",
            "params": [
                {"name": "alert_title",    "value": "$exec.body.rule.description"},
                {"name": "alert_severity", "value": "2"},
                {"name": "alert_source",   "value": "Wazuh"},
                {"name": "alert_status",   "value": "1"},
                {"name": "alert_customer", "value": "1"}
            ]
        }
    }
    cfg = action_map.get(action_type, {"app_action": "get_cases", "params": []})
    return {
        "id": gid(),
        "name": name,
        "description": description,
        "app_name": "IRIS",
        "app_version": "1.0.0",
        "app_action": cfg["app_action"],
        "type": "action",
        "position": {"x": x, "y": y},
        "authentication": {
            "url":     IRIS_URL,
            "api_key": IRIS_API_KEY,
            "verify_ssl": False
        },
        "parameters": cfg["params"]
    }

def misp_action(name, x=0, y=200):
    return {
        "id": gid(),
        "name": name,
        "description": "Search threat intel in MISP",
        "app_name": "MISP",
        "app_version": "1.0.0",
        "app_action": "search_attributes",
        "type": "action",
        "position": {"x": x, "y": y},
        "authentication": {
            "url":     MISP_URL,
            "api_key": MISP_API_KEY,
            "verify_ssl": False
        },
        "parameters": [
            {"name": "value", "value": "$exec.body.data.srcip"},
            {"name": "type",  "value": "ip-src"}
        ]
    }

def vt_action(name, x=0, y=200):
    return {
        "id": gid(),
        "name": name,
        "description": "Analyze IP or hash with VirusTotal",
        "app_name": "VirusTotal",
        "app_version": "1.0.0",
        "app_action": "get_ip_report",
        "type": "action",
        "position": {"x": x, "y": y},
        "authentication": {
            "api_key": VT_API_KEY
        },
        "parameters": [
            {"name": "ip", "value": "$exec.body.data.srcip"}
        ]
    }

def wazuh_action(name, x=0, y=200):
    return {
        "id": gid(),
        "name": name,
        "description": "Trigger Wazuh Active Response",
        "app_name": "Wazuh",
        "app_version": "1.0.0",
        "app_action": "run_active_response",
        "type": "action",
        "position": {"x": x, "y": y},
        "authentication": {
            "url": WAZUH_URL,
            "username": "admin",
            "password": WAZUH_PASS,
            "verify_ssl": False
        },
        "parameters": [
            {"name": "agent_id", "value": "$exec.body.agent.id"},
            {"name": "command", "value": "firewall-drop"},
            {"name": "custom", "value": "true"},
            {"name": "arguments", "value": "[\"$exec.body.data.srcip\"]"}
        ]
    }

def telegram_action(name, x=0, y=200):
    return {
        "id": gid(),
        "name": name,
        "description": "Send alert notification via Telegram",
        "app_name": "Telegram",
        "app_version": "1.0.0",
        "app_action": "send_message",
        "type": "action",
        "position": {"x": x, "y": y},
        "parameters": [
            {"name": "chat_id", "value": "TELEGRAM_CHAT_ID_PLACEHOLDER"},
            {"name": "message", "value": "🚨 T-Guard Alert!\nRule: $exec.body.rule.description\nLevel: $exec.body.rule.level\nAgent: $exec.body.agent.name\nSeverity: HIGH"}
        ]
    }

def build_branches(nodes):
    """Auto build sequential branches from a list of nodes"""
    branches = []
    for i in range(len(nodes) - 1):
        branches.append({
            "id": gid(),
            "source_id": nodes[i]["id"],
            "destination_id": nodes[i+1]["id"]
        })
    return branches

def create_workflow(name, nodes, description=""):
    x = 100
    for n in nodes:
        n["position"] = {"x": x, "y": 200}
        x += 280
    triggers = [n for n in nodes if n.get("type") == "trigger"]
    actions  = [n for n in nodes if n.get("type") == "action"]
    return {
        "name": name,
        "description": description or f"{name} - auto-generated by T-Guard",
        "triggers": triggers,
        "actions": actions,
        "branches": build_branches(nodes),
        "execution_arg": "",
        "tags": ["soc", "t-guard"]
    }

# ── WORKFLOW 1: Anti Duplicate ──────────────────────────────────────
wh1 = webhook_trigger()
i1_check  = iris_action("Check Duplicate (IRIS)", "check_duplicate")
i1_create = iris_action("Create Case (IRIS)",     "create_case")
wf1_nodes = [wh1, i1_check, i1_create]
wf1_branches = [
    {"id": gid(), "source_id": wh1["id"],      "destination_id": i1_check["id"]},
    {"id": gid(), "source_id": i1_check["id"], "destination_id": i1_create["id"],
     "condition": "$Check Duplicate (IRIS).data == null"}
]
wf1 = {**create_workflow("1. Anti Duplicate Case Creation", [wh1]),
       "actions": [i1_check, i1_create], "branches": wf1_branches}

# ── WORKFLOW 2: IP Enrichment ───────────────────────────────────────
wh2   = webhook_trigger()
m2    = misp_action("MISP Enrich")
v2    = vt_action("VT Enrich")
i2    = iris_action("Add Note (IRIS)", "add_notes")
wf2   = create_workflow("2. IP Reputation Enrichment", [wh2, m2, v2, i2])

# ── WORKFLOW 3: Malware Analysis ────────────────────────────────────
wh3   = webhook_trigger()
m3    = misp_action("Search Hash (MISP)")
v3    = vt_action("Analyze Hash (VT)")
i3    = iris_action("Create Alert Case (IRIS)", "create_alert")
t3    = telegram_action("Notify (Telegram)")
wf3   = create_workflow("3. Malware Analysis & Response", [wh3, m3, v3, i3, t3])

# ── WORKFLOW 4: Auto Containment ────────────────────────────────────
wh4   = webhook_trigger()
i4    = iris_action("Create Case (IRIS)", "create_case")
w4    = wazuh_action("Block IP (Wazuh AR)")
t4    = telegram_action("Notify (Telegram)")
wf4   = create_workflow("4. High Severity Auto Containment", [wh4, i4, w4, t4])

# ── WORKFLOW 5: Full SOC Pipeline ───────────────────────────────────
wh5      = webhook_trigger()
i5_check = iris_action("Check Duplicate",    "check_duplicate")
m5       = misp_action("MISP Enrich")
v5       = vt_action("VT Enrich")
i5_case  = iris_action("Create Case",        "create_case")
i5_notes = iris_action("Add Notes",          "add_notes")
t5       = telegram_action("Notify (Telegram)")
wf5      = create_workflow("5. Full SOC Pipeline (T-Guard Supreme)",
                           [wh5, i5_check, m5, v5, i5_case, i5_notes, t5],
                           "Full pipeline: Wazuh → MISP → VT → IRIS Case + Notes → Telegram")

workflows = {
    "1_anti_duplicate.json":  wf1,
    "2_ip_enrichment.json":   wf2,
    "3_malware_analysis.json":wf3,
    "4_auto_containment.json":wf4,
    "5_full_soc_pipeline.json":wf5
}

for fname, data in workflows.items():
    path = os.path.join(TEMPLATES_DIR, fname)
    with open(path, "w") as f:
        json.dump(data, f, indent=2)
    print(f"[OK] Generated: {fname}")

print("\n[DONE] All Shuffle templates generated with live credentials.")
print(f"  IRIS URL   : {IRIS_URL}")
print(f"  MISP URL   : {MISP_URL}")
print(f"  Webhook    : {WEBHOOK_URL}")
print(f"  IRIS Key   : {IRIS_API_KEY[:8]}...{'(SET)' if IRIS_API_KEY != 'IRIS_API_KEY_PLACEHOLDER' else '(MISSING!)'}")
print(f"  MISP Key   : {MISP_API_KEY[:8]}...{'(SET)' if MISP_API_KEY != 'MISP_API_KEY_PLACEHOLDER' else '(MISSING!)'}")
print(f"  VT Key     : {'(SET)' if VT_API_KEY and VT_API_KEY != 'VT_API_KEY_PLACEHOLDER' else '(MISSING - enrichment will not work without it)'}")
