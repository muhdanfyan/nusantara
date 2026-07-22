#!/usr/bin/env python3
"""T-Guard local preflight checks for workflow/import stability."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
N8N_TEMPLATES = ROOT / "n8n" / "templates"
SHUFFLE_TEMPLATES = ROOT / "shuffle" / "templates"
AGENT_CONF = ROOT / "wazuh-docker" / "single-node" / "custom-integrations" / "add_vtwazuh_config-agent.conf"
LOCAL_RULES = ROOT / "wazuh-docker" / "single-node" / "custom-integrations" / "local_rules.xml"
POC_RUNNER = ROOT / "scripts" / "tguard_poc.py"
SELFHEAL_RUNNER = ROOT / "scripts" / "tguard_selfheal.py"
ACCOUNT_DOCTOR = ROOT / "scripts" / "tguard_account_doctor.py"
ENV_DOCTOR = ROOT / "scripts" / "tguard_env_doctor.py"
N8N_IMPORTER = ROOT / "n8n" / "tguard_n8n_import.py"
N8N_VERIFIER = ROOT / "n8n" / "tguard_n8n_verify.py"
ENV_FILE = ROOT / ".tguard.env"


def status(ok: bool, message: str) -> bool:
    print(f"[{'OK' if ok else 'FAIL'}] {message}")
    return ok


def check_json_templates(path: Path) -> bool:
    ok = True
    for item in sorted(path.glob("*.json")):
        try:
            json.loads(item.read_text(encoding="utf-8"))
            status(True, f"JSON valid: {item.relative_to(ROOT)}")
        except Exception as exc:  # noqa: BLE001
            ok = False
            status(False, f"JSON invalid: {item.relative_to(ROOT)} ({exc})")
    return ok


def check_virustotal_nodes() -> bool:
    ok = True
    for item in sorted(N8N_TEMPLATES.glob("*.json")):
        data = json.loads(item.read_text(encoding="utf-8"))
        for node in data.get("nodes", []):
            if node.get("name", "").lower().startswith("virustotal"):
                node_type = node.get("type")
                valid = node_type == "n8n-nodes-base.virustotal"
                ok = status(valid, f"VirusTotal node type in {item.name}: {node_type}") and ok
    return ok


def check_vt_key_hint() -> bool:
    vt_key = os.environ.get("TGUARD_VT_API_KEY") or os.environ.get("VT_API_KEY")
    if vt_key:
        return status(True, "VirusTotal API key is present in environment")
    if ENV_FILE.exists():
        text = ENV_FILE.read_text(encoding="utf-8", errors="replace")
        has_key = False
        for raw in text.splitlines():
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            if line.startswith("export "):
                line = line[len("export "):].strip()
            if not line.startswith(("TGUARD_VT_API_KEY=", "VT_API_KEY=")):
                continue
            value = line.split("=", 1)[1].strip().strip('"').strip("'")
            if value and value != "put_virustotal_api_key_here":
                has_key = True
                break
        if has_key:
            return status(True, "VirusTotal API key is present in .tguard.env")
    return status(False, "VirusTotal API key not found; set TGUARD_VT_API_KEY in .tguard.env")


def check_auth_log_config() -> bool:
    text = AGENT_CONF.read_text(encoding="utf-8", errors="replace")
    checks = [
        ("/var/log/auth.log" in text, "agent watches /var/log/auth.log"),
        ("journalctl -u ssh -u sshd" in text, "agent has journalctl SSH fallback"),
    ]
    ok = True
    for passed, message in checks:
        ok = status(passed, message) and ok
    return ok


def check_poc_config() -> bool:
    ok = True
    local_rules = LOCAL_RULES.read_text(encoding="utf-8", errors="replace")
    ok = status(POC_RUNNER.exists(), "PoC runner exists: scripts/tguard_poc.py") and ok
    ok = status(SELFHEAL_RUNNER.exists(), "Self-heal runner exists: scripts/tguard_selfheal.py") and ok
    ok = status(ACCOUNT_DOCTOR.exists(), "Account doctor exists: scripts/tguard_account_doctor.py") and ok
    ok = status(ENV_DOCTOR.exists(), "Cloud/VM env doctor exists: scripts/tguard_env_doctor.py") and ok
    if ENV_DOCTOR.exists():
        text = ENV_DOCTOR.read_text(encoding="utf-8", errors="replace")
        ok = status("provider_firewall_required_tcp" in text, "env doctor reports cloud firewall requirements") and ok
        ok = status("is_virtualbox" in text and "is_public_cloud_or_vps" in text, "env doctor detects VM/cloud platform") and ok
    ok = status("usecase/webdeface" in local_rules, "local_rules.xml matches current PoC usecase path") and ok
    for name in ["index.html", "index_ori.html", "webdeface.html", "server.js"]:
        ok = status((ROOT / "usecase" / "webdeface" / name).exists(), f"PoC file exists: usecase/webdeface/{name}") and ok
    return ok


def check_n8n_import_helpers() -> bool:
    ok = True
    ok = status(N8N_IMPORTER.exists(), "n8n importer exists: n8n/tguard_n8n_import.py") and ok
    ok = status(N8N_VERIFIER.exists(), "n8n verifier exists: n8n/tguard_n8n_verify.py") and ok
    if N8N_IMPORTER.exists():
        text = N8N_IMPORTER.read_text(encoding="utf-8", errors="replace")
        ok = status("UPDATED" in text and "update_existing_workflow" in text, "n8n importer updates existing workflows") and ok
        ok = status("activate_workflow" in text, "n8n importer activates workflows") and ok
    if N8N_VERIFIER.exists():
        text = N8N_VERIFIER.read_text(encoding="utf-8", errors="replace")
        ok = status("FAIL_CREDENTIALS" in text, "n8n verifier checks credential binding") and ok
        ok = status("FAIL_MISSING" in text, "n8n verifier detects missing workflows") and ok
    if SELFHEAL_RUNNER.exists():
        text = SELFHEAL_RUNNER.read_text(encoding="utf-8", errors="replace")
        ok = status("heal_n8n_workflows" in text, "self-heal can repair missing n8n workflows") and ok
        ok = status("n8n_import_templates" in text, "self-heal can re-import bundled n8n templates") and ok
        ok = status("Evidence captured" in text, "self-heal captures docker evidence logs") and ok
        ok = status("collect_incident_bundle" in text, "self-heal creates incident bundles after failed recovery") and ok
        ok = status("--min-score" in text, "self-heal supports health gate threshold") and ok
    return ok


def main() -> int:
    ok = True
    ok = check_json_templates(N8N_TEMPLATES) and ok
    ok = check_json_templates(SHUFFLE_TEMPLATES) and ok
    ok = check_virustotal_nodes() and ok
    ok = check_auth_log_config() and ok
    ok = check_poc_config() and ok
    ok = check_n8n_import_helpers() and ok
    key_ok = check_vt_key_hint()
    if not key_ok:
        print("[WARN] Install can continue, but VirusTotal enrichment will need manual credentials.")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
