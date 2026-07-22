#!/usr/bin/env python3
"""Stable T-Guard n8n workflow importer.

This script intentionally keeps the same positional CLI used by setup.sh:
  email password workflow_file misp_url misp_key vt_key

It prints one machine-readable status line to stdout:
  OK, EXISTS, FAIL_LOGIN: ..., FAIL_TEMPLATE: ..., FAIL_IMPORT_<code>: ...
Diagnostics go to stderr so setup.sh can keep parsing stdout safely.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from typing import Any


BASE_URL = os.environ.get("N8N_BASE_URL", "http://127.0.0.1:5679").rstrip("/")
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE

PLACEHOLDERS = {
    "",
    "(MISP_API_KEY_PLACEHOLDER)",
    "MISP_API_KEY_PLACEHOLDER",
    "VT_API_KEY_PLACEHOLDER",
    "VIRUSTOTAL_API_KEY_PLACEHOLDER",
    "put_virustotal_api_key_here",
}


def clean_secret(value: str) -> str:
    value = (value or "").strip()
    return "" if value in PLACEHOLDERS else value


def load_json_response(resp: Any) -> Any:
    raw = resp.read().decode("utf-8", errors="replace")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        print(raw[:500], file=sys.stderr)
        return {}


def request(
    path: str,
    data: Any | None = None,
    method: str | None = None,
    cookie: str | None = None,
    timeout: int = 20,
) -> tuple[int, Any, dict[str, str]]:
    headers = {"Accept": "application/json"}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie

    req = urllib.request.Request(f"{BASE_URL}{path}", data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, context=CTX, timeout=timeout)
        return resp.getcode(), load_json_response(resp), dict(resp.headers)
    except urllib.error.HTTPError as exc:
        return exc.code, load_json_response(exc), dict(exc.headers)
    except Exception as exc:  # noqa: BLE001 - status line is consumed by shell
        print(f"request failed {path}: {exc}", file=sys.stderr)
        return 0, {}, {}


def login(email: str, password: str) -> str | None:
    last_error = "No response"
    for _ in range(30):
        code, data, headers = request(
            "/rest/login",
            {"email": email, "password": password},
            method="POST",
            timeout=15,
        )
        cookie = headers.get("Set-Cookie", "").split(";")[0]
        if code == 200 and cookie:
            return cookie
        last_error = f"HTTP {code} {str(data)[:200]}"
        time.sleep(2)
    print(f"FAIL_LOGIN: {last_error}")
    return None


def unwrap_data(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict) and isinstance(payload.get("data"), list):
        return payload["data"]
    if isinstance(payload, list):
        return payload
    return []


def ensure_credential(cookie: str, name: str, credential_type: str, data: dict[str, Any]) -> str | None:
    code, existing, _ = request("/rest/credentials", method="GET", cookie=cookie)
    if code == 200:
        for credential in unwrap_data(existing):
            if credential.get("name") == name:
                return str(credential.get("id"))

    code, created, _ = request(
        "/rest/credentials",
        {"name": name, "type": credential_type, "data": data},
        method="POST",
        cookie=cookie,
    )
    if code in (200, 201):
        created_data = created.get("data", created) if isinstance(created, dict) else {}
        credential_id = created_data.get("id") if isinstance(created_data, dict) else None
        return str(credential_id) if credential_id else None

    print(f"credential create failed {name}: HTTP {code} {str(created)[:300]}", file=sys.stderr)
    return None


def patch_credentials(workflow: dict[str, Any], misp_id: str | None, vt_id: str | None) -> None:
    for node in workflow.get("nodes", []):
        node_type = node.get("type")
        if node_type == "n8n-nodes-base.misp" and misp_id:
            node["credentials"] = {"mispApi": {"id": misp_id, "name": "T-Guard MISP API"}}
        elif node_type in ("n8n-nodes-base.virustotal", "n8n-nodes-base.virusTotal") and vt_id:
            node["credentials"] = {
                "virusTotalApi": {"id": vt_id, "name": "T-Guard VirusTotal API"}
            }


def workflow_id(workflow: dict[str, Any]) -> str:
    return str(workflow.get("id") or workflow.get("workflowId") or "")


def activate_workflow(cookie: str, workflow: dict[str, Any]) -> bool:
    wf_id = workflow_id(workflow)
    if not wf_id:
        return False
    if workflow.get("active") is True:
        return True
    for method, path, body in (
        ("POST", f"/rest/workflows/{wf_id}/activate", {"active": True}),
        ("PATCH", f"/rest/workflows/{wf_id}", {"active": True}),
    ):
        code, _data, _headers = request(path, body, method=method, cookie=cookie)
        if code in (200, 201):
            return True
    return False


def update_existing_workflow(cookie: str, existing: dict[str, Any], desired: dict[str, Any]) -> bool:
    wf_id = workflow_id(existing)
    if not wf_id:
        return False
    payload = dict(desired)
    payload.pop("id", None)
    payload.pop("createdAt", None)
    payload.pop("updatedAt", None)
    for method in ("PATCH", "PUT"):
        code, data, _headers = request(f"/rest/workflows/{wf_id}", payload, method=method, cookie=cookie)
        if code in (200, 201):
            updated = data.get("data", data) if isinstance(data, dict) else {}
            if isinstance(updated, dict):
                activate_workflow(cookie, updated)
            return True
    return False


def main() -> int:
    email = sys.argv[1] if len(sys.argv) > 1 else ""
    password = sys.argv[2] if len(sys.argv) > 2 else ""
    file_path = sys.argv[3] if len(sys.argv) > 3 else ""
    misp_url = (sys.argv[4] if len(sys.argv) > 4 else "").rstrip("/")
    misp_key = clean_secret(sys.argv[5] if len(sys.argv) > 5 else "")
    vt_key = clean_secret(sys.argv[6] if len(sys.argv) > 6 else "")

    cookie = login(email, password)
    if not cookie:
        return 1

    try:
        with open(file_path, "r", encoding="utf-8") as handle:
            workflow = json.load(handle)
    except Exception as exc:  # noqa: BLE001
        print(f"FAIL_TEMPLATE: {exc}")
        return 1

    misp_id = None
    if misp_key and misp_url:
        misp_id = ensure_credential(
            cookie,
            "T-Guard MISP API",
            "mispApi",
            {"url": misp_url, "apiToken": misp_key, "allowUnauthorizedCerts": True},
        )

    vt_id = None
    if vt_key:
        vt_id = ensure_credential(
            cookie,
            "T-Guard VirusTotal API",
            "virusTotalApi",
            {"apiKey": vt_key},
        )

    patch_credentials(workflow, misp_id, vt_id)

    code, existing, _ = request("/rest/workflows", method="GET", cookie=cookie)
    if code == 200:
        for item in unwrap_data(existing):
            if item.get("name") == workflow.get("name"):
                if update_existing_workflow(cookie, item, workflow):
                    print("UPDATED")
                else:
                    activate_workflow(cookie, item)
                    print("EXISTS")
                return 0

    code, response, _ = request("/rest/workflows", workflow, method="POST", cookie=cookie)
    if code in (200, 201):
        created = response.get("data", response) if isinstance(response, dict) else {}
        if isinstance(created, dict):
            activate_workflow(cookie, created)
        print("OK")
        return 0

    print(f"FAIL_IMPORT_{code}: {str(response)[:300]}")
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
