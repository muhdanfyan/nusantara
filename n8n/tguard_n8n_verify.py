#!/usr/bin/env python3
"""Verify and heal n8n workflow imports for T-Guard.

Usage:
  tguard_n8n_verify.py email password template_path [template_path...]

Each template path can be a JSON file or a directory containing JSON workflows.
The verifier logs in, checks expected workflow names, tries to activate imported
workflows, and exits non-zero when any expected workflow is still missing.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any


BASE_URL = os.environ.get("N8N_BASE_URL", "http://127.0.0.1:5679").rstrip("/")
REQUIRE_MISP_CREDENTIAL = os.environ.get("TGUARD_VERIFY_MISP_CREDENTIAL", "").lower() in {
    "1",
    "true",
    "yes",
}
REQUIRE_VT_CREDENTIAL = os.environ.get("TGUARD_VERIFY_VT_CREDENTIAL", "").lower() in {
    "1",
    "true",
    "yes",
}
CTX = ssl.create_default_context()
CTX.check_hostname = False
CTX.verify_mode = ssl.CERT_NONE


def load_json_response(resp: Any) -> Any:
    raw = resp.read().decode("utf-8", errors="replace")
    if not raw:
        return {}
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
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
    except Exception:
        return 0, {}, {}


def wait_healthz() -> bool:
    for _ in range(90):
        code, _data, _headers = request("/healthz", timeout=5)
        if code == 200:
            return True
        time.sleep(2)
    return False


def login(email: str, password: str) -> str | None:
    for _ in range(45):
        code, _data, headers = request(
            "/rest/login",
            {"email": email, "password": password},
            method="POST",
            timeout=15,
        )
        cookie = headers.get("Set-Cookie", "").split(";")[0]
        if code == 200 and cookie:
            return cookie
        time.sleep(2)
    return None


def unwrap_workflows(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, dict):
        data = payload.get("data", payload)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("workflows", "results"):
                if isinstance(data.get(key), list):
                    return data[key]
    if isinstance(payload, list):
        return payload
    return []


def template_files(paths: list[str]) -> list[Path]:
    files: list[Path] = []
    for raw in paths:
        path = Path(raw)
        if path.is_dir():
            files.extend(sorted(path.glob("*.json")))
        elif path.is_file():
            files.append(path)
    return files


def expected_names(paths: list[str]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for file in template_files(paths):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = str(payload.get("name", "")).strip()
        if name and name not in seen:
            seen.add(name)
            names.append(name)
    return names


def template_credential_requirements(paths: list[str]) -> dict[str, set[str]]:
    requirements: dict[str, set[str]] = {}
    for file in template_files(paths):
        try:
            payload = json.loads(file.read_text(encoding="utf-8"))
        except Exception:
            continue
        name = str(payload.get("name", "")).strip()
        if not name:
            continue
        required: set[str] = set()
        for node in payload.get("nodes", []):
            node_type = node.get("type")
            if node_type == "n8n-nodes-base.misp" and REQUIRE_MISP_CREDENTIAL:
                required.add("mispApi")
            if node_type in ("n8n-nodes-base.virustotal", "n8n-nodes-base.virusTotal") and REQUIRE_VT_CREDENTIAL:
                required.add("virusTotalApi")
        requirements[name] = required
    return requirements


def workflow_id(workflow: dict[str, Any]) -> str:
    return str(workflow.get("id") or workflow.get("workflowId") or "")


def workflow_detail(cookie: str, workflow: dict[str, Any]) -> dict[str, Any]:
    if workflow.get("nodes"):
        return workflow
    wf_id = workflow_id(workflow)
    if not wf_id:
        return workflow
    code, data, _headers = request(f"/rest/workflows/{wf_id}", method="GET", cookie=cookie)
    if code == 200 and isinstance(data, dict):
        detail = data.get("data", data)
        if isinstance(detail, dict):
            return detail
    return workflow


def missing_credentials(workflow: dict[str, Any], required: set[str]) -> list[str]:
    if not required:
        return []
    found: set[str] = set()
    for node in workflow.get("nodes", []):
        credentials = node.get("credentials")
        if isinstance(credentials, dict):
            found.update(str(key) for key in credentials)
    return sorted(required - found)


def activate(cookie: str, workflow: dict[str, Any]) -> bool:
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


def main() -> int:
    if len(sys.argv) < 4:
        print("FAIL_USAGE email password template_path [template_path...]")
        return 2

    email = sys.argv[1]
    password = sys.argv[2]
    templates = sys.argv[3:]
    expected = expected_names(templates)
    credential_requirements = template_credential_requirements(templates)
    if not expected:
        print("FAIL_EXPECTED_EMPTY")
        return 2

    if not wait_healthz():
        print("FAIL_HEALTHZ")
        return 3

    cookie = login(email, password)
    if not cookie:
        print("FAIL_LOGIN")
        return 4

    code, payload, _headers = request("/rest/workflows", method="GET", cookie=cookie)
    if code != 200:
        print(f"FAIL_LIST_{code}")
        return 5

    workflows = unwrap_workflows(payload)
    by_name = {str(item.get("name", "")): item for item in workflows if item.get("name")}
    missing = [name for name in expected if name not in by_name]
    activated = 0
    inactive = []
    credential_failures: dict[str, list[str]] = {}
    for name in expected:
        workflow = by_name.get(name)
        if not workflow:
            continue
        detail = workflow_detail(cookie, workflow)
        missing = missing_credentials(detail, credential_requirements.get(name, set()))
        if missing:
            credential_failures[name] = missing
        if activate(cookie, workflow):
            activated += 1
        else:
            inactive.append(name)

    if missing:
        print(
            "FAIL_MISSING "
            + json.dumps({"expected": len(expected), "found": len(expected) - len(missing), "missing": missing})
        )
        return 6
    if credential_failures:
        print(
            "FAIL_CREDENTIALS "
            + json.dumps(
                {
                    "expected": len(expected),
                    "credential_failures": credential_failures,
                    "require_misp": REQUIRE_MISP_CREDENTIAL,
                    "require_vt": REQUIRE_VT_CREDENTIAL,
                }
            )
        )
        return 8
    if inactive:
        print(
            "WARN_INACTIVE "
            + json.dumps({"expected": len(expected), "inactive": inactive, "activated": activated})
        )
        return 7

    print(f"OK expected={len(expected)} found={len(expected)} activated={activated}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
