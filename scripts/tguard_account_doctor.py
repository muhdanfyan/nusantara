#!/usr/bin/env python3
"""Read-only T-Guard account and integration doctor.

This helper is intentionally non-destructive. It helps operators recover from
"forgot the account/key" situations by locating generated credentials, checking
service endpoints, and validating n8n login/workflow visibility when possible.
Secrets are masked in stdout and reports.
"""

from __future__ import annotations

import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.request
import socket
from pathlib import Path
from typing import Any


N8N_DEFAULT_EMAIL = "admin@admin.test"
N8N_DEFAULT_PASS = "TGuardAdmin2024!"


def mask(value: str, keep: int = 4) -> str:
    value = (value or "").strip()
    if not value:
        return ""
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}...{value[-keep:]}"


def parse_env_file(path: Path) -> dict[str, str]:
    data: dict[str, str] = {}
    if not path.exists():
        return data
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        data[key.strip()] = value.strip().strip('"').strip("'")
    return data


HTTP_TIMEOUT = float(os.environ.get("TGUARD_DOCTOR_TIMEOUT", "2.5"))


def http_status(url: str, timeout: float = HTTP_TIMEOUT) -> int:
    ctx = None
    if url.startswith("https://"):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "tguard-account-doctor/1"})
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.getcode()
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def request_json(
    base_url: str,
    path: str,
    data: Any | None = None,
    method: str | None = None,
    cookie: str | None = None,
    timeout: float = HTTP_TIMEOUT,
) -> tuple[int, Any, dict[str, str]]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    headers = {"Accept": "application/json"}
    body = None
    if data is not None:
        body = json.dumps(data).encode("utf-8")
        headers["Content-Type"] = "application/json"
    if cookie:
        headers["Cookie"] = cookie
    req = urllib.request.Request(f"{base_url.rstrip('/')}{path}", data=body, headers=headers, method=method)
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        raw = resp.read().decode("utf-8", errors="replace")
        payload = json.loads(raw) if raw else {}
        return resp.getcode(), payload, dict(resp.headers)
    except urllib.error.HTTPError as exc:
        raw = exc.read().decode("utf-8", errors="replace")
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {}
        return exc.code, payload, dict(exc.headers)
    except Exception:
        return 0, {}, {}


def n8n_login(base_url: str, email: str, password: str) -> str | None:
    for _ in range(3):
        code, _payload, headers = request_json(
            base_url,
            "/rest/login",
            {"email": email, "password": password},
            method="POST",
            timeout=HTTP_TIMEOUT,
        )
        cookie = headers.get("Set-Cookie", "").split(";")[0]
        if code == 200 and cookie:
            return cookie
        time.sleep(0.5)
    return None


def unwrap_list(payload: Any) -> list[dict[str, Any]]:
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


def service_urls(creds: dict[str, str]) -> dict[str, str]:
    ip = creds.get("IP_ADDRESS") or "127.0.0.1"
    return {
        "n8n": creds.get("N8N_URL") or f"http://{ip}:5679",
        "iris": creds.get("IRIS_BASE_URL") or f"https://{ip}:443",
        "misp": creds.get("MISP_BASE_URL") or f"https://{ip}:1443",
        "wazuh": creds.get("WAZUH_DASHBOARD_URL") or f"https://{ip}",
    }


def is_public_ipv4(ip: str) -> bool:
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        nums = [int(part) for part in parts]
    except ValueError:
        return False
    if nums[0] in {10, 127} or nums[0] == 169 and nums[1] == 254 or nums[0] == 192 and nums[1] == 168:
        return False
    if nums[0] == 172 and 16 <= nums[1] <= 31:
        return False
    return True


def detect_public_ip(timeout: float = HTTP_TIMEOUT) -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://ipinfo.io/ip"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "tguard-account-doctor/1"})
            resp = urllib.request.urlopen(req, timeout=timeout)
            ip = resp.read().decode("utf-8", errors="replace").strip()
            if ip.count(".") == 3:
                return ip
        except Exception:
            continue
    return ""


def tcp_probe(host: str, port: int, timeout: float = HTTP_TIMEOUT) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def build_report(root: Path) -> dict[str, Any]:
    generated_path = root / ".tguard_credentials.env"
    config_path = root / ".tguard.env"
    generated = parse_env_file(generated_path)
    config = parse_env_file(config_path)
    merged = {**config, **generated}
    urls = service_urls(merged)
    stored_ip = merged.get("IP_ADDRESS") or ""
    public_ip = detect_public_ip()
    network_mode = merged.get("TGUARD_NETWORK_MODE") or config.get("TGUARD_NETWORK_MODE") or "auto"

    report: dict[str, Any] = {
        "generated_credentials_file": str(generated_path),
        "generated_credentials_exists": generated_path.exists(),
        "local_config_file": str(config_path),
        "local_config_exists": config_path.exists(),
        "accounts": {
            "n8n_url": urls["n8n"],
            "n8n_email": merged.get("N8N_EMAIL") or N8N_DEFAULT_EMAIL,
            "n8n_password": mask(merged.get("N8N_PASS") or N8N_DEFAULT_PASS),
            "misp_url": urls["misp"],
            "misp_api_key": mask(merged.get("MISP_API_KEY", "")),
            "iris_url": urls["iris"],
            "iris_api_key": mask(merged.get("IRIS_API_KEY", "")),
            "virustotal_api_key": mask(merged.get("TGUARD_VT_API_KEY") or merged.get("VT_API_KEY", "")),
        },
        "network": {
            "mode": network_mode,
            "stored_ip": stored_ip,
            "detected_public_ip": public_ip,
            "stored_ip_is_public": is_public_ipv4(stored_ip),
        },
        "endpoints": {},
        "public_access": {},
        "n8n": {},
        "notes": [],
    }

    for label, url in urls.items():
        status = http_status(url)
        report["endpoints"][label] = {"url": url, "http_status": status, "ok": status in {200, 302, 401}}

    if stored_ip and is_public_ipv4(stored_ip):
        public_targets = {
            "wazuh": ("https", stored_ip, 443),
            "misp": ("https", stored_ip, 1443),
            "n8n": ("http", stored_ip, 5679),
        }
        for label, (scheme, host, port) in public_targets.items():
            url = f"{scheme}://{host}:{port}" if not (scheme == "https" and port == 443) else f"https://{host}"
            status = http_status(url)
            report["public_access"][label] = {
                "url": url,
                "tcp_open": tcp_probe(host, port),
                "http_status": status,
                "ok": status in {200, 302, 401},
            }

    email = merged.get("N8N_EMAIL") or N8N_DEFAULT_EMAIL
    password = merged.get("N8N_PASS") or N8N_DEFAULT_PASS
    n8n_endpoint_ok = report["endpoints"].get("n8n", {}).get("http_status") in {200, 302}
    cookie = n8n_login(urls["n8n"], email, password) if n8n_endpoint_ok else None
    report["n8n"]["login_ok"] = bool(cookie)
    if cookie:
        code, payload, _headers = request_json(urls["n8n"], "/rest/workflows", method="GET", cookie=cookie)
        workflows = unwrap_list(payload) if code == 200 else []
        report["n8n"]["workflow_list_status"] = code
        report["n8n"]["workflow_count"] = len(workflows)
        report["n8n"]["workflow_names"] = [str(item.get("name", "")) for item in workflows if item.get("name")]
    else:
        if n8n_endpoint_ok:
            report["notes"].append("n8n login failed with stored/default credentials")
        else:
            report["notes"].append("n8n endpoint is not reachable; login check skipped")

    if not generated_path.exists():
        report["notes"].append("Run Integrate T-Guard SOC Package to regenerate .tguard_credentials.env")
    if not (merged.get("TGUARD_VT_API_KEY") or merged.get("VT_API_KEY")):
        report["notes"].append("VirusTotal API key is not configured; VT enrichment will need manual credential setup")
    if stored_ip and is_public_ipv4(stored_ip):
        public_ok = all(item.get("tcp_open") for item in report["public_access"].values())
        if not public_ok:
            report["notes"].append("Public IP detected but one or more public TCP probes failed; check cloud firewall/security group.")
        report["notes"].append("Do not expose TCP 9200 publicly; Wazuh indexer must stay internal.")

    return report


def main() -> int:
    root = Path(sys.argv[1]).resolve() if len(sys.argv) > 1 else Path(__file__).resolve().parents[1]
    report = build_report(root)
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
