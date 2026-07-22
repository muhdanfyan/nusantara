#!/usr/bin/env python3
"""Evidence-based T-Guard self-healing helper.

The bash installer stays the orchestrator. This helper performs bounded,
non-destructive checks and repair attempts, then writes a report that explains
what happened.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import zipfile
from pathlib import Path
from typing import Any


DEFAULT_CONTAINERS = [
    "single-node-wazuh.indexer-1",
    "single-node-wazuh.manager-1",
    "single-node-wazuh.dashboard-1",
    "iriswebapp_app",
    "iriswebapp_nginx",
    "iriswebapp_db",
    "misp-docker-db-1",
    "misp-docker-core-1",
    "misp-docker-modules-1",
    "n8n",
]

RECOVERY_ORDER = [
    "single-node-wazuh.indexer-1",
    "single-node-wazuh.manager-1",
    "single-node-wazuh.dashboard-1",
    "iriswebapp_db",
    "iriswebapp_rabbitmq",
    "iriswebapp_app",
    "iriswebapp_worker",
    "iriswebapp_nginx",
    "misp-docker-db-1",
    "misp-docker-core-1",
    "misp-docker-modules-1",
    "n8n",
]

DEPENDENCIES = {
    "single-node-wazuh.manager-1": ["single-node-wazuh.indexer-1"],
    "single-node-wazuh.dashboard-1": ["single-node-wazuh.indexer-1", "single-node-wazuh.manager-1"],
    "iriswebapp_app": ["iriswebapp_db", "iriswebapp_rabbitmq"],
    "iriswebapp_worker": ["iriswebapp_db", "iriswebapp_rabbitmq"],
    "iriswebapp_nginx": ["iriswebapp_app"],
    "misp-docker-core-1": ["misp-docker-db-1"],
    "misp-docker-modules-1": ["misp-docker-core-1"],
}

ENDPOINTS = [
    ("n8n", "http://127.0.0.1:5679/healthz", [200, 302], 5679, ["n8n"]),
    ("iris", "https://127.0.0.1:443", [200, 302], 443, ["iriswebapp_nginx", "iriswebapp_app"]),
    ("misp", "https://127.0.0.1:1443", [200, 302], 1443, ["misp-docker-core-1"]),
    ("wazuh-indexer", "https://127.0.0.1:9200", [200, 401], 9200, ["single-node-wazuh.indexer-1"]),
]

CRITICAL_PORTS = [443, 1443, 5679, 1514, 1515, 55000, 9200]
SECRET_KEYWORDS = ("KEY", "TOKEN", "PASS", "PASSWORD", "SECRET", "AUTH")

N8N_REQUIRED_WORKFLOWS = [
    "1. Anti Duplicate Case Creation",
    "2. IP Reputation Enrichment",
    "3. Malware Analysis & Response",
    "4. High Severity Auto Containment",
    "5. Full SOC Alert Pipeline",
]


def run(cmd: list[str], timeout: int = 30, cwd: Path | None = None) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=timeout,
            encoding="utf-8",
            errors="replace",
            cwd=str(cwd) if cwd else None,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return 127, str(exc)


def sudo_cmd(cmd: list[str]) -> list[str]:
    if os.name == "nt" or os.geteuid() == 0:
        return cmd
    return ["sudo", *cmd]


def docker_cmd(args: list[str], timeout: int = 30) -> tuple[int, str]:
    return run(sudo_cmd(["docker", *args]), timeout=timeout)


def compose_cmd(directory: Path, args: list[str], timeout: int = 180) -> tuple[int, str]:
    if not (directory / "docker-compose.yml").exists() and not (directory / "compose.yml").exists():
        return 127, f"compose file not found in {directory}"
    if shutil.which("docker"):
        code, output = run(sudo_cmd(["docker", "compose", *args]), timeout=timeout, cwd=directory)
        if code == 0 or "docker: 'compose' is not a docker command" not in output.lower():
            return code, output
    if shutil.which("docker-compose"):
        return run(sudo_cmd(["docker-compose", *args]), timeout=timeout, cwd=directory)
    return 127, "docker compose unavailable"


def systemctl(action: str, unit: str) -> tuple[int, str]:
    if not shutil.which("systemctl"):
        return 0, "systemctl unavailable"
    cmd = ["systemctl", action]
    if unit:
        cmd.append(unit)
    return run(sudo_cmd(cmd), timeout=60)


def http_status(url: str, timeout: int = 8) -> int:
    ctx = None
    if url.startswith("https://"):
        import ssl

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": "tguard-selfheal/1"})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
        return resp.getcode()
    except urllib.error.HTTPError as exc:
        return exc.code
    except Exception:
        return 0


def port_open(host: str, port: int, timeout: float = 2.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


class Healer:
    def __init__(self, root: Path, log_dir: Path, deep: bool = False, min_score: float = 0.0) -> None:
        self.root = root
        self.log_dir = log_dir
        self.deep = deep
        self.min_score = min_score
        self.events: list[dict[str, Any]] = []
        self.repairs = self.build_repair_plan()
        self.final_score = 0.0

    def build_repair_plan(self) -> dict[str, dict[str, str]]:
        return {
            "single-node-wazuh.manager-1": {"dir": "wazuh-docker/single-node", "service": "wazuh.manager"},
            "single-node-wazuh.indexer-1": {"dir": "wazuh-docker/single-node", "service": "wazuh.indexer"},
            "single-node-wazuh.dashboard-1": {"dir": "wazuh-docker/single-node", "service": "wazuh.dashboard"},
            "iriswebapp_app": {"dir": "iris-web", "service": "app"},
            "iriswebapp_nginx": {"dir": "iris-web", "service": "nginx"},
            "iriswebapp_db": {"dir": "iris-web", "service": "db"},
            "iriswebapp_worker": {"dir": "iris-web", "service": "worker"},
            "iriswebapp_rabbitmq": {"dir": "iris-web", "service": "rabbitmq"},
            "misp-docker-db-1": {"dir": "misp-docker", "service": "db"},
            "misp-docker-core-1": {"dir": "misp-docker", "service": "misp-core"},
            "misp-docker-modules-1": {"dir": "misp-docker", "service": "misp-modules"},
            "n8n": {"dir": "n8n", "service": "n8n"},
        }

    def event(self, level: str, message: str, **fields: Any) -> None:
        row = {"level": level, "message": message, **fields}
        self.events.append(row)
        print(f"[{level}] {message}")

    def evidence_file(self, name: str, suffix: str, content: str) -> None:
        safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in name)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        path = self.log_dir / f"selfheal-{safe_name}-{suffix}-{stamp}.log"
        path.write_text(content, encoding="utf-8", errors="replace")
        self.event("OK", "Evidence captured", path=str(path))

    def mask_value(self, key: str, value: str) -> str:
        if any(token in key.upper() for token in SECRET_KEYWORDS):
            if not value:
                return ""
            if len(value) <= 8:
                return "***"
            return f"{value[:4]}...{value[-4:]}"
        return value

    def redacted_env_snapshot(self) -> dict[str, str]:
        merged: dict[str, str] = {}
        for env_path in [self.root / ".tguard.env", self.root / ".tguard_credentials.env"]:
            for key, value in parse_env_file(env_path).items():
                merged[key] = self.mask_value(key, value)
        return merged

    def expand_targets(self, containers: list[str]) -> list[str]:
        expanded: set[str] = set()

        def add_with_deps(name: str) -> None:
            for dep in DEPENDENCIES.get(name, []):
                add_with_deps(dep)
            expanded.add(name)

        for container in containers:
            add_with_deps(container)

        ordered = [name for name in RECOVERY_ORDER if name in expanded]
        ordered.extend(sorted(name for name in expanded if name not in ordered))
        self.event("OK", "Recovery target plan built", requested=containers, ordered=ordered)
        return ordered

    def endpoint_snapshot(self) -> dict[str, int]:
        return {label: http_status(url) for label, url, _codes, _port, _containers in ENDPOINTS}

    def health_score(self, containers: list[str]) -> dict[str, Any]:
        container_rows = {name: self.inspect_container(name) for name in containers}
        endpoint_rows = self.endpoint_snapshot()
        healthy_containers = sum(
            1
            for state in container_rows.values()
            if state["status"] == "running" and state["health"] in ("healthy", "none")
        )
        healthy_endpoints = sum(
            1
            for label, _url, ok_codes, _port, _containers in ENDPOINTS
            if endpoint_rows.get(label, 0) in ok_codes
        )
        total = max(1, len(container_rows) + len(ENDPOINTS))
        score = round(((healthy_containers + healthy_endpoints) / total) * 100, 2)
        return {
            "score": score,
            "healthy_containers": healthy_containers,
            "total_containers": len(container_rows),
            "healthy_endpoints": healthy_endpoints,
            "total_endpoints": len(ENDPOINTS),
            "containers": container_rows,
            "endpoints": endpoint_rows,
        }

    def emit_health_score(self, label: str, containers: list[str]) -> dict[str, Any]:
        score = self.health_score(containers)
        self.event(
            "OK",
            f"Health score {label}: {score['score']}%",
            healthy_containers=score["healthy_containers"],
            total_containers=score["total_containers"],
            healthy_endpoints=score["healthy_endpoints"],
            total_endpoints=score["total_endpoints"],
        )
        return score

    def ensure_compose_inventory(self) -> None:
        checked: set[Path] = set()
        for plan in self.repairs.values():
            directory = self.root / plan["dir"]
            if directory in checked:
                continue
            checked.add(directory)
            if (directory / "docker-compose.yml").exists() or (directory / "compose.yml").exists():
                self.event("OK", "Compose inventory found", directory=str(directory))
                code, output = compose_cmd(directory, ["config", "--quiet"], timeout=90)
                if code == 0:
                    self.event("OK", "Compose config validates", directory=str(directory))
                else:
                    self.event("WARN", "Compose config validation failed", directory=str(directory), output=output[-1200:])
            else:
                self.event("WARN", "Compose inventory missing", directory=str(directory))

    def ensure_auth_log(self) -> None:
        auth_log = Path("/var/log/auth.log")
        if not Path("/var/log").exists():
            return
        if auth_log.exists():
            self.event("OK", "auth.log exists", path=str(auth_log))
            return
        self.event("HEAL", "auth.log missing; creating fallback file", path=str(auth_log))
        run(sudo_cmd(["touch", str(auth_log)]), timeout=10)
        run(sudo_cmd(["chmod", "640", str(auth_log)]), timeout=10)
        if shutil.which("systemctl"):
            systemctl("enable", "rsyslog")
            systemctl("restart", "rsyslog")
            self.event("HEAL", "rsyslog restarted after auth.log recovery")

    def ensure_docker_network(self) -> None:
        code, output = docker_cmd(["network", "inspect", "bridge"], timeout=15)
        if code == 0:
            self.event("OK", "Docker bridge network exists")
            return
        self.event("HEAL", "Docker bridge network unavailable; restarting docker", output=output[-500:])
        systemctl("restart", "docker")
        time.sleep(5)

    def system_prerequisites(self) -> None:
        self.ensure_kernel()
        self.memory_guard()
        self.ensure_compose_inventory()
        self.ensure_auth_log()
        self.ensure_docker_network()

    def ensure_kernel(self) -> None:
        current = "0"
        try:
            current = Path("/proc/sys/vm/max_map_count").read_text().strip()
        except Exception:
            return
        if current.isdigit() and int(current) < 262144:
            self.event("HEAL", "vm.max_map_count too low; raising to 262144", current=current)
            run(sudo_cmd(["sysctl", "-w", "vm.max_map_count=262144"]), timeout=10)

    def memory_guard(self) -> None:
        meminfo = Path("/proc/meminfo")
        if not meminfo.exists():
            return
        values: dict[str, int] = {}
        for line in meminfo.read_text(encoding="utf-8", errors="replace").splitlines():
            parts = line.split()
            if len(parts) >= 2 and parts[1].isdigit():
                values[parts[0].rstrip(":")] = int(parts[1])
        mem_avail_mb = values.get("MemAvailable", 0) // 1024
        swap_total_mb = values.get("SwapTotal", 0) // 1024
        self.event("OK", "Memory snapshot", mem_available_mb=mem_avail_mb, swap_total_mb=swap_total_mb)
        if mem_avail_mb and mem_avail_mb < 1024 and swap_total_mb < 2048:
            self.event("WARN", "Low available memory and low swap detected; container restarts may fail")

    def ensure_docker(self) -> bool:
        code, output = docker_cmd(["info"], timeout=20)
        if code == 0:
            self.event("OK", "Docker daemon responds")
            return True
        self.event("HEAL", "Docker daemon not responding; restarting docker", output=output[-500:])
        systemctl("daemon-reload", "")
        systemctl("start", "containerd")
        systemctl("restart", "docker")
        time.sleep(5)
        code, output = docker_cmd(["info"], timeout=20)
        ok = code == 0
        self.event("OK" if ok else "FAIL", "Docker daemon recheck", output=output[-500:])
        return ok

    def disk_guard(self) -> None:
        target = self.root if self.root.exists() else Path("/")
        usage = shutil.disk_usage(str(target))
        free_gb = usage.free // (1024**3)
        self.event("OK", f"Disk free at root: {free_gb}GB")
        if free_gb < 10:
            self.event("HEAL", "Low disk; pruning Docker builder/cache")
            docker_cmd(["builder", "prune", "-af"], timeout=120)
            docker_cmd(["container", "prune", "-f"], timeout=60)
        if self.deep and free_gb < 20:
            self.event("HEAL", "Deep mode low disk; pruning unused Docker images")
            docker_cmd(["image", "prune", "-af"], timeout=180)

    def inspect_container(self, name: str) -> dict[str, str]:
        code, raw = docker_cmd(
            [
                "inspect",
                "--format",
                "{{.State.Status}}|{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}|{{.State.ExitCode}}|{{.State.OOMKilled}}|{{.RestartCount}}",
                name,
            ],
            timeout=15,
        )
        if code != 0:
            return {"exists": "false", "status": "missing", "health": "missing", "exit": "", "oom": "", "restarts": ""}
        status, health, exit_code, oom, restarts = (raw.split("|") + ["", "", "", "", ""])[:5]
        return {"exists": "true", "status": status, "health": health, "exit": exit_code, "oom": oom, "restarts": restarts}

    def compose_up(self, name: str) -> None:
        plan = self.repairs.get(name)
        if not plan:
            self.event("WARN", f"No compose repair plan for {name}")
            return
        directory = self.root / plan["dir"]
        service = plan["service"]
        self.event("HEAL", f"Compose up repair: {name}", directory=str(directory), service=service)
        code, output = compose_cmd(directory, ["up", "-d", service], timeout=300)
        self.event("OK" if code == 0 else "FAIL", f"Compose repair result: {name}", output=output[-1200:])
        time.sleep(6)

    def compose_up_stack(self, stack_dir: str, services: list[str]) -> None:
        directory = self.root / stack_dir
        services = [service for service in services if service]
        if not services:
            return
        self.event("HEAL", "Compose stack repair", directory=str(directory), services=services)
        code, output = compose_cmd(directory, ["up", "-d", *services], timeout=420)
        self.event("OK" if code == 0 else "FAIL", "Compose stack repair result", output=output[-1200:])
        time.sleep(8)

    def stack_repair_pass(self, containers: list[str]) -> None:
        if not self.deep:
            return
        grouped: dict[str, list[str]] = {}
        for container in containers:
            plan = self.repairs.get(container)
            if not plan:
                continue
            grouped.setdefault(plan["dir"], [])
            if plan["service"] not in grouped[plan["dir"]]:
                grouped[plan["dir"]].append(plan["service"])
        for stack_dir, services in grouped.items():
            self.compose_up_stack(stack_dir, services)

    def remove_dead_container(self, name: str, state: dict[str, str]) -> None:
        if state["exists"] == "true" and state["status"] in {"created", "exited", "dead"}:
            self.event("HEAL", f"Removing stopped container before compose recreate: {name}", **state)
            docker_cmd(["rm", "-f", name], timeout=60)

    def docker_mount_sources(self, name: str) -> list[str]:
        code, output = docker_cmd(
            ["inspect", "--format", "{{range .Mounts}}{{if eq .Type \"bind\"}}{{.Source}}{{\"\\n\"}}{{end}}{{end}}", name],
            timeout=15,
        )
        if code != 0:
            return []
        return [line.strip() for line in output.splitlines() if line.strip()]

    def fix_bind_permissions(self, name: str) -> None:
        if name != "n8n":
            return
        for source in self.docker_mount_sources(name):
            path = Path(source)
            try:
                path.resolve().relative_to(self.root)
            except Exception:
                self.event("WARN", f"{name}: skip permission fix outside root", path=source)
                continue
            self.event("HEAL", f"{name}: fixing bind mount ownership", path=source)
            run(sudo_cmd(["chown", "-R", "1000:1000", source]), timeout=120)

    def classify_and_repair_logs(self, name: str, logs: str) -> None:
        self.evidence_file(name, "docker-tail", logs)
        lower = logs.lower()
        if "no space left" in lower or "enospc" in lower:
            self.event("HEAL", f"{name}: log indicates no space left; running disk guard")
            self.disk_guard()
        if "max virtual memory areas vm.max_map_count" in lower or "max_map_count" in lower:
            self.event("HEAL", f"{name}: log indicates vm.max_map_count issue")
            self.ensure_kernel()
        if "permission denied" in lower or "eacces" in lower:
            self.event("HEAL", f"{name}: permission issue detected in logs")
            self.fix_bind_permissions(name)
        if "database is uninitialized" in lower or "database system is starting up" in lower:
            self.event("WARN", f"{name}: database still initializing; delaying before restart")
            time.sleep(15)
        if "connection refused" in lower or "temporary failure in name resolution" in lower:
            self.event("WARN", f"{name}: dependency/network readiness issue detected")
            time.sleep(10)

    def wait_until_healthy(self, name: str, timeout: int = 90) -> bool:
        deadline = time.time() + timeout
        while time.time() < deadline:
            state = self.inspect_container(name)
            if state["status"] == "running" and state["health"] in ("healthy", "none"):
                self.event("OK", f"Container healthy after repair: {name}", **state)
                return True
            time.sleep(5)
        state = self.inspect_container(name)
        self.event("FAIL", f"Container still unhealthy after repair: {name}", **state)
        return False

    def heal_container(self, name: str) -> None:
        state = self.inspect_container(name)
        if state["exists"] != "true":
            self.event("HEAL", f"Container missing: {name}; attempting compose recreate")
            self.compose_up(name)
            self.wait_until_healthy(name)
            return
        self.event("OK", f"Container state: {name}", **state)
        if state.get("oom") == "true":
            self.event("HEAL", f"{name}: OOM kill detected; running disk/memory guard before restart", **state)
            self.disk_guard()
            self.memory_guard()
        try:
            restarts = int(state.get("restarts") or "0")
        except ValueError:
            restarts = 0
        if restarts >= 5:
            self.event("WARN", f"{name}: high restart count detected", restarts=restarts)
        if state["status"] == "running" and state["health"] in ("healthy", "none"):
            if name == "n8n":
                self.heal_n8n_workflows()
            return
        code, logs = docker_cmd(["logs", "--tail", "80", name], timeout=20)
        if code == 0 and logs:
            self.classify_and_repair_logs(name, logs)
        self.remove_dead_container(name, state)
        if state["status"] in {"created", "exited", "dead"}:
            self.compose_up(name)
            self.wait_until_healthy(name)
            return
        self.event("HEAL", f"Restarting container: {name}")
        docker_cmd(["restart", name], timeout=90)
        if self.wait_until_healthy(name) and name == "n8n":
            self.heal_n8n_workflows()

    def n8n_export_workflows(self) -> list[dict[str, Any]]:
        code, output = docker_cmd(
            [
                "exec",
                "-u",
                "node",
                "n8n",
                "sh",
                "-lc",
                "rm -f /tmp/tguard_selfheal_export.json; n8n export:workflow --all --output=/tmp/tguard_selfheal_export.json >/tmp/tguard_selfheal_export.log 2>&1; cat /tmp/tguard_selfheal_export.json",
            ],
            timeout=120,
        )
        if code != 0:
            self.event("WARN", "n8n workflow export failed", output=output[-1200:])
            return []
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            self.event("WARN", "n8n workflow export returned invalid JSON", output=output[-1200:])
            return []
        if isinstance(payload, dict):
            data = payload.get("data", payload)
            if isinstance(data, dict):
                payload = data.get("workflows", data.get("results", []))
            else:
                payload = data
        if isinstance(payload, dict) and payload.get("name"):
            return [payload]
        if isinstance(payload, list):
            return [item for item in payload if isinstance(item, dict)]
        return []

    def n8n_import_templates(self) -> None:
        template_dir = self.root / "n8n" / "templates"
        if not template_dir.exists():
            self.event("WARN", "n8n template directory missing", path=str(template_dir))
            return
        container_dir = "/tmp/tguard-selfheal-import"
        docker_cmd(["exec", "n8n", "sh", "-lc", f"rm -rf {container_dir} && mkdir -p {container_dir}"], timeout=30)
        code, output = docker_cmd(["cp", f"{template_dir}/.", f"n8n:{container_dir}/"], timeout=120)
        if code != 0:
            self.event("FAIL", "n8n template copy failed", output=output[-1200:])
            return
        self.event("HEAL", "n8n importing bundled templates")
        code, output = docker_cmd(
            ["exec", "-u", "node", "n8n", "n8n", "import:workflow", "--separate", f"--input={container_dir}"],
            timeout=180,
        )
        self.event("OK" if code == 0 else "FAIL", "n8n template import result", output=output[-1200:])
        code2, output2 = docker_cmd(
            ["exec", "-u", "node", "n8n", "n8n", "update:workflow", "--all", "--active=true"],
            timeout=120,
        )
        self.event("OK" if code2 == 0 else "WARN", "n8n activate workflows result", output=output2[-1200:])

    def heal_n8n_workflows(self) -> None:
        workflows = self.n8n_export_workflows()
        names = {str(item.get("name", "")) for item in workflows}
        missing = [name for name in N8N_REQUIRED_WORKFLOWS if name not in names]
        if workflows and not missing:
            self.event("OK", "n8n workflows present and exported", workflow_count=len(workflows))
            return
        self.event("HEAL", "n8n workflow set incomplete; importing bundled templates", workflow_count=len(workflows), missing=missing)
        self.n8n_import_templates()
        docker_cmd(["restart", "n8n"], timeout=90)
        self.wait_until_healthy("n8n", timeout=120)
        workflows_after = self.n8n_export_workflows()
        names_after = {str(item.get("name", "")) for item in workflows_after}
        missing_after = [name for name in N8N_REQUIRED_WORKFLOWS if name not in names_after]
        self.event(
            "OK" if workflows_after and not missing_after else "WARN",
            "n8n workflow recovery recheck",
            workflow_count=len(workflows_after),
            missing=missing_after,
        )

    def compose_ps_snapshot(self) -> dict[str, str]:
        snapshots: dict[str, str] = {}
        seen: set[str] = set()
        for plan in self.repairs.values():
            stack_dir = plan["dir"]
            if stack_dir in seen:
                continue
            seen.add(stack_dir)
            directory = self.root / stack_dir
            code, output = compose_cmd(directory, ["ps"], timeout=60)
            snapshots[stack_dir] = output if code == 0 else f"ERROR({code}): {output}"
        return snapshots

    def collect_incident_bundle(self, containers: list[str], reason: str) -> None:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        bundle = self.log_dir / f"selfheal-incident-{stamp}.zip"
        self.event("HEAL", "Collecting incident bundle", path=str(bundle), reason=reason)
        with zipfile.ZipFile(bundle, "w", compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr("reason.txt", reason)
            archive.writestr("events.json", json.dumps(self.events, indent=2))
            archive.writestr("redacted-env.json", json.dumps(self.redacted_env_snapshot(), indent=2))
            for label, cmd in {
                "docker-info.txt": sudo_cmd(["docker", "info"]),
                "docker-ps.txt": sudo_cmd(["docker", "ps", "-a"]),
                "docker-networks.txt": sudo_cmd(["docker", "network", "ls"]),
                "df.txt": ["df", "-h"],
                "free.txt": ["free", "-m"],
                "uname.txt": ["uname", "-a"],
            }.items():
                code, output = run(cmd, timeout=45)
                archive.writestr(label, output if code == 0 else f"ERROR({code}): {output}")
            archive.writestr("compose-ps.json", json.dumps(self.compose_ps_snapshot(), indent=2))
            for name in containers:
                code, output = docker_cmd(["inspect", name], timeout=30)
                archive.writestr(f"containers/{name}/inspect.json", output if code == 0 else f"ERROR({code}): {output}")
                code, output = docker_cmd(["logs", "--tail", "250", name], timeout=30)
                archive.writestr(f"containers/{name}/logs.txt", output if code == 0 else f"ERROR({code}): {output}")
        self.event("OK", "Incident bundle ready", path=str(bundle))

    def port_owner_pids(self, port: int) -> list[str]:
        if shutil.which("lsof"):
            code, output = run(sudo_cmd(["lsof", "-ti", f":{port}"]), timeout=10)
            if code == 0:
                return [line.strip() for line in output.splitlines() if line.strip()]
        return []

    def release_foreign_port(self, port: int) -> None:
        pids = self.port_owner_pids(port)
        if not pids:
            return
        for pid in pids:
            code, output = run(["ps", "-p", pid, "-o", "comm="], timeout=5)
            proc = output.strip() if code == 0 else "unknown"
            if proc in {"docker-proxy", "dockerd"}:
                continue
            self.event("HEAL", f"Releasing foreign process on port {port}", pid=pid, process=proc)
            run(sudo_cmd(["kill", "-TERM", pid]), timeout=5)
        time.sleep(2)
        for pid in self.port_owner_pids(port):
            code, output = run(["ps", "-p", pid, "-o", "comm="], timeout=5)
            proc = output.strip() if code == 0 else "unknown"
            if proc not in {"docker-proxy", "dockerd"}:
                self.event("HEAL", f"Force releasing stubborn process on port {port}", pid=pid, process=proc)
                run(sudo_cmd(["kill", "-KILL", pid]), timeout=5)

    def recover_endpoint(self, label: str, port: int, containers: list[str]) -> None:
        self.release_foreign_port(port)
        for container in containers:
            self.heal_container(container)

    def endpoint_checks(self) -> None:
        for label, url, ok_codes, port, containers in ENDPOINTS:
            status = http_status(url)
            ok = status in ok_codes
            self.event("OK" if ok else "WARN", f"Endpoint {label}: HTTP {status}", url=url)
            if ok:
                continue
            self.recover_endpoint(label, port, containers)
            status_after = http_status(url)
            ok_after = status_after in ok_codes
            self.event("OK" if ok_after else "FAIL", f"Endpoint recheck {label}: HTTP {status_after}", url=url)

    def port_checks(self) -> None:
        for port in CRITICAL_PORTS:
            self.event("OK" if port_open("127.0.0.1", port) else "WARN", f"Local port {port} check")

    def recovery_pass(self, containers: list[str], pass_no: int) -> None:
        self.event("OK", f"Recovery pass {pass_no} started", containers=containers)
        if pass_no == 1:
            self.stack_repair_pass(containers)
        for name in containers:
            self.heal_container(name)
        self.endpoint_checks()
        self.port_checks()
        self.event("OK", f"Recovery pass {pass_no} finished")

    def run(self, containers: list[str]) -> int:
        self.log_dir.mkdir(parents=True, exist_ok=True)
        targets = self.expand_targets(containers)
        docker_ok = self.ensure_docker()
        if docker_ok:
            self.system_prerequisites()
            code, output = docker_cmd(["ps", "-a", "--format", "table {{.Names}}\t{{.Status}}\t{{.Ports}}"], timeout=20)
            if code == 0:
                self.evidence_file("docker", "ps", output)
        self.disk_guard()
        before = self.emit_health_score("before", targets) if docker_ok else {"score": 0}
        if docker_ok:
            max_passes = 3 if self.deep else 2
            best_score = float(before["score"])
            for pass_no in range(1, max_passes + 1):
                self.recovery_pass(targets, pass_no)
                current = self.emit_health_score(f"after-pass-{pass_no}", targets)
                current_score = float(current["score"])
                previous_best = best_score
                best_score = max(best_score, current_score)
                if current_score >= 100:
                    self.event("OK", "All monitored checks are healthy; stopping recovery loop")
                    break
                if current_score <= previous_best and pass_no > 1:
                    self.event("WARN", "Health score stopped improving; preserving evidence and stopping bounded recovery")
                    break
            self.final_score = best_score
            if best_score < 100 or any(item["level"] == "FAIL" for item in self.events):
                self.collect_incident_bundle(targets, reason=f"final health score {best_score}%")
        else:
            self.collect_incident_bundle(targets, reason="docker daemon unavailable")
        if self.min_score and self.final_score < self.min_score:
            self.event(
                "FAIL",
                "Health gate failed",
                final_score=self.final_score,
                min_score=self.min_score,
            )
        return self.write_report()

    def write_report(self) -> int:
        stamp = time.strftime("%Y%m%d-%H%M%S")
        report = self.log_dir / f"selfheal-{stamp}.json"
        summary = {
            "HEAL": sum(1 for item in self.events if item["level"] == "HEAL"),
            "WARN": sum(1 for item in self.events if item["level"] == "WARN"),
            "FAIL": sum(1 for item in self.events if item["level"] == "FAIL"),
        }
        self.event("OK", f"Self-heal report written: {report}", **summary)
        report.write_text(json.dumps(self.events, indent=2), encoding="utf-8")
        return 1 if any(item["level"] == "FAIL" for item in self.events) else 0


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--log-dir", default="")
    parser.add_argument("--container", action="append", default=[])
    parser.add_argument("--deep", action="store_true")
    parser.add_argument("--min-score", type=float, default=0.0)
    args = parser.parse_args()

    root = Path(args.root).resolve()
    log_dir = Path(args.log_dir).resolve() if args.log_dir else root / "logs"
    containers = args.container or DEFAULT_CONTAINERS
    return Healer(root, log_dir, deep=args.deep, min_score=args.min_score).run(containers)


if __name__ == "__main__":
    raise SystemExit(main())
