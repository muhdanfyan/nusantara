#!/usr/bin/env python3
"""Read-only cloud/VM readiness doctor for T-Guard installs."""

from __future__ import annotations

import argparse
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any


REQUIRED_PORTS = [80, 443, 1443, 5679, 1514, 1515, 55000]
INTERNAL_ONLY_PORTS = [9200]
MIN_CPU = 2
MIN_RAM_GB = 6
MIN_DISK_GB = 60


def run(cmd: list[str], timeout: int = 8) -> tuple[int, str]:
    try:
        proc = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return proc.returncode, proc.stdout.strip()
    except Exception as exc:  # noqa: BLE001
        return 127, str(exc)


def parse_env_file(path: Path) -> dict[str, str]:
    values: dict[str, str] = {}
    if not path.exists():
        return values
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[len("export ") :].strip()
        if "=" not in line:
            continue
        key, value = line.split("=", 1)
        values[key.strip()] = value.strip().strip('"').strip("'")
    return values


def read_text(path: str) -> str:
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace").strip()
    except Exception:
        return ""


def os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    path = Path("/etc/os-release")
    if not path.exists():
        return data
    for raw in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if "=" not in raw:
            continue
        key, value = raw.split("=", 1)
        data[key] = value.strip().strip('"')
    return data


def detect_private_ip() -> str:
    if os.name != "nt":
        code, output = run(["ip", "-4", "route", "get", "1.1.1.1"], timeout=4)
        if code == 0 and " src " in f" {output} ":
            parts = output.split()
            for idx, item in enumerate(parts):
                if item == "src" and idx + 1 < len(parts):
                    return parts[idx + 1]
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except OSError:
        return ""


def detect_public_ip(timeout: float = 3.0) -> str:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip", "https://ipinfo.io/ip"):
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "tguard-env-doctor/1"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                ip = resp.read().decode("utf-8", errors="replace").strip()
            if ip.count(".") == 3:
                return ip
        except Exception:
            continue
    return ""


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


def dmi_snapshot() -> dict[str, str]:
    return {
        "product": read_text("/sys/class/dmi/id/product_name"),
        "vendor": read_text("/sys/class/dmi/id/sys_vendor"),
        "chassis_vendor": read_text("/sys/class/dmi/id/chassis_vendor"),
    }


def detect_platform() -> dict[str, Any]:
    dmi = dmi_snapshot()
    joined = " ".join(dmi.values()).lower()
    code, virt = run(["systemd-detect-virt"], timeout=4) if shutil.which("systemd-detect-virt") else (127, "")
    virt_l = virt.lower()
    is_virtualbox = "virtualbox" in joined or "oracle" in virt_l or "virtualbox" in virt_l
    cloud_markers = [
        "google",
        "compute engine",
        "digitalocean",
        "droplet",
        "amazon ec2",
        "microsoft corporation",
        "azure",
        "oraclecloud",
        "openstack",
        "hetzner",
        "vultr",
        "linode",
        "hostinger",
        "kvm",
        "qemu",
    ]
    is_cloud = any(marker in joined or marker in virt_l for marker in cloud_markers) and not is_virtualbox
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "virtualization": virt if code == 0 else "",
        "dmi": dmi,
        "is_virtualbox": is_virtualbox,
        "is_public_cloud_or_vps": is_cloud,
    }


def meminfo() -> dict[str, int]:
    values: dict[str, int] = {}
    path = Path("/proc/meminfo")
    if not path.exists():
        return values
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        parts = line.split()
        if len(parts) >= 2 and parts[1].isdigit():
            values[parts[0].rstrip(":")] = int(parts[1])
    return values


def tcp_open(host: str, port: int, timeout: float = 0.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def command_matrix() -> dict[str, bool]:
    commands = ["python3", "curl", "git", "docker", "docker-compose", "jq", "whiptail", "ufw", "systemctl"]
    matrix = {cmd: shutil.which(cmd) is not None for cmd in commands}
    if matrix["docker"]:
        code, output = run(["docker", "compose", "version"], timeout=8)
        matrix["docker_compose_plugin"] = code == 0
        matrix["docker_daemon_ready"] = run(["docker", "info"], timeout=8)[0] == 0
        matrix["docker_compose_available"] = matrix["docker-compose"] or matrix["docker_compose_plugin"]
    else:
        matrix["docker_compose_plugin"] = False
        matrix["docker_daemon_ready"] = False
        matrix["docker_compose_available"] = False
    return matrix


def dns_ok(host: str) -> bool:
    try:
        socket.gethostbyname(host)
        return True
    except OSError:
        return False


def build_report(root: Path, phase: str) -> dict[str, Any]:
    config = parse_env_file(root / ".tguard.env")
    network_mode = os.environ.get("TGUARD_NETWORK_MODE") or config.get("TGUARD_NETWORK_MODE") or "auto"
    platform_info = detect_platform()
    release = os_release()
    mem = meminfo()
    private_ip = detect_private_ip()
    public_ip = detect_public_ip()
    disk = shutil.disk_usage(str(root if root.exists() else Path.cwd()))
    cpu_count = os.cpu_count() or 0
    ram_gb = round(mem.get("MemTotal", 0) / 1024 / 1024, 2) if mem else 0
    swap_gb = round(mem.get("SwapTotal", 0) / 1024 / 1024, 2) if mem else 0
    disk_free_gb = round(disk.free / 1024 / 1024 / 1024, 2)
    selected_ip = public_ip if network_mode == "public" else private_ip
    if network_mode == "auto" and platform_info["is_public_cloud_or_vps"] and public_ip:
        selected_ip = public_ip

    port_conflicts = {str(port): tcp_open("127.0.0.1", port) for port in REQUIRED_PORTS + INTERNAL_ONLY_PORTS}
    commands = command_matrix()
    checks = {
        "os_linux": platform.system() == "Linux",
        "os_ubuntu_or_debian": "ubuntu" in f"{release.get('ID', '')} {release.get('ID_LIKE', '')}".lower()
        or "debian" in f"{release.get('ID', '')} {release.get('ID_LIKE', '')}".lower(),
        "cpu_minimum": cpu_count >= MIN_CPU,
        "ram_minimum": ram_gb >= MIN_RAM_GB,
        "disk_minimum": disk_free_gb >= MIN_DISK_GB,
        "dns_github": dns_ok("github.com"),
        "dns_docker": dns_ok("registry-1.docker.io"),
        "public_ip_available": bool(public_ip),
        "selected_ip_available": bool(selected_ip),
        "docker_compose_available": commands["docker_compose_available"] or phase == "preinstall",
    }

    notes: list[str] = []
    if platform_info["is_virtualbox"]:
        notes.append("VirtualBox detected: use Bridged Adapter or NAT port-forward for 443, 1443, 5679, 1514, 1515, 55000.")
    if network_mode == "public" or is_public_ipv4(selected_ip):
        notes.append("Public mode: open provider firewall/security group inbound TCP 443, 1443, 5679, 1514, 1515, 55000.")
        notes.append("Keep 9200 internal only; do not expose Wazuh indexer to the internet.")
    if phase == "preinstall":
        notes.append("Preinstall port checks report listeners as potential conflicts before T-Guard owns them.")
    if ram_gb and ram_gb < MIN_RAM_GB:
        notes.append("Low RAM: use TGUARD_SMART_MODE=safe or add swap before install.")
    if disk_free_gb < MIN_DISK_GB:
        notes.append("Low disk: use TGUARD_DOCKER_DATA_ROOT on a larger disk or expand the VPS volume.")
    if network_mode == "auto" and platform_info["is_public_cloud_or_vps"]:
        notes.append("Auto mode detected public cloud/VPS and will prefer public IP; explicit TGUARD_NETWORK_MODE=public is still safer.")

    ready = all(checks.values())
    severity = "ready" if ready else "warning"
    if not checks["os_linux"] or not checks["os_ubuntu_or_debian"] or not checks["selected_ip_available"]:
        severity = "blocked"

    return {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "phase": phase,
        "severity": severity,
        "ready": ready,
        "root": str(root),
        "network": {
            "mode": network_mode,
            "private_ip": private_ip,
            "public_ip": public_ip,
            "selected_ip": selected_ip,
            "selected_ip_is_public": is_public_ipv4(selected_ip),
        },
        "platform": platform_info,
        "os_release": release,
        "resources": {
            "cpu_count": cpu_count,
            "ram_gb": ram_gb,
            "swap_gb": swap_gb,
            "disk_free_gb": disk_free_gb,
            "minimums": {"cpu": MIN_CPU, "ram_gb": MIN_RAM_GB, "disk_free_gb": MIN_DISK_GB},
        },
        "commands": commands,
        "checks": checks,
        "ports_listening_before_install": port_conflicts,
        "provider_firewall_required_tcp": REQUIRED_PORTS,
        "internal_only_tcp": INTERNAL_ONLY_PORTS,
        "notes": notes,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--log-dir", default="")
    parser.add_argument("--phase", default="preinstall")
    parser.add_argument("--strict", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    report = build_report(root, args.phase)
    print(json.dumps(report, indent=2))
    if args.log_dir:
        log_dir = Path(args.log_dir).resolve()
        log_dir.mkdir(parents=True, exist_ok=True)
        out = log_dir / f"env-doctor-{args.phase}-{time.strftime('%Y%m%d-%H%M%S')}.json"
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    if args.strict and report["severity"] == "blocked":
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
