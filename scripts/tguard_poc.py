#!/usr/bin/env python3
"""Deterministic T-Guard PoC runner.

Runs safe, local proof-of-concept events that Wazuh can observe:
- SSH failed-login attempts without prompting for passwords.
- EICAR test file creation in watched directories.
- Web defacement file replacement in the configured usecase directory.
"""

from __future__ import annotations

import argparse
import os
import shutil
import socket
import subprocess
import sys
import time
from pathlib import Path


EICAR = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"


def run(cmd: list[str], timeout: int = 15) -> int:
    try:
        return subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=timeout).returncode
    except Exception:
        return 1


def primary_ip() -> str:
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.connect(("1.1.1.1", 80))
        ip = sock.getsockname()[0]
        sock.close()
        return ip
    except Exception:
        return "127.0.0.1"


def write_file(path: Path, content: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8")


def brute_force(target: str, attempts: int) -> bool:
    print(f"[POC] SSH brute force simulation target={target} attempts={attempts}")
    for index in range(1, attempts + 1):
        run(
            [
                "ssh",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "ConnectTimeout=3",
                f"fakeuser_tguard_{index}@{target}",
            ],
            timeout=6,
        )
        print(f"[POC] brute attempt {index}/{attempts}")
        time.sleep(0.5)
    return True


def malware(root: Path, watched_dir: Path) -> bool:
    targets = [
        Path("/root/eicar.com"),
        watched_dir / "eicar.com",
        watched_dir / "uploads" / "eicar-sample.txt",
    ]
    print("[POC] Creating EICAR test files in watched paths")
    for target in targets:
        try:
            write_file(target, EICAR + "\n")
            print(f"[POC] wrote {target}")
        except PermissionError:
            fallback = root / "usecase" / "webdeface" / target.name
            write_file(fallback, EICAR + "\n")
            print(f"[POC] wrote fallback {fallback}")
    return True


def webdeface(watched_dir: Path, recover: bool) -> bool:
    index = watched_dir / "index.html"
    original = watched_dir / "index_ori.html"
    defaced = watched_dir / "webdeface.html"
    backup = watched_dir / f"index.html.tguard-backup-{int(time.time())}"

    if not index.exists() or not defaced.exists():
        print(f"[FAIL] missing webdeface files in {watched_dir}", file=sys.stderr)
        return False

    shutil.copy2(index, backup)
    shutil.copy2(defaced, index)
    os.utime(index, None)
    print(f"[POC] defaced {index}")
    print(f"[POC] backup saved {backup}")

    if recover:
        time.sleep(2)
        source = original if original.exists() else backup
        shutil.copy2(source, index)
        os.utime(index, None)
        print(f"[POC] recovered {index}")

    return True


def write_report(root: Path, lines: list[str]) -> None:
    report = root / "usecase" / "poc-last-run.log"
    report.parent.mkdir(parents=True, exist_ok=True)
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"[POC] report: {report}")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--root", default=str(Path(__file__).resolve().parents[1]))
    parser.add_argument("--scenario", choices=["bruteforce", "malware", "webdeface", "all"], default="all")
    parser.add_argument("--target-ip", default="")
    parser.add_argument("--attempts", type=int, default=10)
    parser.add_argument("--no-recover", action="store_true")
    args = parser.parse_args()

    root = Path(args.root).resolve()
    watched_dir = root / "usecase" / "webdeface"
    target = args.target_ip or primary_ip()
    ran: list[str] = []

    ok = True
    if args.scenario in ("bruteforce", "all"):
        ok = brute_force(target, args.attempts) and ok
        ran.append("bruteforce")
    if args.scenario in ("malware", "all"):
        ok = malware(root, watched_dir) and ok
        ran.append("malware")
    if args.scenario in ("webdeface", "all"):
        ok = webdeface(watched_dir, recover=not args.no_recover) and ok
        ran.append("webdeface")

    write_report(
        root,
        [
            f"time={time.strftime('%Y-%m-%dT%H:%M:%S%z')}",
            f"root={root}",
            f"watched_dir={watched_dir}",
            f"target_ip={target}",
            f"scenarios={','.join(ran)}",
            f"status={'ok' if ok else 'failed'}",
        ],
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
