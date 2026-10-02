#!/usr/bin/env python3
"""
Dump the Windows opensource LogiMX agent process for later Flow session-key scanning.

Use this when pairing/reconnect already happened and you want to recover keys
that are still present in process memory.

Usage:
  python tools/dump_windows_logi_memory.py
  python tools/dump_windows_logi_memory.py --name after_pairing
  python tools/dump_windows_logi_memory.py --pid 1234

Then extract keys against a packet capture:
  python tools/flow_crypto.py extract-keys captures/<session>/<session>.pcapng \\
    --dump dumps/<dump_session>/<dump_session>.<pid>.dmp \\
    --out captures/<session>/session_keys.json
"""

from __future__ import annotations

import argparse
import fnmatch
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_VERSION = "2026-05-19.3-direct-rundll32"
DEFAULT_PATTERNS = ["opensourceLogiMX", "opensourceLogiMX"]
AUXILIARY_PROCESS_NAMES = {"opensourceLogiMX_appbroker", "opensourceLogiMX_updater"}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def repo_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    return script_dir.parent if script_dir.name == "tools" else script_dir


def resolve_root_path(path_value: str, default_relative: str) -> Path:
    if not path_value:
        return repo_root() / default_relative
    path = Path(path_value)
    if path.is_absolute():
        return path
    return repo_root() / path


def run_powershell_json(command: str) -> object:
    result = subprocess.run(
        [
            "powershell",
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-Command",
            command,
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        die(result.stderr.strip() or result.stdout.strip() or "PowerShell command failed")
    output = result.stdout.strip()
    if not output:
        return []
    return json.loads(output)


def list_processes() -> list[dict[str, object]]:
    command = (
        "Get-Process | "
        "Select-Object Id,ProcessName,Path | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    data = run_powershell_json(command)
    if isinstance(data, dict):
        return [data]
    return list(data)


def select_process_id(pid: int, patterns: list[str]) -> int:
    if pid > 0:
        return pid

    processes = list_processes()
    for pattern in patterns:
        needle = pattern.lower()
        process_names = [str(proc.get("ProcessName", "")).lower() for proc in processes]
        exact_matches = [proc for proc, name in zip(processes, process_names) if name == needle]
        matches = exact_matches or [
            proc
            for proc, name in zip(processes, process_names)
            if name not in AUXILIARY_PROCESS_NAMES and fnmatch.fnmatch(name, f"*{needle}*")
        ]
        if matches:
            return int(sorted(matches, key=lambda item: int(item["Id"]))[-1]["Id"])

    joined = ", ".join(patterns)
    die(f"no Logi process found; pass --pid or --pattern. Default patterns: {joined}")


def get_process_info(pid: int) -> dict[str, object]:
    command = (
        f"Get-Process -Id {pid} -ErrorAction Stop | "
        "Select-Object Id,ProcessName,Path | "
        "ConvertTo-Json -Depth 3 -Compress"
    )
    data = run_powershell_json(command)
    if not isinstance(data, dict):
        die(f"could not read process info for pid {pid}")
    return {
        "pid": int(data.get("Id", pid)),
        "processName": data.get("ProcessName", ""),
        "path": data.get("Path", ""),
    }


def windows_path(path: Path) -> str:
    return str(path)


def write_metadata(path: Path, metadata: dict[str, object]) -> None:
    path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")


def dump_process(args: argparse.Namespace) -> int:
    if os.name != "nt":
        die("this script must run on Windows")

    target_pid = select_process_id(args.pid, args.pattern)
    process_info = get_process_info(target_pid)
    session = args.name or f"flow_win_dump_{stamp()}"
    dumps_root = resolve_root_path(args.dumps_dir, "dumps")
    out_dir = dumps_root / session
    out_dir.mkdir(parents=True, exist_ok=True)

    dump_path = out_dir / f"{session}.{target_pid}.dmp"
    metadata_path = out_dir / "dump_metadata.json"
    windir = os.environ.get("WINDIR", r"C:\Windows")
    rundll32 = str(Path(windir) / "System32" / "rundll32.exe")
    comsvcs = str(Path(windir) / "System32" / "comsvcs.dll")
    command = [
        rundll32,
        f"{comsvcs},",
        "MiniDump",
        str(target_pid),
        windows_path(dump_path),
        "full",
    ]

    metadata: dict[str, object] = {
        "session": session,
        "host": os.environ.get("COMPUTERNAME", "unknown"),
        "started": utc_now(),
        "script_version": SCRIPT_VERSION,
        "pid": target_pid,
        "process": process_info,
        "dump": windows_path(dump_path),
        "command": command,
    }
    write_metadata(metadata_path, metadata)

    print(f"target pid={target_pid} process={process_info.get('processName')}")
    print(f"writing {dump_path}")
    print("warning: MiniDumpWriteDump can briefly pause the target process")

    if args.dry_run:
        print(f"would run: {' '.join(command)}")
        return 0

    completed = subprocess.run(command)
    status = completed.returncode

    metadata["ended"] = utc_now()
    metadata["size"] = dump_path.stat().st_size if dump_path.exists() else 0
    metadata["status"] = status if metadata["size"] else 1
    write_metadata(metadata_path, metadata)

    print(f"dump status={metadata['status']} size={metadata['size']} bytes")
    print(f"metadata {metadata_path}")
    return int(metadata["status"])


def main() -> int:
    parser = argparse.ArgumentParser(description="Dump Windows opensource LogiMX process memory")
    parser.add_argument("--pid", "--target-process-id", type=int, default=0, help="Target process id")
    parser.add_argument(
        "--pattern",
        action="append",
        default=[],
        help="Process name pattern; repeatable. Default: opensourceLogiMX",
    )
    parser.add_argument("--name", default="", help="Dump session name")
    parser.add_argument("--dumps-dir", default="", help="Dump root directory; default: dumps")
    parser.add_argument("--dry-run", action="store_true", help="Resolve target and print command only")
    args = parser.parse_args()
    if not args.pattern:
        args.pattern = DEFAULT_PATTERNS
    return dump_process(args)


if __name__ == "__main__":
    raise SystemExit(main())
