#!/usr/bin/env python3
"""
Capture Logitech Flow packets without trapping a new session key.

Use this when you already have a valid session key from a previous
capture_flow_session.py run and only need fresh traffic to decrypt.

Usage:
  python tools/capture_flow_packets.py --peer 192.168.7.27 --name live_test
  python tools/capture_flow_packets.py --peer 192.168.7.27 --name live_test --duration 60

Output:
  captures/<name>/<name>.pcapng
  captures/<name>/capture_metadata.json

Decrypt later:
  python tools/flow_crypto.py decrypt captures/<name>/<name>.pcapng \\
    --keys-file captures/<previous>/session_keys.json \\
    --outdir decrypted/<name>
"""

from __future__ import annotations

import argparse
import glob
import json
import os
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path


SCRIPT_VERSION = "2026-05-19.1-capture-only"
DUMPCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def die(message: str) -> None:
    print(f"ERROR: {message}", file=sys.stderr)
    raise SystemExit(1)


def find_exe(candidates: list[str]) -> str | None:
    for pattern in candidates:
        for match in glob.glob(pattern):
            if os.path.isfile(match):
                return match
        if os.path.isfile(pattern):
            return pattern
    found = shutil_which("dumpcap.exe")
    return found


def shutil_which(name: str) -> str | None:
    for entry in os.environ.get("PATH", "").split(os.pathsep):
        candidate = os.path.join(entry, name)
        if os.path.isfile(candidate):
            return candidate
    return None


def repo_root() -> Path:
    script_dir = Path(__file__).resolve().parent
    return script_dir.parent if script_dir.name == "tools" else script_dir


def auto_interface(dumpcap: str) -> str:
    result = subprocess.run([dumpcap, "-D"], capture_output=True, text=True)
    if result.returncode != 0:
        die(f"dumpcap -D failed: {result.stderr.strip()}")

    lines = result.stdout.splitlines()
    for line in lines:
        if "Wi-Fi" in line or "WiFi" in line:
            return line.split(".", 1)[0].strip()

    ignored = ("loopback", "bluetooth", "npcap", "local area connection*")
    for line in lines:
        if not any(word in line.lower() for word in ignored):
            return line.split(".", 1)[0].strip()

    die("No suitable capture interface found. Run dumpcap -D and pass --interface.")


def build_filter(peer: str) -> str:
    flow_filter = "(tcp port 59869 or udp port 59870 or udp port 59871)"
    if peer:
        return f"host {peer} and {flow_filter}"
    return flow_filter


def run_capture(args: argparse.Namespace) -> int:
    dumpcap = args.dumpcap or find_exe(DUMPCAP_CANDIDATES)
    if not dumpcap:
        die("dumpcap.exe not found. Install Wireshark or pass --dumpcap.")

    session = args.name or f"flow_packets_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    root = repo_root()
    session_dir = root / "captures" / session
    session_dir.mkdir(parents=True, exist_ok=True)

    iface = args.interface or auto_interface(dumpcap)
    capture_filter = build_filter(args.peer)
    pcap_path = session_dir / f"{session}.pcapng"
    metadata_path = session_dir / "capture_metadata.json"

    command = [dumpcap, "-i", iface, "-s", "0", "-w", str(pcap_path), "-f", capture_filter]
    if args.duration > 0:
        command.extend(["-a", f"duration:{args.duration}"])

    metadata = {
        "session": session,
        "host": os.environ.get("COMPUTERNAME", "unknown"),
        "started": utc_now(),
        "script_version": SCRIPT_VERSION,
        "interface": iface,
        "peer": args.peer,
        "duration": args.duration,
        "session_dir": str(session_dir),
        "pcap": str(pcap_path),
        "filter": capture_filter,
        "command": command,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print("=" * 60)
    print("  Logitech Flow Packet Capture")
    print("=" * 60)
    print(f"  Version:   {SCRIPT_VERSION}")
    print(f"  Session:   {session}")
    print(f"  Interface: {iface}")
    print(f"  Filter:    {capture_filter}")
    print(f"  Capture:   {pcap_path}")
    print("=" * 60)
    sys.stdout.flush()

    proc = subprocess.Popen(command)
    try:
        proc.wait()
    except KeyboardInterrupt:
        print("\n[!] Stopping capture...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()

    metadata["ended"] = utc_now()
    metadata["capture_size"] = pcap_path.stat().st_size if pcap_path.exists() else 0
    metadata["exit_code"] = proc.returncode
    metadata_path.write_text(json.dumps(metadata, indent=2), encoding="utf-8")

    print()
    print("=" * 60)
    print("  Results")
    print("=" * 60)
    print(f"  Capture: {pcap_path} ({metadata['capture_size']} bytes)")
    print(f"  Metadata: {metadata_path}")
    print()
    print("  Next:")
    print(f"    python tools\\flow_crypto.py keyids captures\\{session}\\{session}.pcapng")
    print(
        f"    python tools\\flow_crypto.py decrypt captures\\{session}\\{session}.pcapng "
        f"--keys-file captures\\<previous>\\session_keys.json --outdir decrypted\\{session}"
    )
    print("=" * 60)
    return proc.returncode or 0


def main() -> int:
    parser = argparse.ArgumentParser(description="Capture Logitech Flow packets without CDB/key trapping")
    parser.add_argument("--peer", default="", help="IP address of Flow peer to filter capture")
    parser.add_argument("--name", default="", help="Session name (default: auto-generated)")
    parser.add_argument("--duration", type=int, default=0, help="Capture duration in seconds; 0 means until Ctrl+C")
    parser.add_argument("--interface", default="", help="Dumpcap interface index (auto-detect Wi-Fi)")
    parser.add_argument("--dumpcap", default="", help="Path to dumpcap.exe")
    return run_capture(parser.parse_args())


if __name__ == "__main__":
    raise SystemExit(main())
