#!/usr/bin/env python3
"""
Logitech Flow capture orchestrator.

One-shot Windows script that:
  1. Starts dumpcap packet capture
  2. Attaches CDB to opensourceLogiMX to trap session key
  3. Waits for pairing (user prompted)
  4. Collects key + capture
  5. Produces decryptable output

Usage:
  python capture_flow_session.py [--peer <ip>] [--name <session>] [--timeout <secs>]

Output:
  captures/<name>/<name>.pcapng          - packet capture
  captures/<name>/flow_keys.log          - CDB key trap output
  captures/<name>/capture_metadata.json  - capture metadata
  captures/<name>/session_keys.json      - extracted session keys (ready for flow_crypto.py)

After .172 -> .241:
  python3 tools/flow_crypto.py decrypt captures/<name>/<name>.pcapng \\
    --key-log captures/<name>/flow_keys.log
"""

import argparse
import glob
import json
import os
import re
import signal
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Optional

# --- Configuration ---
SCRIPT_VERSION = "2026-05-19.3-single-session-dir"
TOOLS_DIR = os.path.dirname(os.path.abspath(__file__))
REPO_ROOT = os.path.dirname(TOOLS_DIR)

# CDB breakpoint offsets (opensource LogiMX)
DERIVE_ENTRY_OFFSET = "0x19b6ae0"
KEY_DUMP_OFFSET = "0x19b6e36"

# Known CDB paths
CDB_CANDIDATES = [
    r"C:\Temp\debuggers\cdb.exe",
    r"C:\Program Files\WindowsApps\Microsoft.WinDbg_*\amd64\cdb.exe",
]

# Dumpcap paths
DUMPCAP_CANDIDATES = [
    r"C:\Program Files\Wireshark\dumpcap.exe",
    r"C:\Program Files (x86)\Wireshark\dumpcap.exe",
]


def find_exe(candidates: list[str]) -> Optional[str]:
    """Find first existing executable from a list of patterns."""
    for pattern in candidates:
        matches = glob.glob(pattern)
        if matches:
            return matches[0]
        if os.path.isfile(pattern):
            return pattern
    return None


def find_process(name: str) -> Optional[int]:
    """Find PID of a running process by image name."""
    result = subprocess.run(
        ["tasklist", "/fi", f"imagename eq {name}", "/fo", "csv", "/nh"],
        capture_output=True, text=True, shell=True,
    )
    for line in result.stdout.strip().split("\n"):
        line = line.strip().strip('"')
        if line and name.lower() in line.lower():
            parts = [p.strip('"') for p in line.split(",")]
            if len(parts) >= 2:
                try:
                    return int(parts[1])
                except (ValueError, IndexError):
                    continue
    return None


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def die(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def has_real_key_dump(log: str) -> bool:
    """Return true only when the breakpoint actually printed a dump block.

    CDB echoes the breakpoint command into the log, so a plain substring check
    matches the literal `.echo ===KEY_DUMP===` command before pairing happens.
    The real trap prints markers on their own lines, with db output between them.
    """
    dump_line = re.compile(
        r"^[0-9a-fA-F`]+\s+"
        r"(?:[0-9a-fA-F]{2}(?:[\s-]+|$)){16,}"
    )
    lines = log.splitlines()
    for i, line in enumerate(lines):
        if line.strip() != "===KEY_DUMP===":
            continue
        saw_dump_line = False
        for inner in lines[i + 1:]:
            stripped = inner.strip()
            if stripped == "===KEY_END===":
                return saw_dump_line
            if stripped.startswith("0:") or stripped.startswith("bp "):
                return False
            # CDB db output starts with an address and at least 8 hex bytes.
            if dump_line.match(stripped):
                saw_dump_line = True
    return False


def main() -> None:
    parser = argparse.ArgumentParser(description="Logitech Flow capture orchestrator")
    parser.add_argument("--peer", default="", help="IP address of Flow peer to filter capture")
    parser.add_argument("--name", default="", help="Session name (default: auto-generated)")
    parser.add_argument("--timeout", type=int, default=300, help="Max seconds to wait for pair (default: 300)")
    parser.add_argument("--interface", default="", help="Dumpcap interface index (auto-detect WiFi)")
    parser.add_argument("--cdb", default="", help="Path to cdb.exe")
    parser.add_argument("--dumpcap", default="", help="Path to dumpcap.exe")
    args = parser.parse_args()

    # --- Validate ---
    session_name = args.name or f"flow_capture_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    
    # Resolve repo root from this script's location
    script_dir = os.path.dirname(os.path.abspath(__file__))
    repo_root = os.path.dirname(script_dir) if os.path.basename(script_dir) == "tools" else script_dir
    session_dir = os.path.join(repo_root, "captures", session_name)
    os.makedirs(session_dir, exist_ok=True)

    dumpcap = args.dumpcap or find_exe(DUMPCAP_CANDIDATES)
    if not dumpcap:
        die("dumpcap.exe not found. Install Wireshark or pass --dumpcap.")

    cdb = args.cdb or find_exe(CDB_CANDIDATES)
    if not cdb:
        die("cdb.exe not found. Install WinDbg or pass --cdb.")

    agent_pid = find_process("opensourceLogiMX.exe")
    if not agent_pid:
        die("opensourceLogiMX.exe not running. Start opensource LogiMX first.")

    # --- Interface detection ---
    iface = args.interface
    if not iface:
        result = subprocess.run([dumpcap, "-D"], capture_output=True, text=True)
        for line in result.stdout.splitlines():
            if "Wi-Fi" in line:
                iface = line.split(".")[0].strip()
                break
        if not iface:
            for line in result.stdout.splitlines():
                if not any(x in line.lower() for x in ("loopback", "bluetooth", "local area connection*")):
                    parts = line.split(".")
                    if parts:
                        iface = parts[0].strip()
                        break
        if not iface:
            die("No suitable capture interface found. Run dumpcap -D and pass --interface.")

    # --- Capture filter ---
    flow_filter = "(tcp port 59869 or udp port 59870 or udp port 59871)"
    if args.peer:
        flow_filter = f"host {args.peer} and {flow_filter}"

    # --- CDB script ---
    cdb_script_path = os.path.join(session_dir, "cdb_script.txt")
    key_log_path = os.path.join(session_dir, "flow_keys.log")
    
    # Remove stale key log from previous runs
    if os.path.exists(key_log_path):
        os.remove(key_log_path)
    
    cdb_commands = (
        f'.logopen "{key_log_path}"\n'
        f'.sxn ibp\n'
        f'bp opensourceLogiMX+{DERIVE_ENTRY_OFFSET} ".echo ===DERIVE_ENTRY===; g"\n'
        f'bp opensourceLogiMX+{KEY_DUMP_OFFSET} ".echo ===KEY_DUMP===; db poi(@r14) L180; .echo ===KEY_END===; g"\n'
        ".echo TRAP_READY\n"
        "g\n"
    )
    with open(cdb_script_path, "w") as f:
        f.write(cdb_commands)

    # --- Pcap path ---
    pcap_path = os.path.join(session_dir, f"{session_name}.pcapng")

    # --- Metadata ---
    metadata = {
        "session": session_name,
        "host": os.environ.get("COMPUTERNAME", "unknown"),
        "started": utc_now(),
        "agent_pid": agent_pid,
        "cdb": cdb,
        "dumpcap": dumpcap,
        "interface": iface,
        "peer": args.peer,
        "filter": flow_filter,
        "pcap": pcap_path,
        "key_log": key_log_path,
        "offsets": {
            "derive_entry": DERIVE_ENTRY_OFFSET,
            "key_dump": KEY_DUMP_OFFSET,
        },
    }

    # --- Start capture ---
    print("=" * 60)
    print("  Logitech Flow Capture Orchestrator")
    print("=" * 60)
    print(f"  Version:   {SCRIPT_VERSION}")
    print(f"  Session:   {session_name}")
    print(f"  Agent PID: {agent_pid}")
    print(f"  Interface: {iface}")
    print(f"  Filter:    {flow_filter}")
    print(f"  Capture:   {pcap_path}")
    print(f"  Key log:   {key_log_path}")
    print("=" * 60)

    dumpcap_proc = subprocess.Popen(
        [dumpcap, "-i", iface, "-s", "0", "-w", pcap_path, "-f", flow_filter],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(2)
    if dumpcap_proc.poll() is not None:
        die("dumpcap failed to start. Check interface and permissions.")

    metadata["capture_started"] = utc_now()
    print("[*] Packet capture started.")

    # --- Attach CDB ---
    try:
        cdb_proc = subprocess.Popen(
            [cdb, "-p", str(agent_pid), "-cf", cdb_script_path],
            stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, stdin=subprocess.DEVNULL,
        )
        time.sleep(4)
        if cdb_proc.poll() is not None:
            _, stderr_data = cdb_proc.communicate(timeout=3)
            err_msg = stderr_data.decode("latin1", errors="replace").strip()[:300] if stderr_data else ""
            dumpcap_proc.terminate()
            dumpcap_proc.wait(timeout=3)
            die(f"CDB exited immediately ({cdb_proc.returncode}). Run this script as Administrator.\n{err_msg}")
    except Exception as e:
        dumpcap_proc.terminate()
        dumpcap_proc.wait(timeout=3)
        die(f"CDB error: {e}")

    metadata["cdb_attached"] = utc_now()
    print("[*] CDB attached to opensourceLogiMX.", flush=True)
    print(flush=True)
    print("=" * 60, flush=True)
    print("  >>> PAIR NOW in opensource LogiMX <<<", flush=True)
    print(f"  Waiting up to {args.timeout}s for session key...", flush=True)
    print("=" * 60, flush=True)
    print(flush=True)

    # --- Wait for key trap ---
    deadline = time.time() + args.timeout
    key_trapped = False
    dots = 0

    while time.time() < deadline:
        time.sleep(1)
        dots += 1
        if dots % 10 == 0:
            elapsed = int(time.time() - (deadline - args.timeout))
            print(f"  [{elapsed}s] still waiting...", flush=True)
            
        if not os.path.exists(key_log_path):
            continue
        try:
            size = os.path.getsize(key_log_path)
            with open(key_log_path, "r", errors="replace") as f:
                log = f.read()
            if has_real_key_dump(log):
                key_trapped = True
                break
        except Exception:
            pass

        if cdb_proc.poll() is not None:
            print(f"[!] CDB exited with code {cdb_proc.returncode}", flush=True)
            time.sleep(2)
            break

    # --- Stop capture ---
    dumpcap_proc.terminate()
    dumpcap_proc.wait(timeout=5)
    metadata["capture_ended"] = utc_now()
    metadata["capture_size"] = os.path.getsize(pcap_path) if os.path.exists(pcap_path) else 0

    # --- Collect results ---
    if key_trapped:
        print()
        print("[+] Session key trapped successfully.")
        # Try to extract keys right away using the built-in extractor
        # Write session_keys.json
        key_log_exists = os.path.exists(key_log_path) and os.path.getsize(key_log_path) > 0
        metadata["key_trapped"] = True
        metadata["key_log_size"] = os.path.getsize(key_log_path) if key_log_exists else 0
    else:
        print()
        print("[!] Key trap did not fire within timeout.")
        print(f"    Check {key_log_path} — may need manual extraction.")
        metadata["key_trapped"] = False

    metadata["ended"] = utc_now()

    # Write metadata
    meta_path = os.path.join(session_dir, "capture_metadata.json")
    with open(meta_path, "w") as f:
        json.dump(metadata, f, indent=2)

    print()
    print("=" * 60)
    print("  Results")
    print("=" * 60)
    print(f"  Capture: {pcap_path} ({metadata['capture_size']} bytes)")
    print(f"  Key log: {key_log_path}")
    print(f"  Metadata: {meta_path}")
    print()
    print("  Next: copy to Linux and run:")
    print(f"    python3 tools/flow_crypto.py decrypt captures/{session_name}/{session_name}.pcapng \\")
    print(f"      --key-log captures/{session_name}/flow_keys.log")
    print("=" * 60)

    # CDB keeps running — user must kill manually
    if cdb_proc.poll() is None:
        print()
        print("[*] CDB still attached. To detach: taskkill /f /im cdb.exe")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        sys.exit(1)
