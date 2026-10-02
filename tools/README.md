# opensource LogiMX Tools

Utilities for capturing, decrypting, and inspecting LogiMX Flow traffic.

Run the Windows capture tools from a Windows checkout/workspace such as:

```cmd
cd C:\Temp\opensourceLogiMX
```

Run Linux-side analysis from the project root:

```bash
cd /mnt/Data/Projects/opensourceLogiMX
```

## Recommended Capture Flow

Use the one-shot capture when pairing or reconnecting and we need a decryptable
session:

```cmd
python tools\capture_flow_session.py --peer 192.168.1.20 --name receive_pairing
```

What it does:

1. Starts `dumpcap` for Flow TCP/UDP traffic.
2. Attaches CDB to `opensourceLogiMX`.
3. Waits while you perform pairing/reconnect.
4. Traps Flow session keys into `flow_keys.log`.
5. Writes capture metadata and extracted `session_keys.json`.

Output:

```text
captures/<name>/<name>.pcapng
captures/<name>/flow_keys.log
captures/<name>/capture_metadata.json
captures/<name>/session_keys.json
```

Then decrypt:

```bash
python3 tools/flow_crypto.py decrypt captures/<name>/<name>.pcapng \
  --key-log captures/<name>/flow_keys.log \
  --keys-file captures/<name>/session_keys.json \
  --outdir captures/<name>/decrypted
```

## Usage Examples

### Record a known-good Windows-to-Windows pairing

Run this on the Windows host that is starting the pairing. Start it before
clicking through the pairing flow, then stop only after Flow shows connected or
after it clearly fails.

```cmd
cd C:\Temp\opensourceLogiMX
python tools\capture_flow_session.py ^
  --peer 192.168.1.20 ^
  --name win172_to_win27_pairing ^
  --timeout 420
```

If auto-detection picks the wrong tools or interface, pass them explicitly:

```cmd
python tools\capture_flow_session.py ^
  --peer 192.168.1.20 ^
  --name win172_to_win27_pairing ^
  --interface 5 ^
  --cdb C:\Temp\debuggers\cdb.exe ^
  --dumpcap "C:\Program Files\Wireshark\dumpcap.exe"
```

### Record a failing Windows-to-Linux pairing

Run this on the Windows host before starting the pairing attempt against the
Linux daemon. Keep the capture running for roughly 30 seconds after the final
Settings packet or after Windows reports failure.

```cmd
cd C:\Temp\opensourceLogiMX
python tools\capture_flow_session.py ^
  --peer 192.168.1.10 ^
  --name win_to_linux_pairing_fail ^
  --timeout 420
```

On Linux, keep daemon logs line-buffered in a separate shell so the capture and
server-side state can be compared later:

```bash
cd /mnt/Data/Projects/opensourceLogiMX/Linux
nohup stdbuf -oL -eL ./build/logi-flow-cli daemon \
  --flow-device /dev/hidraw10 \
  > /tmp/flow_pairing.log 2>&1 &
```

### Decrypt a captured session

Run from the project root on Linux:

```bash
cd /mnt/Data/Projects/opensourceLogiMX
python3 tools/flow_crypto.py decrypt \
  captures/win172_to_win27_pairing/win172_to_win27_pairing.pcapng \
  --key-log captures/win172_to_win27_pairing/flow_keys.log \
  --keys-file captures/win172_to_win27_pairing/session_keys.json \
  --outdir captures/win172_to_win27_pairing/decrypted
```

The decrypted directory should contain plaintext packet dumps plus summary
files suitable for diffing against another capture.

### Diff a good pairing against a failing one

Once both captures are decrypted, compare the generated summaries:

```bash
diff -u \
  captures/win172_to_win27_pairing/decrypted/summary.txt \
  captures/win_to_linux_pairing_fail/decrypted/summary.txt
```

For JSON-aware inspection, use `jq`:

```bash
jq '.frames[] | {index, direction, packet_class, counter, key_id}' \
  captures/win_to_linux_pairing_fail/decrypted/summary.json
```

### Packet-only follow-up capture

Use this after a successful key-trap run when we only need fresh packets for the
same connection/profile:

```cmd
cd C:\Temp\opensourceLogiMX
python tools\capture_flow_packets.py ^
  --peer 192.168.1.20 ^
  --name post_pairing_heartbeat ^
  --duration 90
```

Then decrypt it with the previously verified keys:

```bash
python3 tools/flow_crypto.py decrypt \
  captures/post_pairing_heartbeat/post_pairing_heartbeat.pcapng \
  --keys-file captures/win172_to_win27_pairing/session_keys.json \
  --outdir captures/post_pairing_heartbeat/decrypted
```

### Memory-dump fallback

If the CDB key trap missed the session key, dump opensource LogiMX memory on the
Windows host:

```cmd
cd C:\Temp\opensourceLogiMX
python tools\dump_windows_logi_memory.py --name after_pairing
```

Then scan the dump against the capture:

```bash
python3 tools/flow_crypto.py extract-keys \
  captures/win_to_linux_pairing_fail/win_to_linux_pairing_fail.pcapng \
  --dump dumps/after_pairing/after_pairing.<pid>.dmp \
  --out captures/win_to_linux_pairing_fail/session_keys.json
```

Use `--dry-run` first if you need to confirm which process would be dumped:

```cmd
python tools\dump_windows_logi_memory.py --dry-run
```

## Script Reference

### `capture_flow_session.py`

Windows one-shot capture orchestrator. Use this first for pairing/reconnect
captures because it records packets and traps the session key in the same run.

Requires:

- Administrator shell
- Wireshark `dumpcap.exe`
- CDB/WinDbg available, preferably at `C:\Temp\debuggers\cdb.exe`
- Running `opensourceLogiMX`

Typical use:

```cmd
python tools\capture_flow_session.py --peer 192.168.1.20 --name win172_to_win27_pairing
```

### `capture_flow_packets.py`

Windows packet-only capture. Use this when we already have a valid key from a
previous `capture_flow_session.py` run and only need fresh traffic.

Typical use:

```cmd
python tools\capture_flow_packets.py --peer 192.168.1.20 --name live_test --duration 60
```

Output:

```text
captures/<name>/<name>.pcapng
captures/<name>/capture_metadata.json
```

Decrypt with a previous key file:

```bash
python3 tools/flow_crypto.py decrypt captures/<name>/<name>.pcapng \
  --keys-file captures/<previous>/session_keys.json \
  --outdir captures/<name>/decrypted
```

### `dump_windows_logi_memory.py`

Windows fallback key-recovery helper. It creates full dumps of opensource LogiMX
processes so `flow_crypto.py` can scan memory for session keys after a
pairing/reconnect already happened.

Use this when the CDB key trap failed or when we need to inspect a live
post-pairing process.

Typical use:

```cmd
python tools\dump_windows_logi_memory.py --name after_pairing
```

Then extract keys against a capture:

```bash
python3 tools/flow_crypto.py extract-keys captures/<session>/<session>.pcapng \
  --dump dumps/<dump_session>/<dump_session>.<pid>.dmp \
  --out captures/<session>/session_keys.json
```

### `flow_crypto.py`

Cross-platform Marconi/Flow crypto toolbox. It lists key IDs, extracts and
verifies session keys, decrypts captures, and derives thekogans/PBKDF-style
keys when we have X25519 material.

Common commands:

```bash
python3 tools/flow_crypto.py keyids captures/<name>/<name>.pcapng

python3 tools/flow_crypto.py extract-keys captures/<name>/<name>.pcapng \
  --key-log captures/<name>/flow_keys.log \
  --out captures/<name>/session_keys.json

python3 tools/flow_crypto.py decrypt captures/<name>/<name>.pcapng \
  --keys-file captures/<name>/session_keys.json \
  --outdir captures/<name>/decrypted

python3 tools/flow_crypto.py derive --secret <hex> --salt <hex>
```

`decrypt` can also take `--key`, `--key-log`, `--dump`, `--private-key`,
`--manual-secret`, and `--salt` depending on what evidence we captured.

## Working Captures

- `captures/peer2-v31/` - `peer2 to peer1 v31 build, 93/93 decrypted.
- `captures/peer2_peer1_full/` - `peer2 to peer1, 127/133 decrypted, key trapped.
