# LogiMX Marconi Protocol Reference

## Overview

LogiMX Flow uses a proprietary protocol internally called "Marconi" (C++ namespace `logitech::marconi`). It's a two-layer system:

1. **Discovery** (UDP) — host presence, peer discovery, pairing search
2. **Tunnel** (TCP) — encrypted Flow traffic: mouse, keyboard, clipboard, settings

All tunnel traffic is AES-256-GCM encrypted, using a bootstrap key for handshake and per-session keys derived via X25519 ECDH.

## Ports

| Port  | Proto | Purpose                                |
| ----- | ----- | -------------------------------------- |
| 59869 | TCP   | Encrypted Flow tunnel (Marconi frames) |
| 59870 | UDP   | Broadcast discovery & pairing search   |
| 59871 | UDP   | Directed discovery pings               |

## Discovery Protocol (UDP 59870-59871)

Discovery packets are encrypted with the bootstrap key (AES-256-GCM) and contain FARS-serialized payloads after decryption. Broadcasts go to `255.255.255.255:59870` or the subnet broadcast.

### Packet Types

| Packet                    | Direction | Purpose                                        |
| ------------------------- | --------- | ---------------------------------------------- |
| `InitiateDiscoveryPacket` | Broadcast | "I'm searching for peers" — triggers responses |
| `BeaconPacket`            | Broadcast | Periodic presence announcement with peer list  |
| `PingPacket`              | Unicast   | "Are you there?" directed at a known host      |

### Discovery Flow

Common successful pairing-search choreography observed in captures:

```
Searching host sends:    InitiateDiscoveryPacket → 192.168.1.255:59870
Searching host sends:    BeaconPacket            → 192.168.1.255:59870
Other hosts respond:     PingPacket             → searching_host:59870
Other hosts respond:     BeaconPacket           → searching_host:59871
Searching host replies:  PingPacket             → other_host:59871
```

Beacon packets are sent periodically (~every 30s) to maintain presence even when no search is active.

No distinct `PingReplyPacket` was needed to explain observed captures; replies reuse `PingPacket` and directed `BeaconPacket` traffic.

**Critical finding:** opensource LogiMX on Windows opens TCP only to peers discovered during an _active search_ (`InitiateDiscoveryPacket`), not to peers seen in passive beacons. A peer must send `InitiateDiscoveryPacket` to trigger Windows to connect.

**Response pattern:** In successful pairing-search flows, discovery responses must match the official choreography: broadcast `BeaconPacket` on UDP 59870, unicast `PingPacket` back to the searching host on UDP 59870, and answer directed discovery on UDP 59871 with directed traffic on UDP 59871.

## Marconi Frame Format (TCP 59869)

Every frame on the TCP tunnel:

```
Offset  Size  Field
0       32    keyId (32-byte key identifier carried in the frame header)
32      4     frameCiphertextLength (length of the following ciphertext block, big-endian)
36      2     ivLen (always 12)
38      4     ciphertextLen (big-endian)
42      2     macLen (always 16)
44      12    nonce (12-byte AES-GCM IV)
56      N     ciphertext
56+N    16    GCM authentication tag
```

Total overhead: 72 bytes per frame (header + tag).

### keyId

The `keyId` is the 32-byte key identifier carried on the wire to select the correct decrypting key:

- Bootstrap frames use keyId: `10512c128c6053cea372259d74b8438e60e88d25e5ab463fed92bacde551f394`
- Session frames use the negotiated session keyId carried in the handshake `DHEParams`

## Handshake Sequence

```
Initiator                         Server (peer)
  |                                   |
  |── ClientHelloPacket ─────────────>|  (bootstrap-encrypted)
  |                                   |  Contains: X25519 public key, cipher suite
  |                                   |
  |<── ServerHelloPacket ─────────────|  (bootstrap-encrypted)
  |                                   |  Contains: X25519 public key, session keyId
  |                                   |
  |── PromoteConnectionPacket ───────>|  (bootstrap-encrypted)
  |                                   |  Confirms session key established
  |                                   |
  |══ All subsequent frames use ══════|  (session-key encrypted)
  |   session key                     |
  |                                   |
  |── ClientDeviceConnectPacket ─────>|  "I'm device X, here are my capabilities"
  |<── ServerDeviceConnectPacket ─────|  "I'm device Y, here are mine"
  |                                   |
  |── SettingsPacket ────────────────>|  "These are my Flow settings and peers"
  |<── SettingsPacket ────────────────|  "These are mine"
  |                                   |
  |── GlobalData(SetOwnerPacket) ────>|  "I'm the owner"
  |<── HeartbeatPacket ───────────────|  Keepalive
  |── HeartbeatPacket ───────────────>|
```

### Pairing search nuances

When the receiver-side host starts the pairing search, it first answers Settings with the peer row unknown (`keyboardChannel = ffffffff`), then sends a corrected Settings packet. The initiator must be prepared for same-counter replies and a follow-up correction.

### After pairing

After Settings/SetOwner exchange, the tunnel enters steady state:

- `HeartbeatPacket` every ~15 seconds (echo-only for client-initiated sessions)
- `DeviceDataPacket` for mouse/keyboard/clipboard
- `SetCurrentHostPacket` when mouse moves between hosts
- `InitiateFlowPacket` to trigger a host switch

### Session Constraints

- The peer's `GlobalData(SetOwnerPacket)` is a confirmation step, not a request. Replying to it causes disconnects.
- Some outbound sessions receive a second `SettingsPacket` after the initial exchange. Answer it once, keep the same counter relationship, and avoid response bursts.
- Reusing a just-sent outbound Settings counter wedges the session. After replying with `counter+1`, local state must advance to that new counter.
- opensource LogiMX on Windows is sensitive to repeated responses. Multiple `SettingsPacket`, `SetCurrentHostPacket`, or `SetOwnerPacket` replies in a burst can disconnect or crash the peer.

## FARS Packet Classes

FARS (Flow Application Remote Serialization) is thekogans' custom serialization format, providing a class-based packet dispatch system. Each packet has a type identifier and a counter for ordering.

| Packet Class                | Counter | Contents                                                              |
| --------------------------- | ------- | --------------------------------------------------------------------- |
| `ClientHelloPacket`         | —       | DHEParams, X25519 public key, hostname, cipher suite                  |
| `ServerHelloPacket`         | —       | DHEParams, X25519 public key, session keyId                           |
| `PromoteConnectionPacket`   | —       | Confirmation, session keyId                                           |
| `ClientDeviceConnectPacket` | ✓       | Device info, capabilities                                             |
| `ServerDeviceConnectPacket` | ✓       | Device info, capabilities                                             |
| `DeviceDataPacket`          | —       | Mouse HID reports, keyboard HID reports, clipboard, or nested packets (counters are in nested packets) |
| `GlobalDataPacket`          | ✓       | Wraps SetOwnerPacket, role negotiation                                |
| `HeartbeatPacket`           | ✓       | Keepalive ping                                                        |
| `SettingsPacket`            | ✓       | Flow preferences, peer list, keyboard-link state                      |
| `SetCurrentHostPacket`      | ✓       | Mouse has moved to this host (payload = Flow channel)                 |
| `SetOwnerPacket`            | ✓       | This host is the active Flow owner                                    |
| `InitiateFlowPacket`        | ✓       | Request mouse/keyboard flow switch                                    |

## SettingsPacket Layout

**See [packet-reference.md](packet-reference.md) section 6.2 for the complete `SettingsPacket` structural specification, including the variable-length state blob, host rows, and 84-byte outer tail.**

Operationally important constraints:

- Steady-state paired rows use 1-based Flow channels, not zero-based indices.
- `keyboardChannel = ffffffff` is the no-keyboard / placeholder value. Linked hosts use their actual Flow channel there.
- Pairing/search responses can include compact placeholder rows before full peer rows.
- The 84-byte outer tail carried alongside Settings in `DeviceDataPacket` is host/context-specific and must match peer expectations.

## DeviceDataPacket Action Payloads

**See [packet-reference.md](packet-reference.md) section 7 for action payload formats (clipboard, mouse & keyboard).**

## Heartbeat Behavior
- **Client-initiated sessions:** Stay _passive_ — only echo peer heartbeats. Proactive heartbeats from a client cause Windows to TCP FIN.
- Heartbeat echo delay >10s causes Windows disconnection. Keep HID switching off the TCP event loop.

## Host Switching

- `SetCurrentHostPacket` carries the Flow channel itself (`00000001`, `00000002`, `00000003`), not a zero-based host index.
- The active local Flow channel follows the device's current Easy-Switch / host slot. Treat it as device state, not something inferred from peer advertisements.
- Keep HID switching asynchronous and off the TCP event loop; synchronous host switching delays heartbeat echoes enough to make Windows disconnect.

---

_For the most detailed packet-level reference, see [docs/packet-reference.md](docs/packet-reference.md)._

---

**Protocol Designer:** Ahmed Abdelghany
