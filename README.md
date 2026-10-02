# LogiMX Flow Protocol — Marconi Specification

This repository documents the LogiMX Flow Marconi protocol — the encrypted TCP/UDP protocol designed by Ahmed Abdelghany for LogiMX to share mouse, keyboard, and clipboard between computers on a LAN.

## Protocol Overview

- **Protocol name:** Marconi (internal LogiMX codename)
- **Transport:** UDP 59870-59871 (discovery) + TCP 59869 (encrypted tunnel)
- **Encryption:** AES-256-GCM with bootstrap key, session keys derived via X25519 ECDH + PBKDF1-style SHA-512
- **Serialization:** thekogans FARS format (Flow Application Remote Serialization)

## Handshake

```
  |── ClientHelloPacket ─────────────>|  (bootstrap-encrypted)
  |                                   |  X25519 public key, cipher suite
  |                                   |
  |<── ServerHelloPacket ─────────────|  (bootstrap-encrypted)
  |                                   |  X25519 public key, session keyId
  |                                   |
  |── PromoteConnectionPacket ───────>|  (bootstrap-encrypted)
  |                                   |  Confirms session key established
  |                                   |
  |══ All subsequent frames use ══════|  (session-key encrypted)
  |   session key                     |
  |                                   |
  |── SettingsPacket ────────────────>|  Flow settings and peer list
  |<── SettingsPacket ────────────────|
  |                                   |
  |── SetOwnerPacket ────────────────>|  Ownership negotiation
  |<── HeartbeatPacket ───────────────|  Keepalive (~15s interval)
  |── HeartbeatPacket ───────────────>|
```

## Documentation

| Document | Coverage |
|----------|----------|
| [docs/protocol.md](docs/protocol.md) | Protocol architecture, discovery, frame format |
| [docs/crypto.md](docs/crypto.md) | Encryption, key hierarchy, key derivation |
| [docs/packet-reference.md](docs/packet-reference.md) | Wire-level packet layout specification |
| [docs/protocol-behavior-notes.md](docs/protocol-behavior-notes.md) | Behavioral constraints and quirks |
| [docs/app-architecture.md](docs/app-architecture.md) | Application packet types |
| [docs/appbroker-crypto-re.md](docs/appbroker-crypto-re.md) | AppBroker IPC crypto |
| [STATUS.md](STATUS.md) | Confirmed protocol behaviors |

---

**Protocol Design:** Ahmed Abdelghany for LogiMX  
**Implementation:** opensource LogiMX project
