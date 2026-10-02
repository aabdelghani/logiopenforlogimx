# LogiMX Marconi Protocol — Cryptography

This document describes the LogiMX Flow host-to-host LAN cryptography used by the Marconi protocol. The separate peripheral/AppBroker protocol is documented in [appbroker-crypto-re.md](appbroker-crypto-re.md).

## Key Hierarchy

```
Bootstrap Key (hardcoded in opensourceLogiMX.exe)
  │
  └─ encrypts handshake frames:
       ClientHelloPacket, ServerHelloPacket, PromoteConnectionPacket
       │
       └─ X25519 ECDH key exchange inside bootstrap channel
            │
            └─ Session Key (AES-256-GCM)
                 │
                 └─ encrypts all subsequent frames:
                      DeviceData, GlobalData, Heartbeat, Settings, etc.
```

## Cipher Suite

| Component          | Algorithm                                                                        |
| ------------------ | -------------------------------------------------------------------------------- |
| Encryption         | AES-256-GCM                                                                      |
| Key Exchange       | X25519 ECDH                                                                      |
| KDF                | PBKDF1-style SHA2-512 (count=1) via `thekogans::SymmetricKey::FromSecretAndSalt` |
| Key Identification | 32-byte key identifier carried in `DHEParams` and frame headers                  |
| Authentication     | GCM tag (16 bytes)                                                               |

## Bootstrap Key

The bootstrap key is hardcoded in `opensourceLogiMX.exe`. It's a raw AES-256 key, not derived from any input.

```
Bootstrap key:  1316ee2215da62321e1e7257104dc24fd6a865e90eca357aa663c66f93da7182
Bootstrap keyId: 10512c128c6053cea372259d74b8438e60e88d25e5ab463fed92bacde551f394
```

This key decrypts:

- `ClientHelloPacket` — contains initiator X25519 public key, hostname, cipher suite
- `ServerHelloPacket` — contains server X25519 public key, session keyId
- `PromoteConnectionPacket` — confirmation of session key
- Inner frames of `DeviceDataPacket` (e.g., nested `SettingsPacket` during pairing before session key is established)


## Session Key Derivation

### ECDH Exchange

Both sides generate ephemeral X25519 keypairs:

```
Initiator:
  private_key_A → public_key_A (sent in ClientHelloPacket.DHEParams)

Server:
  private_key_B → public_key_B (sent in ServerHelloPacket.DHEParams)

Shared secret = X25519(private_key_A, public_key_B)
              = X25519(private_key_B, public_key_A)
```

### FromSecretAndSalt

The shared secret (32 bytes) and a serialized salt block feed into `thekogans::crypto::SymmetricKey::FromSecretAndSalt`:

```
Input:  shared_secret (32 bytes) + salt = 0x01 || clientSerializedObject || serverSerializedObject
KDF:    PBKDF1-style SHA2-512 loop, count=1
Output: AES-256 session key (32 bytes), associated on the wire with the negotiated session keyId
```

In current captures that serialized salt block is 189 bytes long.

The salt is 189 bytes, containing a serialization prefix (0x01), client public key bytes, and server public key bytes, ordered based on who initiated.
