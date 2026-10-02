# AppBroker Cryptographic Protocol

The AppBroker is the IPC bridge between the Flow agent and UI. It uses the same cryptographic primitives as the Marconi LAN protocol but with device-specific parameters.

## Crypto Summary

| Component | Algorithm |
|-----------|-----------|
| Key Exchange | X25519 ECDH |
| Encryption | AES-256-GCM |
| KDF | PBKDF1-style SHA-256 (count=1) |
| Authentication | GCM tag (16 bytes) |

## Key Derivation

The AppBroker uses X25519 ECDH followed by FromSecretAndSalt to derive session keys from:

- Shared secret (32 bytes from ECDH)
- Salt: serialized pair of public keys
- Hash function: SHA-256
- Iteration count: 1

For more details on the Marconi LAN protocol crypto, see [crypto.md](crypto.md).
