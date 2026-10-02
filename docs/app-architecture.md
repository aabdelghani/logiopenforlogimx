# Application Architecture

The Flow protocol runs over TCP port 59869 with a custom encrypted framing layer.

## Key Components

- **Bootstrap Key**: A hardcoded AES-256 key used to encrypt the initial handshake frames (ClientHelloPacket, ServerHelloPacket, PromoteConnectionPacket)
- **Session Key**: Derived via X25519 ECDH + SHA-512 PBKDF, used for all subsequent encrypted frames
- **Serialization**: thekogans FARS format (Flow Application Remote Serialization)

## Packet Types

| Packet | Direction | Purpose |
|--------|-----------|---------|
| ClientHelloPacket | initiator→server | X25519 public key, cipher suite |
| ServerHelloPacket | server→initiator | X25519 public key, session keyId |
| PromoteConnectionPacket | initiator→server | Confirms session key established |
| DeviceDataPacket | bidirectional | Mouse, keyboard, clipboard data |
| GlobalDataPacket | bidirectional | Role negotiation, ownership |
| HeartbeatPacket | bidirectional | Keepalive (~15s interval) |
| SettingsPacket | bidirectional | Flow preferences and peer list |
| SetCurrentHostPacket | bidirectional | Mouse has moved to this host |
| SetOwnerPacket | bidirectional | Host is the active owner |
| InitiateFlowPacket | bidirectional | Request mouse/keyboard flow |
