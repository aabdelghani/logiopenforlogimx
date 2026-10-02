# Protocol Behavior Reference

This document collects observed protocol behaviors and implementation details.

## Marconi Architecture

The network subsystem is `logitech::marconi` with these observed classes:

- `DiscoveryMgr`, `BroadcastDiscovery`, `NodeStoreDiscovery`
- `ConnectionMgr`, `Tunnel`, `Device`, `Watchdog`

## Discovery Log Format

Discovery packet fields follow this log format pattern:

```
Broadcasting InitiateDiscoveryPacket: (%u, %u, %u), force: %s.
Received BeaconPacket: (%u, %u, %u), hostId: %s, from: %s:%u, to: %s:%u, force: %s, ping port %u, isEnabled: %s, peer hostId: %s.
Unicasting PingPacket: (%u, %u, %u), hostId: %s, address: %s:%u, force: %s.
Received PingPacket: (%u, %u, %u), hostId: %s, from: %s:%u, to: %s:%u, force: %s, connect port: %u, device.peer[%u]: hostId: %s
Initiating connection: (%u, %u, %u), hostId: %s, from: %s:%u, to: %s:%u, force: %s.
```

## Tunnel Log Strings

```
Sending ClientHelloPacket, %s
Received ClientHelloPacket; hostId: %s, %s
Sending ServerHelloPacket, %s
Sending PromoteConnectionPacket, hostId: %s
Sending HeartbeatPacket, hostId: %s (%I64d, %I64d)

> **Note:** This is a Windows log format string, not the wire payload. The actual HeartbeatPacket wire payload is a single u8 counter.
Sending GlobalDataPacket; size: %u, %s.
Sending DeviceDataPacket; size: %u, %s.
```

## Flow Packet Classes

Observed in binary strings: `SettingsPacket`, `InitiateFlowPacket`, `SetCurrentHostPacket`, `keyboard::KeyPacket`, `clipboard::ClipboardUpdatePacket`, `clipboard::GetFormatDataPacket`, `clipboard::FormatDataPacket`, `clipboard::FileDescriptorsPacket`, `clipboard::FileDataPacket`, `clipboard::ErrorPacket`, `SetOwnerPacket`

## Discovery Packet Fields

Discovery packets carry the following fields:

| Packet | Fields |
|--------|--------|
| InitiateDiscoveryPacket | id, serialNumber, channel, force |
| BeaconPacket | id, serialNumber, channel, hostId, force, port |
| PingPacket | id, serialNumber, channel, hostId, force, port |

Wire format: `identity(8) + channel(4) + presenceFlag(1)`.

## HID++ Device Switching

Flow uses HID++ for local host switching. Relevant features observed:

- `0x1814` — `Feature1814ChangeHost`: `GetHostInfo`, `SetCurrentHost`, `GetCookies`, event `ChangeHostRequestedEvent`
- `0x1815` — host metadata / host names

## thekogans Library

LogiMX links several thekogans open-source libraries (https://github.com/thekogans):

- thekogans/crypto -- AES-256-GCM, X25519 ECDH, key derivation
- thekogans/packet -- packet framing, serialization, session management
- thekogans/util -- Serializer, Buffer, SecureVector
- thekogans/stream -- stream-based serialization

The frame format wraps FARS-serialized payloads in a thekogans::packet envelope with AES-256-GCM encryption via thekogans::crypto.

Frame layout on the wire:

```
keyId(32) + frameCiphertextLength(4) + ivLength(2) + ciphertextLength(4) + macLength(2) + nonce(12) + ciphertext + tag(16)
```

After decryption, the plaintext contains a `PlaintextHeader` (2 bytes: random padding length + flags), optional random padding, optional `Session::Header` (24 bytes: GUID + sequence number), and the serialized packet.

The packet itself uses a variable-length header: `magic(4) + classNameLength(varint) + className + version(2) + size(varint)`.

In Flow captures, `ClientHelloPacket` / `ServerHelloPacket` carry the X25519 DHE parameters and negotiated session keyId used by subsequent frames.
