# LogiMX Flow Protocol — Confirmed Behaviors

## Confirmed

- UDP `59870`: broadcast discovery (`InitiateDiscoveryPacket`, `BeaconPacket`, `PingPacket`)
- UDP `59871`: directed discovery/ping
- TCP `59869`: Marconi encrypted Flow tunnel
- Marconi frame format: keyId(32) + frameCiphertextLength(4) + ivLen(2) + ctLen(4) + macLen(2) + nonce(12) + ct + tag(16)
- Bootstrap AES key recovered and verified across multiple sessions
- Session AES key derivation via X25519 ECDH + PBKDF1-style SHA-512
- SettingsPacket layout fully mapped (20–28 byte variable-length state blob, host rows, keyboard-link toggle)
- Clipboard protocol: `ClipboardUpdatePacket → GetFormatDataPacket → FormatDataPacket`
- Keyboard forwarding mechanism: `InitiateFlowPacket → SetCurrentHostPacket → HID++ ChangeHost`
  - `SettingsPacket.keyboardLink` toggles keyboard forwarding
  - `SettingsPacket.keyboardChannel` tracks which channels have keyboards attached
  - Keyboard HID reports inside `DeviceDataPacket` action payloads are standard USB HID keyboard reports (opaque forwarding, opensource LogiMX does not transform them)
- Steady-state tunnel behavior: `DeviceData + Heartbeat` (~15s interval)

## Critical Behaviors

**Windows Flow TCP initiation.** The Windows implementation does NOT initiate Flow TCP to peers it discovers passively. It only opens TCP to peers found during an active search (`InitiateDiscoveryPacket`), or waits for the peer to connect inbound. This means any interoperable peer must actively send `InitiateDiscoveryPacket` to trigger the implementation to connect.

**Heartbeat passivity.** Sessions where Windows is the TCP server require passive heartbeat behavior from the client — only echo peer heartbeats, never send proactive ones. Proactive heartbeats cause Windows to TCP FIN.

**Settings packet quirks.** Settings packets must use 1-based row channels (not 0-based), host-first row ordering, a specific compact state blob, and an 84-byte `DeviceDataPacket` tail whose content is host/context-specific.

