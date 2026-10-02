# LogiMX Flow / Marconi Protocol — Packet Format Reference

This document is a **structural specification** of the LogiMX Flow LAN protocol packets. It is intended to be sufficient for implementing packet serialization and deserialization.

---

## 1. Protocol Overview

LogiMX Flow (internally called **Marconi**) operates in three layers:

| Layer | Transport | Encryption | Purpose |
|-------|-----------|------------|---------|
| UDP Discovery | UDP 59870 (broadcast), 59871 (directed) | Bootstrap key (AES-256-GCM) | Peer discovery and presence |
| TCP Handshake | TCP 59869 | Bootstrap key (AES-256-GCM) | X25519 key exchange, session establishment |
| TCP Session | TCP 59869 | Session key (AES-256-GCM) | Flow data: settings, mouse/keyboard, clipboard |

**Port table:**

| Port | Proto | Purpose |
|------|-------|---------|
| 59869 | TCP | Encrypted Flow tunnel |
| 59870 | UDP | Broadcast discovery & search |
| 59871 | UDP | Directed discovery pings |

### Encryption Model

Two encryption layers with distinct keys:

| Key | Scope | KeyId (hex) | Key (hex) |
|-----|-------|-------------|-----------|
| **Bootstrap** | Discovery, handshake, nested DeviceData inner frames | `10512c128c6053cea372259d74b8438e60e88d25e5ab463fed92bacde551f394` | `1316ee2215da62321e1e7257104dc24fd6a865e90eca357aa663c66f93da7182` |
| **Session** | All post-PromoteConnection traffic (outer frames) | Derived per-session via X25519 DHE | Extracted from endpoint memory or dump |

**Key derivation:** Session keys are derived via X25519 ECDH → `thekogans::crypto::SymmetricKey::FromSecretAndSalt` (PBKDF1-style SHA-512, count=1). The frame header carries a 32-byte key identifier; bootstrap traffic uses the fixed bootstrap keyId above, and session traffic uses the negotiated session keyId exchanged during the handshake.

**Nested encryption rule:**
- `DeviceDataPacket` inner payload → bootstrap key (separate encrypted frame inside the plaintext)
- `GlobalDataPacket` nested `SetOwnerPacket` → **plaintext** (no additional encryption)

---

## 2. Wire Formats

### 2.1 Encrypted Frame Layout (outer)

Applies to all frames on TCP 59869 and UDP discovery packets after encryption wrapping.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0x00 | 32 | bytes | keyId | 32-byte key identifier used to select the decrypting key |
| 0x20 | 4 | u32be | frameCiphertextLength | Length of the following ciphertext block (`CiphertextHeader + nonce + ciphertext + tag`) |
| 0x24 | 2 | u16be | ivLength | Normally 12 |
| 0x26 | 4 | u32be | ciphertextLength | Length of ciphertext body |
| 0x2A | 2 | u16be | macLength | Normally 16 (GCM tag) |
| 0x2C | ivLength | bytes | nonce | AES-GCM IV (12 bytes) |
| 0x2C+ivLength | ciphertextLength | bytes | ciphertext | AES-256-GCM encrypted payload |
| 0x2C+ivLength+ciphertextLength | macLength | bytes | tag | GCM authentication tag (16 bytes) |

**Total overhead:** 72 bytes (header + tag). No AAD is used for bootstrap frames.

**Frame extraction:** `totalFrameSize = 36 + frameCiphertextLength`.

### 2.2 Plaintext Wrapper

After AES-256-GCM decryption, plaintext starts with a random-padding wrapper:

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0x00 | 1 | u8 | randomLength | Number of random padding bytes following |
| 0x01 | 1 | u8 | flags | Bit 0 (`FLAGS_SESSION_HEADER`): session header present |
| 0x02 | randomLength | bytes | randomBytes | Padding; varying sizes per packet type (see table below) |
| — | 24 (if flags & 1) | — | sessionHeader | GUID (16 bytes) + sequence number (u64be) |
| — | … | — | farsBody | FARS packet starts here |

**Padding reference by packet type:**

| Packet | Inner Pad | Outer Pad | Total Random |
|--------|-----------|-----------|--------------|
| InitiateDiscoveryPacket | — | — | 95 |
| BeaconPacket (broadcast) | — | — | 79 |
| PingPacket | — | — | 80 |
| ClientHelloPacket | — | — | 71 |
| ServerHelloPacket | — | — | 71 |
| PromoteConnectionPacket | — | — | 30 (fixed) |
| HeartbeatPacket | — | — | 33 |
| GlobalDataPacket(SetOwner) | — | — | 12 |
| DeviceData(ClientDeviceConnect) | 81 | 9 | 90 |
| DeviceData(ServerDeviceConnect) | 81 | 9 | 90 |
| DeviceData(Settings) | 84 | 26 | 110 |
| DeviceData(InitiateFlow, reverse) | 94 | 71 | 165 |
| DeviceData(InitiateFlow, forward) | 17 | 95 | 112 |
| DeviceData(SetCurrentHost) | 5 | 2 | 7 |
| Clipboard(GlobalData) | — | — | 15 |

**Discovery reply variants (directed vs broadcast):**

| Reply Type | Port | Pad Size |
|------------|------|----------|
| Broadcast beacon reply | 59870 | 44 |
| Broadcast ping reply | 59870 | 38 |
| Directed beacon reply | 59871 | 40 |
| Directed ping reply | 59871 | 62 |
| Directed extra discovery | 59871 | 20 |
| Directed extra beacon | 59871 | 29 |

**Important:** Too-short padding causes packets to be ignored by the official implementation. Match official padding sizes.

### 2.3 FARS Packet Header

All Marconi application packets use the FARS serialization format:

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0x00 | 4 | ASCII | magic | `"FARS"` (0x46415253) |
| 0x04 | varint | — | classNameLength | Variable-length encoded; also serves as type tag |
| 0x04+varint | classNameLength | ASCII | className | e.g. `"HeartbeatPacket"`, `"DeviceDataPacket"` |
| after class | 2 | u16be | version | Always `0x0001` |
| after version | varint | — | payloadLength | Variable-length encoded payload size |
| after payloadLen | payloadLength | — | payload | Packet-specific payload |

**Class name length prefix → class name mapping:**

| Prefix (hex/dec) | Class Name |
|-------------------|------------|
| `\x1d` (29) | SettingsPacket, SetOwnerPacket |
| `\x1f` (31) | HeartbeatPacket |
| `\x21` (33) | InitiateDiscoveryPacket, ClientHelloPacket, ServerHelloPacket |
| `\x25` (37) | InitiateFlowPacket |
| `\x29` (41) | SetCurrentHostPacket |
| `\x2d` (45) | PromoteConnectionPacket |
| `\x21` (33, `!`) | DeviceDataPacket, GlobalDataPacket |

_Note: `\x21` is used for multiple packet classes; disambiguation requires parsing the class name string._

**Length encoding:** The classNameLength, payloadLength, and all string lengths use the thekogans variable-length encoding (`SizeT` / `SerializableHeader`):
- Values are shifted left by 1 and OR'd with 1: `encoded = ((value << 1) | 1) << (bytes - 1)`
- The low bit of each byte indicates continuation; trailing zeros indicate the byte count.
- This is NOT a simple u8/u16 length prefix.

---

## 3. Discovery Packets (Bootstrap-Key Encrypted, UDP)

### 3.1 InitiateDiscoveryPacket

**Encryption:** Bootstrap key
**Transport:** UDP broadcast to port 59870 (also directed to 59871)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial/identity |
| payload+0x08 | 4 | u32be | channel | Flow channel number |
| payload+0x0C | 1 | u8 | presenceFlag | Presence flag (0 = normal) |

**Total payload:** 13 bytes before FARS header and wrapper.

### 3.2 BeaconPacket

**Encryption:** Bootstrap key
**Transport:** UDP broadcast to port 59870, periodic (~30s)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial/identity |
| payload+0x08 | 4 | u32be | channel | Flow channel number |
| payload+0x0C | — | len-prefixed string | hostName | Hostname of sender |
| — | 1 | u8 | presenceFlag | Presence flag |
| — | 2 | bytes | tail | `e9de` = broadcast, `e9df` = directed reply |

### 3.3 PingPacket

**Encryption:** Bootstrap key
**Transport:** UDP unicast to port 59870 or 59871

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial/identity |
| payload+0x08 | 4 | u32be | channel | Flow channel number |
| payload+0x0C | — | len-prefixed string | hostName | Sender hostname |
| — | 1 | u8 | presenceFlag | Presence flag |
| — | 2 | bytes | tail | Always `e9dd` |

**Discovery choreography:**

```
Initiator → broadcast:59870  InitiateDiscoveryPacket
Initiator → broadcast:59870  BeaconPacket
Responder → initiator:59870  PingPacket
Responder → initiator:59871  BeaconPacket (directed)
Initiator → responder:59871  PingPacket (directed)
Initiator → responder:59869  TCP SYN
```

**Rule:** Daemon must listen on both UDP 59870 and 59871. Directed discovery on 59871 is required.

---

## 4. Handshake Packets (Bootstrap-Key Encrypted, TCP)

**Important:** ClientHello, ServerHello, and PromoteConnection are generated from **hardcoded binary templates** with dynamic fields patched in (hostname, X25519 public keys, object IDs). They are NOT constructed from scratch field-by-field.

### 4.1 ClientHelloPacket

**Encryption:** Bootstrap key
**Transport:** TCP (client → server)
**Generation:** Template-based with patches for hostname and X25519 public key

**Contains:** X25519 public key, hostname, cipher suite string

| Field | Notes |
|-------|-------|
| clientPublicKey | X25519 ephemeral public key (32 bytes, patched into template) |
| hostname | Client hostname (patched into template) |
| cipherSuite | `"AECDHE_ECDSA_AES-256-GCM_SHA2-512"` |
| clientSerialized | X25519 serialized key object (patched into template) |
| sessionKeyId | 32 bytes, located 34 bytes before first X25519 object marker |

### 4.2 ServerHelloPacket

**Encryption:** Bootstrap key
**Transport:** TCP (server → client)
**Generation:** Template-based, copies DHE prefix from ClientHello, patches server X25519 keys

| Field | Notes |
|-------|-------|
| serverPublicKey | X25519 ephemeral public key (patched into template) |
| sessionKeyId | Copied from ClientHello (same keyId both sides derive) |
| serverSerialized | X25519 serialized key object (patched into template) |

### 4.3 PromoteConnectionPacket

**Encryption:** Bootstrap key
**Transport:** TCP (client → server)
**Generation:** Template-based with hostname patched in

| Field | Notes |
|-------|-------|
| hostname | Client hostname (patched into template) |

**Padding:** Fixed 30 bytes of random padding.

**Handshake sequence:**

```
Client → Server:  ClientHelloPacket    (bootstrap key)
Server → Client:  ServerHelloPacket    (bootstrap key)
Client → Server:  PromoteConnectionPacket  (bootstrap key)
─── session key begins ───
Client → Server:  DeviceDataPacket(ClientDeviceConnect)
Server → Client:  DeviceDataPacket(ServerDeviceConnect)
Server → Client:  DeviceDataPacket(SettingsPacket)
Client → Server:  DeviceDataPacket(SettingsPacket, counter+1)
```

**X25519 session key derivation:**

```
sharedSecret = X25519(localPrivateKey, remotePublicKey)
salt         = 0x01 || clientSerializedObject || serverSerializedObject
sessionKey   = KDF(sharedSecret, salt, length=32, rounds=1, hash=SHA512)
sessionKeyId = negotiated in the handshake DHE parameters and carried in subsequent frame headers
```

**Implementation note:** The Hello/Promote packets are still best treated as capture-derived templates with patched dynamic fields. The packet classes, encryption, padding, and patched fields are identified here, but the full field-by-field serialized object graph inside those handshake packets is not yet documented to the same level as `SettingsPacket` or the discovery packets.

---

## 5. Session Packets (Session-Key Encrypted, TCP)

### 5.1 HeartbeatPacket

**FARS prefix:** `\x1f` (classNameLength = 31)
**Encryption:** Session key (outer frame)
**Frequency:** ~15 seconds, alternating between peers

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 1 | u8 | counter | Monotonic heartbeat counter (increments each beat) |

**Total payload:** 1 byte.

**Behavior:** Both sides echo their own counters. Pure keepalive, no state machine. The responder should echo a heartbeat reply within ~2–26 ms. **Do not** send proactive outbound heartbeats from the non-initiating peer; Windows closes the connection with FIN.

### 5.2 GlobalDataPacket

**FARS prefix:** `\x21` (classNameLength = 33)
**Encryption:** Session key (outer frame); nested payload is **plaintext** (not bootstrap-encrypted)
**Contains:** Sender hostname + nested plaintext FARS frame (typically `SetOwnerPacket`)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | — | len-prefixed string | hostname | Sender's hostname |
| — | 1 | u8 | objectMarker1 | Always `0x03` |
| — | 1 | u8 | objectMarker2 | Always `0x03` |
| — | 1 | u8 | objectMarker3 | Always `0x02` |
| — | varint | — | objectSize | Size of nested object payload |
| — | 1 | u8 | innerMarker | Always `0x01` |
| — | varint | — | innerLength | Size of inner body |
| — | varint | — | allocatorLength | Length of allocator string |
| — | allocatorLength | ASCII | allocator | Always `"DefaultAllocator"` |
| — | innerLength | — | innerFarsBody | Nested plaintext FARS packet (e.g. SetOwnerPacket) |

**Note:** Unlike `DeviceDataPacket`, the nested body here is NOT separately encrypted.

### 5.3 DeviceDataPacket

**FARS prefix:** `\x21` (classNameLength = 33)
**Encryption:** Session key (outer frame); inner frame uses **bootstrap key**
**Contains:** Device identity + channel + nested encrypted FARS frame + 84-byte tail

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial/identity |
| payload+0x08 | 4 | u32be | channel | Sender's Flow channel number |
| — | 1 | u8 | objectMarker1 | Always `0x03` |
| — | 1 | u8 | objectMarker2 | Always `0x03` |
| — | 1 | u8 | objectMarker3 | Always `0x02` |
| — | varint | — | objectSize | inner_frame_len + 84 |
| — | 1 | u8 | innerMarker | Always `0x01` |
| — | varint | — | innerLength | Size of inner body before decryption |
| — | varint | — | allocatorLength | Length of allocator string |
| — | allocatorLength | ASCII | allocator | Always `"DefaultAllocator"` |
| — | innerLength | — | innerFrame | Bootstrap-key encrypted Marconi frame |
| — | 84 | bytes | tail | Host/context-specific data (see tail format below) |

**84-byte tail format:**
- Normally: 84 zero bytes
- When keyboard link active: UTF-16-like structured data containing `{deviceUuid}\0{deviceType}` padded with nulls

Example keyboard link tail structure:
```
{ UUID-UTF16 } 0x00 { deviceType-UTF16 } 0x00 0x00 ... (padded to 84 bytes)
```

**Decryption of inner frame:** After session-key decryption of the outer frame, locate the inner encrypted frame within the DeviceDataPacket payload and decrypt it with the **bootstrap key**. The result is one of: `SettingsPacket`, `InitiateFlowPacket`, `SetCurrentHostPacket`, `ClientDeviceConnectPacket`, `ServerDeviceConnectPacket`.

---

## 6. Nested Packets (Bootstrap-Key Encrypted inside DeviceDataPacket, or Plaintext inside GlobalDataPacket)

### 6.1 SetOwnerPacket (plaintext inside GlobalDataPacket)

**FARS prefix:** `\x1d` (classNameLength = 29)
**Encryption:** None (nested plaintext inside GlobalDataPacket)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 2 | bytes | prefix | Always `01 00` |
| — | — | len-prefixed string | hostname | Owner hostname |
| — | 1 | u8 | enabled | `0x01` = confirm |

**Usage:** Sent inside `GlobalDataPacket` to claim or confirm ownership.

### 6.2 SettingsPacket (bootstrap-key encrypted inside DeviceDataPacket)

**FARS prefix:** `\x1d` (classNameLength = 29)
**Encryption:** Bootstrap key (inside DeviceDataPacket)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial |
| payload+0x08 | 4 | u32be | channel | Sender's Flow channel |
| payload+0x0C | 4 | u32be | counter | Increments on each settings change |
| — | — | len-prefixed string | layout | Usually `"horizontal"` |
| — | 20–28 | bytes | stateBlob | Variable-length state blob (see below) |
| — | variable | — | rows[] | Heterogeneous row entries (see row formats) |

**State blob (variable length, 20–28 bytes):**

The blob length varies across captures. The parser probes lengths 20–28 and accepts the one that yields valid rows. Most common is 22 bytes.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| 0x00 | 1 | bool | on | Flow enabled |
| 0x01 | 1 | bool | ctrlKey | Ctrl-key modifier |
| 0x02 | 1 | bool | copyPaste | Clipboard copy/paste |
| 0x03 | 1 | bool | dragDrop | Drag and drop |
| 0x04 | 1 | bool | hotCorners | Hot corners |
| 0x05 | 1 | bool | keyboardLink | Keyboard link enabled |
| 0x06 | 4 | u32be | keyboardId | Keyboard device ID (`0xffffffff` if unknown) |
| 0x0A | 4 | u32be | keyboardSerialNumber | Keyboard serial (`0xffffffff` if unknown) |
| 0x0E | 4 | u32be | trailing1 | Usually zero; `0xffffffff` in placeholder variants |
| 0x12 | 4 | u32be | trailing2 | Usually zero; may differ in placeholder variants |
| 0x16 | 4 | u32be | trailing3 | Present in 26–28 byte blobs; meaning unknown |

**Observed state blob variants:**

| Length | Hex | Description |
|--------|-----|-------------|
| 22 | `0100010100000006b35b42c457360000000000000000` | Keyboard link OFF, known identity |
| 22 | `0100010100010006b35b42c457360000000000000000` | Keyboard link ON, known identity |
| 22 | `010001010000ffffffffffffffff00000000ffffffff` | Unknown keyboard channel (placeholder) |

**Common field mapping for the 22-byte state blob:**

| Relative Offset | Field | Values |
|-----------------|-------|--------|
| 0x00 | on | `00` = false, `01` = true |
| 0x01 | ctrlKey | `00` = false, `01` = true |
| 0x02 | copyPaste | `00` = false, `01` = true |
| 0x03 | dragDrop | `00` = false, `01` = true |
| 0x04 | hotCorners | `00` = false, `01` = true |
| 0x05 | keyboardLink | `00` = false, `01` = true |
| 0x06-0x09 | keyboardId | `u32be` |
| 0x0A-0x0D | keyboardSerialNumber | `u32be` |
| 0x0E-0x11 | trailing1 | Usually `00000000` |
| 0x12-0x15 | trailing2 | `00000000` when keyboard known, placeholder-specific otherwise |

**Row formats:**

_Compact host-only row (channel = 0):_

| Offset | Size | Type | Field |
|--------|------|------|-------|
| — | — | len-prefixed string | hostname |
| — | 1 | u8 | enabled (`0x01` = enabled, `0x00` = disabled) |

_Full row:_

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| — | 4 | u32be | channel | Peer's Flow channel |
| — | 4 | u32be | keyboardChannel | Linked keyboard channel (`0xffffffff` = none) |
| — | — | len-prefixed string | hostname | May be empty string |
| — | 1 | u8 | enabled | `0x01` = enabled, `0x00` = disabled |

**Row ordering:** Not always sender-first. Compact rows can precede full rows. `--remove-from-flow` can appear as a hostname in unpair/position operations.

**Operational constraints:**

- In steady-state paired settings, row channels are 1-based.
- `keyboardChannel = ffffffff` is reserved for the no-keyboard / placeholder row.
- A linked host's `keyboardChannel` matches that host's Flow channel.
- Send exactly one Settings response per peer Settings request. Bursts of repeated Settings replies can crash opensource LogiMX.
- The 84-byte tail after the inner Settings frame is part of the on-wire structure and must be preserved as peer/context-specific data rather than synthesized blindly.

### 6.3 InitiateFlowPacket (bootstrap-key encrypted inside DeviceDataPacket)

**FARS prefix:** `\x25` (classNameLength = 37)
**Encryption:** Bootstrap key (inside DeviceDataPacket)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 4 | u32be | direction | Direction flag: `0` = reverse (left), `1` = forward (right) |
| payload+0x04 | 4 | f32be | normalizedPosition | Screen edge position where mouse crossed |

**Total payload:** 8 bytes.

**Flow edge position constants (capture-derived):**

| Direction | Value |
|-----------|-------|
| Reverse (left edge) | `0.53294414` |
| Forward (right edge) | `0.56255794` |

**Usage:** Sent when the source host initiates a mouse/keyboard transition to another host. The `direction` and `normalizedPosition` encode which screen edge the mouse crossed.

### 6.4 SetCurrentHostPacket (bootstrap-key encrypted inside DeviceDataPacket)

**FARS prefix:** `\x29` (classNameLength = 41)
**Encryption:** Bootstrap key (inside DeviceDataPacket)

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 4 | u32be | hostId | Target Flow channel (`0x00000001`, `0x00000002`, `0x00000003`, ...) |

**Total payload:** 4 bytes (FARS header adds 9 more → payloadLength = 0x09 in doc).

**Usage:** Sent by the target host acknowledging a mouse transition.

### 6.5 ClientDeviceConnectPacket (bootstrap-key encrypted inside DeviceDataPacket)

**Encryption:** Bootstrap key (inside DeviceDataPacket)
**Sent by:** TCP client (initiator) as the first session-key-encrypted frame after handshake.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial |
| payload+0x08 | 4 | u32be | channel | Sender's Flow channel |
| payload+0x0C | — | len-prefixed string | hostName | Client hostname |

### 6.6 ServerDeviceConnectPacket (bootstrap-key encrypted inside DeviceDataPacket)

**Encryption:** Bootstrap key (inside DeviceDataPacket)
**Sent by:** TCP server (listener) in response to ClientDeviceConnect.

| Offset | Size | Type | Field | Notes |
|--------|------|------|-------|-------|
| payload+0x00 | 8 | bytes | deviceIdentity | Device serial |
| payload+0x08 | 4 | u32be | channel | Sender's Flow channel |
| payload+0x0C | — | len-prefixed string | hostName | Server hostname |

---

## 7. Clipboard & Keyboard Packets

These packets are carried inside `DeviceDataPacket` (bootstrap-key encrypted inner frames). Their inner payloads are USB HID reports or opaque platform-specific data forwarded without transformation by opensource LogiMX.

| Packet Class | Direction | Content |
|---|---|---|
| `keyboard::KeyPacket` | Source → Target | USB HID keyboard report, forwarded opaquely |
| `clipboard::ClipboardUpdatePacket` | Source → Target | Clipboard change notification; payload: sequenceId (u32be) + format list |
| `clipboard::GetFormatDataPacket` | Target → Source | Request clipboard data in a specific format |
| `clipboard::GetFolderFileDescriptorsPacket` | Target → Source | Request folder file descriptors |
| `clipboard::GetFileDescriptorsPacket` | Target → Source | Request file descriptors |
| `clipboard::GetFileDataPacket` | Target → Source | Request file data |
| `clipboard::FormatDataPacket` | Source → Target | Clipboard data in requested format; payload: sequenceId (u32be) + formatName + data |
| `clipboard::FileDescriptorsPacket` | Source → Target | File descriptor list |
| `clipboard::FileDataPacket` | Source → Target | File content data |
| `clipboard::ErrorPacket` | Either | Error response |

**ClipboardUpdatePacket payload:**

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 4 | u32be | sequenceId |
| — | varint | — | formatCount |
| — | variable | — | formatNames[] | Each is a len-prefixed string |

**FormatDataPacket payload:**

| Offset | Size | Type | Field |
|--------|------|------|-------|
| 0x00 | 4 | u32be | sequenceId |
| — | — | len-prefixed string | formatName |
| — | variable | bytes | data |

---

## 8. Action-to-Packet Mapping

| Action | Outer Packet | Inner Packet | Key Detail |
|--------|-------------|-------------|------------|
| Disable peer | DeviceDataPacket | SettingsPacket | Target peer's `enabled` = `0x00` |
| Enable peer | DeviceDataPacket | SettingsPacket | Target peer's `enabled` = `0x01` |
| Mouse transition | GlobalDataPacket → DeviceDataPacket → DeviceDataPacket → GlobalDataPacket | SetOwnerPacket(prefix=0100) → InitiateFlowPacket → SetCurrentHostPacket → SetOwnerPacket | Source claims → initiates flow → target confirms |
| Peer position change | DeviceDataPacket | SettingsPacket | `--remove-from-flow` entries; `horizontal` field encodes layout |
| Unpair | GlobalDataPacket → DeviceDataPacket → DeviceDataPacket → DeviceDataPacket | SetOwnerPacket → InitiateFlowPacket(zeros) → SetCurrentHostPacket → SettingsPacket | `--remove-from-flow` for both peers, then TCP FIN |
| Heartbeat | HeartbeatPacket | (none) | 1-byte counter, ~15s interval |
| Claim ownership | GlobalDataPacket | SetOwnerPacket(prefix=0100) | Sent by source at flow start/unpair |
| Confirm ownership | GlobalDataPacket | SetOwnerPacket | Sent by target after flow arrival |

**Mouse transition choreography (full sequence):**

```
1. Source → Target:  GlobalDataPacket(SetOwnerPacket, hostname=source)
2. [~8 seconds]
3. Source → Target:  DeviceDataPacket(InitiateFlowPacket, direction, position)
4. Target → Source:  DeviceDataPacket(SetCurrentHostPacket, hostId=targetChannel)
5. Target → Source:  GlobalDataPacket(SetOwnerPacket, hostname=target)
6. Heartbeats continue
```

**Unpair choreography (full sequence):**

```
1. Source → Target:  GlobalDataPacket(SetOwnerPacket) + DeviceDataPacket(InitiateFlowPacket, zeros)
2. Target → Source:  DeviceDataPacket(SetCurrentHostPacket, hostId)
3. [~26 seconds]
4. Source → Target:  DeviceDataPacket(InitiateFlowPacket, data=counter)
5. Target → Source:  DeviceDataPacket(SetCurrentHostPacket, hostId)
6. Source → Target:  DeviceDataPacket(SettingsPacket, --remove-from-flow for both peers)
7. TCP FIN/ACK teardown
```

---

## 9. Implementation Notes

### Discovery
- Listen on both UDP 59870 and 59871.
- Official clients use broadcast AND directed packets.
- Packet padding (random-length) matters; too-short packets are ignored.
- The local Flow channel must match the local device's current Easy-Switch / host slot; do not infer it from the peer's advertised channel.

### TCP Client (Outbound) Sequence
1. Send `ClientHelloPacket` with hostname (bootstrap key).
2. Receive `ServerHelloPacket` (bootstrap key).
3. Derive session key from X25519 exchange.
4. Send `PromoteConnectionPacket` (bootstrap key).
5. Send `DeviceDataPacket(ClientDeviceConnect)` (session key, first session frame).
6. Wait for `DeviceDataPacket(ServerDeviceConnect)`.
7. Wait for `DeviceDataPacket(SettingsPacket)`.
8. Reply with exactly one `DeviceDataPacket(SettingsPacket)` using counter+1.
9. If the peer sends a corrected follow-up `SettingsPacket`, answer it once without emitting a burst, and advance the stored counter to the just-sent value.
10. Stay passive for heartbeat: do NOT send proactive `HeartbeatPacket`. Echo received heartbeats only.
11. Keep HID++ host-switching asynchronous. Do not block the TCP event loop for HID probing (~10s can cause Windows to FIN).
12. Split keyboard/mouse HID switching into independent per-device workers.

### TCP Server (Inbound) Sequence
1. Receive `ClientHelloPacket` (bootstrap key).
2. Send `ServerHelloPacket` (bootstrap key).
3. Derive session key.
4. Receive `PromoteConnectionPacket` (bootstrap key).
5. Receive `DeviceDataPacket(ClientDeviceConnect)` (session key).
6. Respond with `ServerDeviceConnect`, `SettingsPacket`, etc.

### Nested Encryption
- `DeviceDataPacket`: decrypt outer (session key), then decrypt inner frame (bootstrap key).
- `GlobalDataPacket`: decrypt outer (session key); nested `SetOwnerPacket` is plaintext within.
- `GlobalDataPacket` owner payload includes a wrapper (`hostname + 030302 + object length + inner length + allocator`) before the nested `SetOwnerPacket`.

### Critical Pitfalls
- **Do not** send a Settings x4 burst; this crashes opensource LogiMX.
- **Do not** send proactive outbound heartbeats from the non-initiating peer; Windows closes the connection with FIN.
- **Do not** perform synchronous HID switching during frame handling; queue it asynchronously with a 10s duplicate suppression.
- **Do not** reply to the peer's `GlobalData(SetOwnerPacket)` confirmation with another owner packet.
- **Do not** reuse a just-sent Settings counter locally; advance stored state to the transmitted `counter+1` value.

---

## 10. Remaining Unknowns

- Exact election rule for TCP initiator vs. acceptor role.
- Full field semantics for the last 4–12 bytes of the SettingsPacket state blob beyond known-identity vs. placeholder distinction.
- Exact format of keyboard HID reports inside DeviceDataPacket action payloads (opaque forwarding).

---

## Appendix A: Key Constants

```
Bootstrap key:      1316ee2215da62321e1e7257104dc24fd6a865e90eca357aa663c66f93da7182
Bootstrap keyId:   10512c128c6053cea372259d74b8438e60e88d25e5ab463fed92bacde551f394

Padding constants:
  kDiscoveryPad                          = 95
  kBeaconPad                             = 79
  kPingPad                               = 80
  kClientHelloPad                        = 71
  kServerHelloPad                        = 71
  kHeartbeatPad                          = 33
  kGlobalSetOwnerPad                     = 12
  kServerConnectInnerPad                 = 81
  kServerConnectOuterPad                 = 9
  kSettingsInnerPad                      = 84
  kSettingsOuterPad                      = 26
  kInitiateFlowReverseInnerPad           = 94
  kInitiateFlowReverseOuterPad           = 71
  kInitiateFlowForwardInnerPad           = 17
  kInitiateFlowForwardOuterPad           = 95
  kSetCurrentHostInnerPad                = 5
  kSetCurrentHostOuterPad                = 2
  kClipboardGlobalPad                    = 15

Discovery reply padding:
  kDiscoveryReplyBroadcastBeaconPad        = 44
  kDiscoveryReplyBroadcastPingPad        = 38
  kDiscoveryReplyDirectedBeaconPad       = 40
  kDiscoveryReplyDirectedPingPad         = 62
  kDiscoveryReplyPeerDiscoveryPad        = 20
  kDiscoveryReplyPeerBeaconPad           = 29

Beacon/Ping tails:
  kBeaconTailBroadcast                   = e9de
  kBeaconTailDirected                    = e9df
  Ping tail                              = e9dd

Flow edge positions:
  kFlowEdgePositionReverse               = 0.53294414
  kFlowEdgePositionForward               = 0.56255794

Device data tail:
  kDeviceDataTailLength                  = 84

Sentinel values:
  kUnsetChannel                          = 0xffffffff
```

---

**Protocol Specification:** Ahmed Abdelghany for LogiMX
