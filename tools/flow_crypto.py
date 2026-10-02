#!/usr/bin/env python3
"""Logitech Flow / Marconi capture crypto toolbox.

This replaces the pile of one-off decrypt and dump scanners with one workflow:

  1. Find Marconi keyIds in a pcap/pcapng.
  2. Extract candidate session keys from WinDbg logs or process dumps.
  3. Verify keys by actually decrypting frames for the matching keyId.
  4. Write decrypted plaintext plus JSON/CSV/text summaries.

The frame format on the wire is thekogans Ciphertext:
  keyId(32) | frameLen(u32be) | ivLen(u16be) | ctLen(u32be) | macLen(u16be)
  | iv | ciphertext | mac
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import math
import re
import socket
import struct
import sys
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Iterable, Iterator

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


FLOW_PORTS = {59869, 59870, 59871}
BOOTSTRAP_KEY_ID = bytes.fromhex(
    "10512c128c6053cea372259d74b8438e60e88d25e5ab463fed92bacde551f394"
)
BOOTSTRAP_KEY = bytes.fromhex(
    "1316ee2215da62321e1e7257104dc24fd6a865e90eca357aa663c66f93da7182"
)
KNOWN_KEYS = {BOOTSTRAP_KEY_ID.hex(): BOOTSTRAP_KEY.hex()}


def be16(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 2], "big")


def be32(buf: bytes, off: int) -> int:
    return int.from_bytes(buf[off : off + 4], "big")


def pad4(length: int) -> int:
    return (length + 3) & ~3


@dataclass
class Packet:
    no: int
    ts: float | None
    linktype: int
    data: bytes


@dataclass
class TransportPayload:
    frame: int
    ts: float | None
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    payload: bytes


@dataclass
class MarconiFrame:
    transport: TransportPayload
    key_id: bytes
    iv: bytes
    ciphertext: bytes
    mac: bytes
    frame_length: int


@dataclass
class DecryptRow:
    frame: int
    time: float | None
    proto: str
    src: str
    sport: int
    dst: str
    dport: int
    payloadLen: int
    keyId: str
    iv: str
    cipherLen: int
    mac: str
    decrypted: bool
    key: str = ""
    keySource: str = ""
    plaintextLength: int = 0
    packetOffset: int | None = None
    packetClass: str = ""
    plaintextPath: str = ""
    plaintextHead: str = ""
    strings: list[str] | None = None
    note: str = ""


@dataclass
class CandidateKey:
    key_id: str
    key: str
    source: str
    offset: str = ""
    hits: int = 0
    verifiedFrames: list[int] | None = None
    packetClasses: list[str] | None = None


def iter_pcap(path: Path) -> Iterator[Packet]:
    data = path.read_bytes()
    if len(data) < 4:
        return

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\x4d\x3c\xb2\xa1"):
        endian = "<"
        nano = magic == b"\x4d\x3c\xb2\xa1"
        linktype = struct.unpack_from(endian + "I", data, 20)[0]
        off = 24
        no = 0
        while off + 16 <= len(data):
            sec, frac, caplen, _origlen = struct.unpack_from(endian + "IIII", data, off)
            off += 16
            pkt = data[off : off + caplen]
            off += caplen
            no += 1
            divisor = 1_000_000_000 if nano else 1_000_000
            yield Packet(no, sec + frac / divisor, linktype, pkt)
        return

    if magic in (b"\xa1\xb2\xc3\xd4", b"\xa1\xb2\x3c\x4d"):
        endian = ">"
        nano = magic == b"\xa1\xb2\x3c\x4d"
        linktype = struct.unpack_from(endian + "I", data, 20)[0]
        off = 24
        no = 0
        while off + 16 <= len(data):
            sec, frac, caplen, _origlen = struct.unpack_from(endian + "IIII", data, off)
            off += 16
            pkt = data[off : off + caplen]
            off += caplen
            no += 1
            divisor = 1_000_000_000 if nano else 1_000_000
            yield Packet(no, sec + frac / divisor, linktype, pkt)
        return

    if magic != b"\x0a\x0d\x0d\x0a":
        raise ValueError(f"{path}: unsupported capture format")

    yield from iter_pcapng(data)


def iter_pcapng(data: bytes) -> Iterator[Packet]:
    off = 0
    endian = "<"
    linktypes: dict[int, int] = {}
    no = 0
    while off + 12 <= len(data):
        block_type, block_len = struct.unpack_from(endian + "II", data, off)
        if block_len < 12 or off + block_len > len(data):
            # Section Header Block can switch endianness before we know it.
            block_type_be, block_len_be = struct.unpack_from(">II", data, off)
            if block_type_be == 0x0A0D0D0A and 12 <= block_len_be <= len(data) - off:
                block_type, block_len = block_type_be, block_len_be
                endian = ">"
            else:
                raise ValueError(f"bad pcapng block at offset {off:#x}")

        body = data[off + 8 : off + block_len - 4]
        if block_type == 0x0A0D0D0A:
            bom = body[:4]
            endian = "<" if bom == b"\x4d\x3c\x2b\x1a" else ">"
            linktypes.clear()
        elif block_type == 0x00000001 and len(body) >= 8:
            iface_id = len(linktypes)
            linktypes[iface_id] = struct.unpack_from(endian + "H", body, 0)[0]
        elif block_type == 0x00000006 and len(body) >= 20:
            iface_id, ts_hi, ts_lo, caplen, _origlen = struct.unpack_from(endian + "IIIII", body, 0)
            pkt = body[20 : 20 + caplen]
            no += 1
            ts = ((ts_hi << 32) | ts_lo) / 1_000_000
            yield Packet(no, ts, linktypes.get(iface_id, 1), pkt)

        off += block_len


def transport_payload(packet: Packet) -> TransportPayload | None:
    pkt = packet.data
    if packet.linktype != 1:
        return None
    if len(pkt) < 34 or pkt[12:14] != b"\x08\x00":
        return None

    ip = pkt[14:]
    if not ip or (ip[0] >> 4) != 4:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if len(ip) < ihl + 8:
        return None
    total = be16(ip, 2)
    if total < ihl or len(ip) < total:
        return None

    src = socket.inet_ntoa(ip[12:16])
    dst = socket.inet_ntoa(ip[16:20])
    proto = ip[9]
    body = ip[ihl:total]
    if proto == 17 and len(body) >= 8:
        sport, dport, length = be16(body, 0), be16(body, 2), be16(body, 4)
        if 8 <= length <= len(body):
            return TransportPayload(packet.no, packet.ts, "udp", src, sport, dst, dport, body[8:length])
    if proto == 6 and len(body) >= 20:
        sport, dport = be16(body, 0), be16(body, 2)
        thl = (body[12] >> 4) * 4
        if 20 <= thl <= len(body):
            return TransportPayload(packet.no, packet.ts, "tcp", src, sport, dst, dport, body[thl:])
    return None


def parse_marconi_frame(transport: TransportPayload) -> MarconiFrame | None:
    payload = transport.payload
    if len(payload) < 60:
        return None
    frame_len = be32(payload, 32)
    iv_len = be16(payload, 36)
    ct_len = be32(payload, 38)
    mac_len = be16(payload, 42)
    if frame_len != len(payload) - 36:
        return None
    if 8 + iv_len + ct_len + mac_len != frame_len:
        return None
    if len(payload) != 44 + iv_len + ct_len + mac_len:
        return None

    iv_off = 44
    ct_off = iv_off + iv_len
    mac_off = ct_off + ct_len
    return MarconiFrame(
        transport=transport,
        key_id=payload[:32],
        iv=payload[iv_off:ct_off],
        ciphertext=payload[ct_off:mac_off],
        mac=payload[mac_off : mac_off + mac_len],
        frame_length=frame_len,
    )


def iter_marconi_frames(path: Path) -> Iterator[MarconiFrame]:
    for packet in iter_pcap(path):
        transport = transport_payload(packet)
        if not transport:
            continue
        if transport.sport not in FLOW_PORTS and transport.dport not in FLOW_PORTS:
            continue
        frame = parse_marconi_frame(transport)
        if frame:
            yield frame


def plaintext_packet_offset(plaintext: bytes) -> int | None:
    if len(plaintext) < 2:
        return None
    off = 2 + plaintext[0]
    if plaintext[1] & 1:
        off += 24
    return off if off <= len(plaintext) else None


def packet_class(plaintext: bytes) -> str:
    off = plaintext_packet_offset(plaintext)
    windows = []
    if off is not None:
        windows.append(plaintext[off : off + 256])
    windows.append(plaintext[:320])
    for window in windows:
        match = re.search(rb"([A-Za-z0-9_:]+Packet)", window)
        if match:
            return match.group(1).decode("ascii", "replace")
    return ""


def interesting_strings(plaintext: bytes) -> list[str]:
    out: list[str] = []
    for raw in re.findall(rb"[A-Za-z0-9_.:/@+-]{4,}", plaintext):
        text = raw.decode("latin1", "replace")
        if any(token in text for token in ("Packet", "desktop", "DESKTOP", "dinm", "FARS", "AECD")):
            out.append(text)
    return out[:12]


def looks_like_plaintext(plaintext: bytes) -> bool:
    if packet_class(plaintext):
        return True
    return b"FARS" in plaintext[:512] or b"Packet" in plaintext[:512]


def shannon_entropy(buf: bytes) -> float:
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    entropy = 0.0
    for count in counts:
        if count:
            p = count / len(buf)
            entropy -= p * math.log2(p)
    return entropy


def valid_aes_key(buf: bytes) -> bool:
    return len(buf) == 32 and len(set(buf)) >= 20 and shannon_entropy(buf) >= 4.35


def parse_hex_key(value: str) -> bytes:
    cleaned = re.sub(r"[^0-9a-fA-F]", "", value)
    if len(cleaned) != 64:
        raise argparse.ArgumentTypeError("AES-256 key must be 64 hex characters")
    return bytes.fromhex(cleaned)


def parse_key_file(path: Path) -> list[CandidateKey]:
    candidates: list[CandidateKey] = []
    seen: set[tuple[str, str]] = set()
    for lineno, line in enumerate(path.read_text(errors="replace").splitlines(), 1):
        key_id = ""
        key = ""
        if match := re.search(r"keyId\s*[:=]\s*([0-9a-fA-F]{64})", line):
            key_id = match.group(1).lower()
        if match := re.search(r"\b(?:key|aes|session_key)\s*[:=]\s*([0-9a-fA-F]{64})", line):
            key = match.group(1).lower()
        if not key:
            hexes = re.findall(r"\b[0-9a-fA-F]{64}\b", line)
            if len(hexes) == 1:
                key = hexes[0].lower()
            elif len(hexes) >= 2:
                key_id, key = hexes[0].lower(), hexes[1].lower()
        if key:
            item = (key_id, key)
            if item not in seen:
                seen.add(item)
                candidates.append(CandidateKey(key_id, key, f"{path}:{lineno}"))
    return candidates


def load_manual_keys(values: Iterable[str], files: Iterable[Path]) -> list[CandidateKey]:
    candidates = [
        CandidateKey("", BOOTSTRAP_KEY.hex(), "built-in bootstrap"),
    ]
    for value in values:
        candidates.append(CandidateKey("", parse_hex_key(value).hex(), "--key"))
    for path in files:
        candidates.extend(parse_key_file(path))
    return dedupe_candidates(candidates)


def dedupe_candidates(candidates: Iterable[CandidateKey]) -> list[CandidateKey]:
    seen: set[tuple[str, str, str]] = set()
    out: list[CandidateKey] = []
    for cand in candidates:
        key = cand.key.lower()
        key_id = cand.key_id.lower()
        marker = (key_id, key, cand.source)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(
            CandidateKey(
                key_id,
                key,
                cand.source,
                cand.offset,
                cand.hits,
                cand.verifiedFrames,
                cand.packetClasses,
            )
        )
    return out


def decrypt_one(frame: MarconiFrame, key: bytes) -> bytes | None:
    try:
        return AESGCM(key).decrypt(frame.iv, frame.ciphertext + frame.mac, None)
    except Exception:
        return None


def verify_candidates(candidates: list[CandidateKey], frames: list[MarconiFrame]) -> list[CandidateKey]:
    verified: list[CandidateKey] = []
    for cand in candidates:
        key = bytes.fromhex(cand.key)
        frame_subset = frames
        if cand.key_id:
            frame_subset = [f for f in frames if f.key_id.hex() == cand.key_id]
        hit_frames: list[int] = []
        classes: list[str] = []
        inferred_key_id = cand.key_id
        for frame in frame_subset:
            pt = decrypt_one(frame, key)
            if pt is None or not looks_like_plaintext(pt):
                continue
            hit_frames.append(frame.transport.frame)
            klass = packet_class(pt)
            if klass:
                classes.append(klass)
            if not inferred_key_id:
                inferred_key_id = frame.key_id.hex()
            if len(hit_frames) >= 8:
                break
        if hit_frames:
            out = CandidateKey(
                inferred_key_id,
                cand.key,
                cand.source,
                cand.offset,
                len(hit_frames),
                hit_frames,
                sorted(set(classes)),
            )
            verified.append(out)
    return dedupe_candidates(verified)


def extract_from_dump(dump: Path, target_key_ids: Iterable[str]) -> list[CandidateKey]:
    data = dump.read_bytes()
    candidates: list[CandidateKey] = []
    seen: set[tuple[str, str, str]] = set()
    key_ids = [bytes.fromhex(k) for k in target_key_ids if k and k != BOOTSTRAP_KEY_ID.hex()]
    preferred_relative_offsets = [0x70, 0x68, 0x78, 0x80, 0x60, 0x88]

    for key_id in key_ids:
        pos = 0
        while True:
            hit = data.find(key_id, pos)
            if hit < 0:
                break
            for rel in preferred_relative_offsets:
                start = hit + rel
                key = data[start : start + 32]
                if valid_aes_key(key):
                    marker = (key_id.hex(), key.hex(), f"{hit:#x}+{rel:#x}")
                    if marker not in seen:
                        seen.add(marker)
                        candidates.append(
                            CandidateKey(key_id.hex(), key.hex(), str(dump), f"{hit:#x}+{rel:#x}")
                        )

            lo = max(0, hit - 0x100)
            hi = min(len(data) - 32, hit + 0x300)
            for start in range(lo, hi + 1, 8):
                key = data[start : start + 32]
                if not valid_aes_key(key):
                    continue
                marker = (key_id.hex(), key.hex(), f"{start:#x}")
                if marker in seen:
                    continue
                seen.add(marker)
                candidates.append(CandidateKey(key_id.hex(), key.hex(), str(dump), f"{start:#x}"))
            pos = hit + 1
    return candidates


def parse_windbg_db_blocks(path: Path) -> Iterator[tuple[str, bytes]]:
    label = ""
    chunks: list[int] = []
    for line in path.read_text(errors="replace").splitlines():
        stripped = line.strip()
        if stripped and not re.match(r"^[0-9a-fA-F]{8}`[0-9a-fA-F]{8}\s+", stripped):
            if chunks:
                yield label, bytes(chunks)
                chunks = []
            if re.match(r"^[A-Z0-9_ -]{3,}$", stripped):
                label = stripped
            continue
        match = re.match(r"^[0-9a-fA-F]{8}`[0-9a-fA-F]{8}\s+(.+)$", stripped)
        if not match:
            continue
        hex_part = match.group(1).split("  ", 1)[0]
        for token in re.findall(r"\b[0-9a-fA-F]{2}\b", hex_part.replace("-", " ")):
            chunks.append(int(token, 16))
    if chunks:
        yield label, bytes(chunks)


def extract_from_windbg_log(path: Path, target_key_ids: Iterable[str]) -> list[CandidateKey]:
    key_ids = [bytes.fromhex(k) for k in target_key_ids if k]
    candidates: list[CandidateKey] = []
    seen: set[tuple[str, str, str]] = set()
    for label, block in parse_windbg_db_blocks(path):
        for key_id in key_ids:
            pos = 0
            while True:
                hit = block.find(key_id, pos)
                if hit < 0:
                    break
                for rel in (0x70, 0x68, 0x78, 0x80, 0x00):
                    start = hit + rel
                    key = block[start : start + 32]
                    if valid_aes_key(key):
                        marker = (key_id.hex(), key.hex(), f"{label}:{hit:#x}+{rel:#x}")
                        if marker not in seen:
                            seen.add(marker)
                            candidates.append(
                                CandidateKey(
                                    key_id.hex(),
                                    key.hex(),
                                    str(path),
                                    f"{label}:{hit:#x}+{rel:#x}",
                                )
                            )
                pos = hit + 1
    return candidates


def extract_key_ids(frames: list[MarconiFrame]) -> list[str]:
    return sorted({frame.key_id.hex() for frame in frames})


def decrypt_capture(path: Path, outdir: Path, candidates: list[CandidateKey]) -> list[DecryptRow]:
    outdir.mkdir(parents=True, exist_ok=True)
    frames = list(iter_marconi_frames(path))
    rows: list[DecryptRow] = []
    key_map: dict[str, list[CandidateKey]] = {}
    wildcard: list[CandidateKey] = []
    for cand in candidates:
        if cand.key_id:
            key_map.setdefault(cand.key_id, []).append(cand)
        else:
            wildcard.append(cand)

    for frame in frames:
        key_id = frame.key_id.hex()
        transport = frame.transport
        row = DecryptRow(
            frame=transport.frame,
            time=transport.ts,
            proto=transport.proto,
            src=transport.src,
            sport=transport.sport,
            dst=transport.dst,
            dport=transport.dport,
            payloadLen=len(transport.payload),
            keyId=key_id,
            iv=frame.iv.hex(),
            cipherLen=len(frame.ciphertext),
            mac=frame.mac.hex(),
            decrypted=False,
            strings=[],
        )

        for cand in key_map.get(key_id, []) + wildcard:
            pt = decrypt_one(frame, bytes.fromhex(cand.key))
            if pt is None:
                continue
            name = f"frame_{transport.frame:06d}_{key_id[:8]}.bin"
            plain_path = outdir / name
            plain_path.write_bytes(pt)
            row.decrypted = True
            row.key = cand.key
            row.keySource = cand.source
            row.plaintextLength = len(pt)
            row.packetOffset = plaintext_packet_offset(pt)
            row.packetClass = packet_class(pt)
            row.plaintextPath = str(plain_path)
            row.plaintextHead = pt[:128].hex()
            row.strings = interesting_strings(pt)
            break
        if not row.decrypted:
            row.note = "no matching key"
        rows.append(row)

    return rows


def write_rows(rows: list[DecryptRow], outdir: Path) -> None:
    json_rows = [asdict(row) for row in rows]
    (outdir / "summary.json").write_text(json.dumps(json_rows, indent=2))
    if rows:
        with (outdir / "summary.csv").open("w", newline="") as fh:
            writer = csv.DictWriter(fh, fieldnames=list(json_rows[0].keys()))
            writer.writeheader()
            writer.writerows(json_rows)
    with (outdir / "summary.txt").open("w") as fh:
        for row in rows:
            klass = row.packetClass or "-"
            dec = "dec" if row.decrypted else "enc"
            fh.write(
                f"#{row.frame:<6} {row.proto.upper():3s} {row.src}:{row.sport} -> "
                f"{row.dst}:{row.dport} len={row.payloadLen:<4} key={row.keyId[:8]} "
                f"{dec} {klass} {row.note}\n"
            )


def derive_thekogans_key(
    secret: bytes,
    salt: bytes,
    key_length: int = 32,
    hash_name: str = "SHA512",
    count: int = 1,
) -> bytes:
    hashes = {"SHA512": hashlib.sha512, "SHA256": hashlib.sha256}
    if hash_name.upper() not in hashes:
        raise ValueError(f"unsupported hash {hash_name}")
    h_factory = hashes[hash_name.upper()]
    key = bytearray()
    previous = b""
    while len(key) < key_length:
        h = h_factory()
        if previous:
            h.update(previous)
        h.update(secret)
        h.update(salt)
        previous = h.digest()
        for _ in range(1, count):
            previous = h_factory(previous).digest()
        key.extend(previous[: key_length - len(key)])
    return bytes(key)


def _parse_fars_dhe_key(plaintext: bytes) -> bytes | None:
    """Extract X25519 public key from a decrypted ClientHello/ServerHello."""
    marker = b"X25519AsymmetricKey"
    idx = plaintext.find(marker)
    if idx < 0:
        return None
    key_start = idx + len(marker) + 3  # marker + 2-byte header + 1-byte length
    key = plaintext[key_start:key_start + 32]
    if len(key) == 32 and shannon_entropy(key) >= 4.0:
        return key
    return None


def derive_session_from_handshake(
    frames,
    bootstrap_key: bytes,
    manual_secret: bytes | None = None,
    private_key: bytes | None = None,
    salt: bytes | None = None,
):
    """Derive session key from bootstrap-decrypted ClientHello/ServerHello.

    Returns (key_hex, key_id_hex, source) or (None, None, reason).
    """
    from hashlib import sha512

    cl_pt = None
    sh_pt = None
    for frame in frames:
        pt = decrypt_one(frame, bootstrap_key)
        if pt is None or not looks_like_plaintext(pt):
            continue
        klass = packet_class(pt)
        if klass == "ClientHelloPacket" and cl_pt is None:
            cl_pt = pt
        elif klass == "ServerHelloPacket" and sh_pt is None:
            sh_pt = pt
        if cl_pt and sh_pt:
            break

    if not cl_pt or not sh_pt:
        return None, None, "ClientHello or ServerHello not found in bootstrap frames"

    cl_pub = _parse_fars_dhe_key(cl_pt)
    sh_pub = _parse_fars_dhe_key(sh_pt)

    if not cl_pub or not sh_pub:
        return None, None, "X25519 keys not found in handshake"

    # Determine shared secret
    if manual_secret:
        secret = manual_secret
        source = "manual-secret"
    elif private_key:
        try:
            priv = X25519PrivateKey.from_private_bytes(private_key)
            secret = priv.exchange(cl_pub)
            source = "ecdh(priv,cl_pub)"
        except Exception as e:
            return None, None, "ECDH failed: {}".format(e)
    else:
        return (
            None, None,
            "keys extracted (cl_pub={}... sh_pub={}...) "
            "but no private key or manual secret; pass --private-key or --manual-secret".format(
                cl_pub.hex()[:16], sh_pub.hex()[:16])
        )

    # Derive session key via thekogans PBKDF
    effective_salt = salt if salt else (cl_pub + sh_pub)
    key = derive_thekogans_key(secret, effective_salt, 32, "SHA512", 1)
    key_id = sha512(key).digest()[:32]

    return key.hex(), key_id.hex(), source



def cmd_keyids(args: argparse.Namespace) -> int:
    frames = list(iter_marconi_frames(args.capture))
    counts: dict[str, int] = {}
    for frame in frames:
        counts[frame.key_id.hex()] = counts.get(frame.key_id.hex(), 0) + 1
    for key_id, count in sorted(counts.items(), key=lambda item: (-item[1], item[0])):
        marker = " bootstrap" if key_id == BOOTSTRAP_KEY_ID.hex() else ""
        print(f"{key_id} {count}{marker}")
    return 0


def collect_candidates(args: argparse.Namespace, frames: list[MarconiFrame]) -> list[CandidateKey]:
    candidates = load_manual_keys(args.key or [], args.keys_file or [])
    target_ids = extract_key_ids(frames)
    for dump in args.dump or []:
        print(f"scanning dump {dump}", file=sys.stderr)
        candidates.extend(extract_from_dump(dump, target_ids))
    for log in args.key_log or []:
        candidates.extend(extract_from_windbg_log(log, target_ids))
    return dedupe_candidates(candidates)


def cmd_extract_keys(args: argparse.Namespace) -> int:
    frames = list(iter_marconi_frames(args.capture))
    candidates = collect_candidates(args, frames)
    verified = verify_candidates(candidates, frames)
    out = [asdict(item) for item in verified]
    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json.dumps(out, indent=2))
    print(json.dumps(out, indent=2))
    return 0 if verified else 1


def cmd_decrypt(args: argparse.Namespace) -> int:
    frames = list(iter_marconi_frames(args.capture))
    candidates = collect_candidates(args, frames)
    verified = verify_candidates(candidates, frames)

    # Try auto-derive session key from bootstrap-decrypted handshake
    if not any(c.key_id for c in verified if c.key_id != BOOTSTRAP_KEY_ID.hex()):
        priv_bytes = bytes.fromhex(args.private_key) if args.private_key else None
        secret_bytes = bytes.fromhex(args.manual_secret) if args.manual_secret else None
        salt_bytes = bytes.fromhex(args.salt) if args.salt else None
        key_hex, key_id_hex, source = derive_session_from_handshake(
            frames, BOOTSTRAP_KEY,
            manual_secret=secret_bytes,
            private_key=priv_bytes,
            salt=salt_bytes,
        )
        if key_hex:
            print("auto-derived session key: keyId={}... source={}".format(key_id_hex[:16], source), file=sys.stderr)
            candidates.append(CandidateKey(key_id_hex, key_hex, source))
            verified = verify_candidates(candidates, frames)

    # Keep manually supplied keys even if only later frames prove useful.
    candidates = dedupe_candidates(verified + candidates)
    rows = decrypt_capture(args.capture, args.outdir, candidates)
    write_rows(rows, args.outdir)
    decrypted = sum(1 for row in rows if row.decrypted)
    total = len(rows)
    print(f"frames={total} decrypted={decrypted} outdir={args.outdir}")
    for key in verified:
        classes = ",".join(key.packetClasses or [])
        print(f"verified keyId={key.key_id[:8]} key={key.key} hits={key.hits} {classes}")
    return 0 if decrypted else 1


def cmd_derive(args: argparse.Namespace) -> int:
    key = derive_thekogans_key(
        bytes.fromhex(args.secret),
        bytes.fromhex(args.salt),
        args.key_length,
        args.hash,
        args.count,
    )
    print(key.hex())
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="cmd", required=True)

    keyids = sub.add_parser("keyids", help="list Marconi keyIds in a pcap/pcapng")
    keyids.add_argument("capture", type=Path)
    keyids.set_defaults(func=cmd_keyids)

    def add_key_inputs(p: argparse.ArgumentParser) -> None:
        p.add_argument("--key", action="append", help="raw AES-256 key hex; repeatable")
        p.add_argument("--keys-file", action="append", type=Path, help="text/json-ish file containing key hex")
        p.add_argument("--dump", action="append", type=Path, help="process dump to scan for session keys")
        p.add_argument("--key-log", action="append", type=Path, help="WinDbg keytrap log to scan")

    extract = sub.add_parser("extract-keys", help="extract and verify session keys against a capture")
    extract.add_argument("capture", type=Path)
    add_key_inputs(extract)
    extract.add_argument("--out", type=Path, help="write verified keys JSON")
    extract.set_defaults(func=cmd_extract_keys)

    decrypt = sub.add_parser("decrypt", help="decrypt Marconi frames from a capture")
    decrypt.add_argument("capture", type=Path)
    add_key_inputs(decrypt)
    decrypt.add_argument("--outdir", type=Path, default=Path("decrypted"))
    decrypt.add_argument("--private-key", help="X25519 private key hex for session key derivation")
    decrypt.add_argument("--manual-secret", help="pre-computed X25519 shared secret hex")
    decrypt.add_argument("--salt", help="PBKDF salt hex (default: cl_pub+sh_pub)")
    decrypt.set_defaults(func=cmd_decrypt)

    derive = sub.add_parser("derive", help="derive thekogans PBKDF-style session key")
    derive.add_argument("--secret", required=True, help="X25519 shared secret hex")
    derive.add_argument("--salt", required=True, help="binary salt hex")
    derive.add_argument("--hash", default="SHA512")
    derive.add_argument("--count", type=int, default=1)
    derive.add_argument("--key-length", type=int, default=32)
    derive.set_defaults(func=cmd_derive)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
