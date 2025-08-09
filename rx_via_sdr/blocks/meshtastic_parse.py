#!/usr/bin/env python3
import pmt
from gnuradio import gr

from meshtastic import mesh_pb2
import base64
import binascii
import re
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime

from typing import Dict, Any

PSK_MAP: Dict[int, bytes] = {}


def xor_hash(data: bytes) -> int:
    h = 0
    for b in data:
        h ^= b
    return h


def parse_psk(text: str) -> bytes:
    text = text.strip()
    if re.fullmatch(r"[0-9A-Fa-f]{2,64}", text):
        return bytes.fromhex(text)
    try:
        return base64.b64decode(text)
    except binascii.Error as exc:
        raise ValueError("PSK must be hex or base64") from exc


def aes_decrypt_ctr(key: bytes, sender: int, pkt_id: int, ciphertext: bytes) -> bytes:
    if len(key) not in (16, 32):
        raise ValueError("PSK must be 16 or 32 bytes")
    counter_block = pkt_id.to_bytes(8, "little") + sender.to_bytes(4, "little") + b"\x00" * 4
    cipher = Cipher(algorithms.AES(key), modes.CTR(counter_block))
    decryptor = cipher.decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()


def parse_data_proto(blob: bytes) -> mesh_pb2.Data | None:
    msg = mesh_pb2.Data()
    try:
        msg.ParseFromString(blob)
        return msg
    except Exception:
        return None


def add_psk(name: str, key: bytes) -> None:
    ch_hash = xor_hash(name.encode()) ^ xor_hash(key)
    PSK_MAP[ch_hash] = key
    print(f"Channel '{name}' -> hash 0x{ch_hash:02X}")


def _u32_le(bs: bytes) -> int:
    """Helper: read a 32-bit little-endian unsigned int from *bs*."""
    return int.from_bytes(bs, "little", signed=False)


def decode_layer1(raw: bytes) -> Dict[str, Any] | None:
    """Return a dict with Meshtastic layer-1 header fields.
    If the packet is too short, return *None*.
    """
    if len(raw) < 16:
        return None

    dest = _u32_le(raw[0:4])
    sender = _u32_le(raw[4:8])
    packet_id = _u32_le(raw[8:12])
    flags = raw[12]
    channel_hash = raw[13]
    next_hop = raw[14]
    relay = raw[15]
    payload = raw[16:]

    return {
        "dest": dest,
        "sender": sender,
        "packet_id": packet_id,
        "flags_raw": flags,
        "hop_limit": flags & 0x07,
        "want_ack": bool(flags & 0x08),
        "via_mqtt": bool(flags & 0x10),
        "hop_start": (flags >> 5) & 0x07,
        "channel_hash": channel_hash,
        "next_hop": next_hop,
        "relay": relay,
        "payload": payload,
    }


def hexdump(data: bytes, width: int = 16) -> None:
    """Print a classic hex dump of *data*."""
    for off in range(0, len(data), width):
        chunk = data[off : off + width]
        hexpart = " ".join(f"{b:02X}" for b in chunk)
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        print(f"{off:04X}  {hexpart:<{width*3}}  {asc}")


def print_header(h: Dict[str, Any]) -> None:
    """Print Meshtastic layer-1 header fields in offline decode format."""
    flags = h["flags_raw"]
    want_ack = h["want_ack"]
    via_mqtt = h["via_mqtt"]
    hop_limit = h["hop_limit"]
    hop_start = h["hop_start"]

    print("Header:")
    print(f"Dest        : 0x{h['dest']:08X}")
    print(f"Sender      : 0x{h['sender']:08X}")
    print(f"Packet-ID   : 0x{h['packet_id']:08X}")
    print(f"Flags       : 0x{flags:02X} [HopLimit={hop_limit} HopStart={hop_start} WantAck={want_ack} ViaMQTT={via_mqtt}]")
    print(f"ChannelHash : 0x{h['channel_hash']:02X}")
    print(f"Next-hop    : {h['next_hop']}")
    print(f"Relay       : {h['relay']}")


class meshtastic_parse(gr.basic_block):
    def __init__(self, print_msg=False, decrypt=True, encryption_keys=dict()):
        super().__init__(
            name="meshtastic_parse",
            in_sig=None,
            out_sig=None,
        )

        self.message_port_register_in(pmt.intern("msg"))
        self.message_port_register_out(pmt.intern("msg_out"))
        self.set_msg_handler(pmt.intern("msg"), self._handle)
        self.print_msg = print_msg
        self.decrypt = decrypt

        # # Default PSK for MediumSlow channel
        # add_psk("MediumSlow", parse_psk("1PG7OiApB1nwvP+rz05pAQ=="))
        for k, v in encryption_keys.items():
            add_psk(k, parse_psk(v))


    def set_decrypt(self, decrypt):
        self.decrypt = bool(decrypt)


    def _handle(self, msg):
        # Ignore empty messages
        if pmt.is_null(msg):
            return

        # msg is a PMT u8vector containing the raw payload bytes
        payload = pmt.to_python(msg)

        # timestamp and parse layer-1
        hdr = decode_layer1(payload)
        if hdr is None:
            print("Frame too short:")
            hexdump(payload)
            return

        if self.print_msg:
            print(f"{datetime.now():%Y-%m-%d %H:%M:%S.%f}")
            print_header(hdr)

        data = hdr["payload"]

        # attempt decryption and parse layer-2 protobuf
        if self.decrypt:
            key = PSK_MAP.get(hdr["channel_hash"])
            if key:
                try:
                    data = aes_decrypt_ctr(key, hdr["sender"], hdr["packet_id"], data)
                except Exception as exc:
                    if self.print_msg: print(f"Decryption failed: {exc}")

            data_msg = parse_data_proto(data)
            if self.print_msg:
                if data_msg:
                    print("Payload (proto deserialized):")
                    print(str(data_msg).rstrip("\n"))
                else:
                    print("Payload (hex, because proto deserialized failed):")
                    hexdump(data)
                print()

        # publish decrypted frame (header + payload) as bytes
        # header bytes are the first 16 bytes of the original message
        hdr_bytes = bytes(payload[:16])
        # ensure payload and data are byte sequences (not numpy arrays)
        data = bytes(data)
        frame = hdr_bytes + data

        # publish as u8vector
        self.message_port_pub(
            pmt.intern("msg_out"), pmt.init_u8vector(len(frame), list(frame))
        )
