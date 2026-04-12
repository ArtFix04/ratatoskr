"""
Ratatoskr packet format.

Wire layout (binary, big-endian):
┌────────────┬──────────────┬──────────────┬─────────────────────────────┐
│ version    │ msg_type     │ next_hop_len │ next_hop (ASCII addr:port)  │
│  1 byte    │  1 byte      │  1 byte      │  next_hop_len bytes         │
├────────────┴──────────────┴──────────────┴─────────────────────────────┤
│ payload_len  (4 bytes, uint32)                                          │
├─────────────────────────────────────────────────────────────────────────┤
│ payload  (payload_len bytes)                                            │
└─────────────────────────────────────────────────────────────────────────┘

msg_type values:
  Plain (direct / fallback mode):
    0x01  RELAY        — forward raw payload to next_hop
    0x02  EXIT         — connect to target and pipe
    0x03  RESPONSE     — plain response back toward client

  Onion-encrypted:
    0x11  ONION_RELAY    — decrypt one NaCl layer, get inner Packet, forward
                           to next_hop field of *this* packet
    0x12  ONION_EXIT     — decrypt innermost layer, extract "host:port\\n", connect
    0x14  ONION_UDP_EXIT — like ONION_EXIT but sends a UDP datagram; returns reply
    0x15  ONION_UDP_RESP — UDP reply from exit node, piped back to client
"""

from __future__ import annotations

import struct
from dataclasses import dataclass
from enum import IntEnum

VERSION = 0x01
HEADER_FIXED = 3   # version + msg_type + next_hop_len
PAYLOAD_LEN_SIZE = 4


class MsgType(IntEnum):
    # Plain / fallback mode
    RELAY    = 0x01
    EXIT     = 0x02
    RESPONSE = 0x03
    # Onion-encrypted
    ONION_RELAY    = 0x11
    ONION_EXIT     = 0x12
    ONION_UDP_EXIT = 0x14
    ONION_UDP_RESP = 0x15

    def is_onion(self) -> bool:
        return self in (
            MsgType.ONION_RELAY, MsgType.ONION_EXIT,
            MsgType.ONION_UDP_EXIT, MsgType.ONION_UDP_RESP,
        )


@dataclass
class Packet:
    msg_type: MsgType
    next_hop: str        # Yggdrasil IPv6 address string, empty for EXIT
    payload: bytes

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        hop_encoded = self.next_hop.encode("ascii")
        if len(hop_encoded) > 255:
            raise ValueError("next_hop address too long")
        header = struct.pack(
            "!BBB",
            VERSION,
            int(self.msg_type),
            len(hop_encoded),
        )
        payload_len = struct.pack("!I", len(self.payload))
        return header + hop_encoded + payload_len + self.payload

    @classmethod
    def from_bytes(cls, data: bytes) -> "Packet":
        if len(data) < HEADER_FIXED:
            raise ValueError("Packet too short for header")
        version, msg_type_raw, hop_len = struct.unpack_from("!BBB", data, 0)
        if version != VERSION:
            raise ValueError(f"Unsupported packet version: {version}")
        offset = HEADER_FIXED
        if len(data) < offset + hop_len + PAYLOAD_LEN_SIZE:
            raise ValueError("Packet too short for next_hop + payload_len")
        next_hop = data[offset : offset + hop_len].decode("ascii")
        offset += hop_len
        (payload_len,) = struct.unpack_from("!I", data, offset)
        offset += PAYLOAD_LEN_SIZE
        if len(data) < offset + payload_len:
            raise ValueError("Packet too short for declared payload length")
        payload = data[offset : offset + payload_len]
        return cls(
            msg_type=MsgType(msg_type_raw),
            next_hop=next_hop,
            payload=payload,
        )

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @classmethod
    async def read_from_stream(
        cls, reader: "asyncio.StreamReader"  # noqa: F821
    ) -> "Packet":
        """Read exactly one packet from an asyncio StreamReader."""
        header_raw = await reader.readexactly(HEADER_FIXED)
        version, msg_type_raw, hop_len = struct.unpack("!BBB", header_raw)
        if version != VERSION:
            raise ValueError(f"Unsupported packet version: {version}")
        rest = await reader.readexactly(hop_len + PAYLOAD_LEN_SIZE)
        next_hop = rest[:hop_len].decode("ascii")
        (payload_len,) = struct.unpack_from("!I", rest, hop_len)
        payload = await reader.readexactly(payload_len)
        return cls(MsgType(msg_type_raw), next_hop, payload)
