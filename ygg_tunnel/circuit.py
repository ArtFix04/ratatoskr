"""
Circuit building and onion packet construction (client-side).

A Circuit is an N-hop path (default 3): Guard → [Middle…] → Exit.

Onion construction (built from inside out):

  Innermost (for Exit):
    plaintext  = b"<host>:<port>\\n"
    ciphertext = SealedBox(exit.pubkey).encrypt(plaintext)
    inner_pkt  = Packet(ONION_EXIT, "", ciphertext)

  Middle layers (for each intermediate hop, inside-out):
    ciphertext = SealedBox(hop.pubkey).encrypt(prev_pkt.to_bytes())
    pkt        = Packet(ONION_RELAY, _hop_addr(next_hop), ciphertext)

  Outermost (for Guard):
    ciphertext = SealedBox(guard.pubkey).encrypt(mid_pkt.to_bytes())
    outer_pkt  = Packet(ONION_RELAY, _hop_addr(middle), ciphertext)

The client connects to guard.addr:guard.port and sends outer_pkt.to_bytes().
Subsequent TCP data (from the browser) flows through the open connection chain.

Circuit rotation:
  CircuitManager holds one active Circuit and rebuilds it every ROTATION_SECS.
  The SOCKS5 connect handler calls CircuitManager.get_circuit() to get a live
  circuit, then connects to the guard and sends the onion packet.
"""

from __future__ import annotations

import asyncio
import logging
import random
import time
from dataclasses import dataclass, field
from typing import Optional, Tuple

from .crypto import encrypt_for
from .packet import MsgType, Packet
from .peers import PeerInfo, PeerRegistry

log = logging.getLogger(__name__)

ROTATION_SECS  = 600  # rebuild circuit every 10 minutes
PRE_BUILD_SECS = 60   # start building next circuit this many seconds before expiry
MIN_HOPS = 2          # guard + exit minimum


# ---------------------------------------------------------------------------
# Circuit
# ---------------------------------------------------------------------------

@dataclass
class Circuit:
    hops: list[PeerInfo]  # hops[0]=guard, hops[-1]=exit
    built_at: float = field(default=0.0)

    def __post_init__(self) -> None:
        if not self.built_at:
            self.built_at = time.time()

    @property
    def guard(self) -> PeerInfo:
        return self.hops[0]

    @property
    def exit_node(self) -> PeerInfo:
        return self.hops[-1]

    def is_expired(self) -> bool:
        return (time.time() - self.built_at) > ROTATION_SECS

    def describe(self) -> str:
        n = len(self.hops)
        parts = [f"Guard={self.hops[0].addr}"]
        for i, h in enumerate(self.hops[1:-1], 1):
            label = "Middle" if n == 3 else f"Middle{i}"
            parts.append(f"{label}={h.addr}")
        parts.append(f"Exit={self.hops[-1].addr}")
        return "  ".join(parts)


# ---------------------------------------------------------------------------
# Onion packet builders
# ---------------------------------------------------------------------------

def _hop_addr(peer: "PeerInfo") -> str:
    """
    Encode a peer's address + port as the next_hop string in a packet.

    Format:
      IPv4 →  "127.0.0.1:9051"
      IPv6 →  "[200:abcd::1]:9051"

    The relay handler parses this back with _parse_hostport() in gateway.py.
    Embedding the port lets multiple relay instances run on the same IP
    (different ports), which is essential for single-machine testing.
    """
    addr = peer.addr
    port = peer.port
    if ":" in addr:          # IPv6 — wrap in brackets
        return f"[{addr}]:{port}"
    return f"{addr}:{port}"  # IPv4


def build_onion_connect(
    host: str,
    port: int,
    circuit: Circuit,
) -> Packet:
    """
    Build the outermost onion packet for a TCP CONNECT to (host, port).
    Works for any circuit length ≥ 2.
    """
    hops = circuit.hops

    # Innermost layer: for the exit node
    target = f"{host}:{port}\n".encode()
    ciphertext = encrypt_for(target, hops[-1].public_key())
    pkt = Packet(MsgType.ONION_EXIT, "", ciphertext)

    # Wrap outward: from second-to-last hop down to guard
    for i in range(len(hops) - 2, -1, -1):
        next_hop_addr = _hop_addr(hops[i + 1])
        ciphertext = encrypt_for(pkt.to_bytes(), hops[i].public_key())
        pkt = Packet(MsgType.ONION_RELAY, next_hop_addr, ciphertext)

    return pkt


def build_onion_udp(
    dst_host: str,
    dst_port: int,
    data: bytes,
    circuit: Circuit,
) -> Packet:
    """
    Build the outermost onion packet for a UDP datagram.
    The innermost layer is ONION_UDP_EXIT instead of ONION_EXIT; otherwise
    the wrapping is identical to build_onion_connect.
    """
    hops = circuit.hops

    # Innermost: for exit node — UDP payload
    target = f"{dst_host}:{dst_port}\n".encode() + data
    ciphertext = encrypt_for(target, hops[-1].public_key())
    pkt = Packet(MsgType.ONION_UDP_EXIT, "", ciphertext)

    # Wrap outward
    for i in range(len(hops) - 2, -1, -1):
        next_hop_addr = _hop_addr(hops[i + 1])
        ciphertext = encrypt_for(pkt.to_bytes(), hops[i].public_key())
        pkt = Packet(MsgType.ONION_RELAY, next_hop_addr, ciphertext)

    return pkt


# ---------------------------------------------------------------------------
# Circuit manager (holds the live circuit, handles rotation)
# ---------------------------------------------------------------------------

class CircuitManager:
    """
    Maintains a single active N-hop circuit, rebuilding it on expiry or on
    an explicit call to rotate().

    Usage (inside the SOCKS5 connect handler):
        reader, writer = await manager.open_stream(host, port)
        # pipe browser ↔ (reader, writer)
    """

    def __init__(self, registry: PeerRegistry, hops: int = 3) -> None:
        self.registry = registry
        self.hops = max(MIN_HOPS, hops)
        self._circuit: Optional[Circuit] = None
        self._next_circuit: Optional[Circuit] = None  # pre-built, ready to swap in
        self._healthy: Optional[bool] = None
        self._lock = asyncio.Lock()

    async def get_circuit(self) -> Circuit:
        async with self._lock:
            if self._circuit is None or self._circuit.is_expired():
                if self._next_circuit is not None:
                    self._circuit = self._next_circuit
                    self._next_circuit = None
                    log.info("Swapped to pre-built circuit: %s", self._circuit.describe())
                else:
                    self._circuit = await self._build()
            return self._circuit

    async def rotate(self) -> Circuit:
        async with self._lock:
            self._circuit = await self._build()
            self._next_circuit = None
            return self._circuit

    def start_background_tasks(self, state=None) -> None:
        """Start health-check and pre-build loops. Call once after the event loop is running."""
        asyncio.ensure_future(self._health_check_loop(state))
        asyncio.ensure_future(self._pre_build_loop())

    async def _health_check_loop(self, state=None) -> None:
        """Every 30 s try a TCP connection to the guard. Update state.circuit_healthy."""
        while True:
            await asyncio.sleep(30)
            circuit = self._circuit
            if circuit is None:
                continue
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(circuit.guard.addr, circuit.guard.port),
                    timeout=3.0,
                )
                writer.close()
                self._healthy = True
            except (OSError, asyncio.TimeoutError):
                self._healthy = False
            if state is not None:
                state.circuit_healthy = self._healthy

    async def _pre_build_loop(self) -> None:
        """30 s before expiry, build the next circuit in the background."""
        while True:
            await asyncio.sleep(30)
            async with self._lock:
                if self._circuit is None or self._next_circuit is not None:
                    continue
                time_left = ROTATION_SECS - (time.time() - self._circuit.built_at)
                if time_left <= PRE_BUILD_SECS:
                    try:
                        self._next_circuit = await self._build()
                        log.info("Pre-built next circuit: %s", self._next_circuit.describe())
                    except Exception as exc:
                        log.debug("Pre-build failed: %s", exc)

    async def open_stream(
        self,
        host: str,
        port: int,
    ) -> Tuple[asyncio.StreamReader, asyncio.StreamWriter]:
        """
        Build the onion packet for (host, port), connect to the Guard, send
        the packet, and return the open (reader, writer) for data piping.
        """
        circuit = await self.get_circuit()
        onion_pkt = build_onion_connect(host, port, circuit)

        log.info("Opening %d-hop stream to %s:%d via %s",
                 len(circuit.hops), host, port, circuit.describe())
        reader, writer = await asyncio.open_connection(
            circuit.guard.addr,
            circuit.guard.port,
        )
        writer.write(onion_pkt.to_bytes())
        await writer.drain()
        return reader, writer

    async def send_udp(
        self,
        dst_host: str,
        dst_port: int,
        data: bytes,
        timeout: float = 5.0,
    ) -> Optional[bytes]:
        """
        Send a UDP datagram through the onion circuit.
        Opens a fresh TCP connection to the guard, sends an ONION_UDP_EXIT
        onion packet, waits for an ONION_UDP_RESP, returns the payload.
        Returns None on timeout or error.
        """
        circuit = await self.get_circuit()
        onion_pkt = build_onion_udp(dst_host, dst_port, data, circuit)

        try:
            reader, writer = await asyncio.open_connection(
                circuit.guard.addr,
                circuit.guard.port,
            )
            writer.write(onion_pkt.to_bytes())
            await writer.drain()

            resp_pkt = await asyncio.wait_for(
                Packet.read_from_stream(reader), timeout=timeout
            )
            writer.close()
            if resp_pkt.msg_type == MsgType.ONION_UDP_RESP:
                return resp_pkt.payload
        except (OSError, asyncio.TimeoutError, ValueError) as exc:
            log.debug("UDP circuit send failed: %s", exc)
        return None

    # ------------------------------------------------------------------

    async def _build(self) -> Circuit:
        n = self.hops
        relays = self.registry.relays()
        exits = self.registry.exits()

        n_relays_needed = n - 1   # all but last hop must be relays

        if len(relays) < n_relays_needed:
            raise RuntimeError(
                f"Not enough relay peers to build a {n}-hop circuit "
                f"(have {len(relays)}, need ≥ {n_relays_needed}). "
                "Add peers or wait for discovery."
            )
        if not exits:
            raise RuntimeError(
                "No exit peers available. "
                "Add at least one exit node to your peer list."
            )

        chosen_relays = random.sample(relays, n_relays_needed)
        exit_node = random.choice(exits)

        circuit = Circuit(hops=chosen_relays + [exit_node])
        log.info("New %d-hop circuit: %s", n, circuit.describe())
        return circuit
