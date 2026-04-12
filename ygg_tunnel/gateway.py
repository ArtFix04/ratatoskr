"""
Node logic — handles all three roles:

  client  — local SOCKS5 proxy that builds onion circuits, or falls back
             to a direct TCP bridge when no peers are available (--no-require-ygg)
  relay   — accepts ONION_RELAY packets, decrypts one layer, forwards
  exit    — accepts ONION_EXIT / ONION_UDP_EXIT packets, reaches the internet

A single process can serve as relay AND exit simultaneously (if --exit is set)
but acts as relay-only by default, mirroring Tor's default behaviour.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Optional

from .circuit import CircuitManager
from .crypto import DecryptionError, decrypt_layer
from .exit_policy import ExitPolicy
from .keys import NodeIdentity
from .packet import MsgType, Packet
from .peers import PeerInfo, PeerRegistry, start_peers_http_server
from .relay_log import RelayLog
from .socks5 import Socks5Server
from .yggdrasil import get_local_ygg_address

if TYPE_CHECKING:
    from .ui.state import AppState

log = logging.getLogger(__name__)

YGG_TUNNEL_PORT = 9051


# ---------------------------------------------------------------------------
# Shared pipe helper
# ---------------------------------------------------------------------------

async def _pipe(
    src_reader: asyncio.StreamReader,
    dst_writer: asyncio.StreamWriter,
    state: Optional["AppState"] = None,
    direction: str = "out",
) -> int:
    """Forward bytes from src to dst. Returns total bytes forwarded."""
    total = 0
    try:
        while True:
            chunk = await src_reader.read(65536)
            if not chunk:
                break
            dst_writer.write(chunk)
            await dst_writer.drain()
            total += len(chunk)
            if state is not None:
                state.add_bytes(direction, len(chunk))
    except (asyncio.IncompleteReadError, ConnectionResetError):
        pass
    finally:
        if not dst_writer.is_closing():
            dst_writer.close()
    return total


# ---------------------------------------------------------------------------
# SOCKS5 connect handlers
# ---------------------------------------------------------------------------

async def direct_connect_handler(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    host: str,
    port: int,
    state: Optional["AppState"] = None,
) -> None:
    """Fallback: plain TCP bridge used when no peers/Yggdrasil are available."""
    try:
        remote_reader, remote_writer = await asyncio.open_connection(host, port)
    except OSError as exc:
        log.warning("Direct connect to %s:%d failed — %s", host, port, exc)
        return
    log.debug("Direct bridge %s:%d", host, port)
    if state:
        state.connection_opened()
    try:
        await asyncio.gather(
            _pipe(client_reader, remote_writer, state, "out"),
            _pipe(remote_reader, client_writer, state, "in"),
            return_exceptions=True,
        )
    finally:
        if state:
            state.connection_closed()


def make_circuit_connect_handler(
    manager: CircuitManager,
    state: Optional["AppState"] = None,
):
    """
    Return a SOCKS5 connect handler that routes traffic through the onion
    circuit managed by *manager*.

    On the first failure the circuit is rotated and the connection is retried
    once automatically (handles a guard node going offline mid-session).
    """
    async def _handler(
        client_reader: asyncio.StreamReader,
        client_writer: asyncio.StreamWriter,
        host: str,
        port: int,
    ) -> None:
        guard_reader = guard_writer = None
        for attempt in range(2):
            try:
                guard_reader, guard_writer = await manager.open_stream(host, port)
                break
            except (OSError, RuntimeError) as exc:
                if attempt == 0:
                    log.warning("Circuit failed (%s) — rotating and retrying", exc)
                    try:
                        await manager.rotate()
                    except Exception:
                        pass
                else:
                    log.warning("Circuit open failed for %s:%d — %s", host, port, exc)

        if guard_reader is None:
            return

        if state:
            state.connection_opened()
            if manager._circuit:
                state.circuit_info = manager._circuit.describe()
        try:
            await asyncio.gather(
                _pipe(client_reader, guard_writer, state, "out"),
                _pipe(guard_reader, client_writer, state, "in"),
                return_exceptions=True,
            )
        finally:
            if state:
                state.connection_closed()

    return _handler


# ---------------------------------------------------------------------------
# Relay / Exit — Yggdrasil peer handler
# ---------------------------------------------------------------------------

class PeerHandler:
    """
    Handles inbound connections from other Yggdrasil nodes.
    Instantiated once per GatewayNode; the identity and exit_mode are shared.
    """

    def __init__(
        self,
        identity: NodeIdentity,
        exit_mode: bool,
        exit_policy: Optional[ExitPolicy] = None,
        relay_log: Optional[RelayLog] = None,
    ) -> None:
        self.identity = identity
        self.exit_mode = exit_mode
        self.exit_policy = exit_policy
        self.relay_log = relay_log

    async def __call__(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        peer = writer.get_extra_info("peername")
        log.debug("Peer connection from %s", peer)
        try:
            pkt = await Packet.read_from_stream(reader)
            await self._dispatch(pkt, reader, writer)
        except Exception as exc:
            log.warning("Peer handler error (%s): %s", peer, exc)
        finally:
            if not writer.is_closing():
                writer.close()

    async def _dispatch(
        self,
        pkt: Packet,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        if pkt.msg_type == MsgType.ONION_RELAY:
            await self._handle_onion_relay(pkt, reader, writer)
        elif pkt.msg_type == MsgType.ONION_EXIT:
            if self.exit_mode:
                await self._handle_onion_exit(pkt, reader, writer)
            else:
                log.warning("Received ONION_EXIT but not in exit mode — dropping")
        elif pkt.msg_type == MsgType.ONION_UDP_EXIT:
            if self.exit_mode:
                await self._handle_onion_udp_exit(pkt, writer)
            else:
                log.warning("Received ONION_UDP_EXIT but not in exit mode — dropping")
        else:
            log.warning("Unhandled msg_type %s", pkt.msg_type)

    # ------------------------------------------------------------------
    # ONION_RELAY: decrypt one layer, forward inner packet to next_hop
    # ------------------------------------------------------------------

    async def _handle_onion_relay(
        self,
        pkt: Packet,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            inner_bytes = decrypt_layer(pkt.payload, self.identity.private_key)
        except DecryptionError as exc:
            log.warning("ONION_RELAY: decryption failed — %s", exc)
            return

        try:
            inner_pkt = Packet.from_bytes(inner_bytes)
        except ValueError as exc:
            log.warning("ONION_RELAY: inner packet malformed — %s", exc)
            return

        next_hop = pkt.next_hop
        if not next_hop:
            log.warning("ONION_RELAY: empty next_hop")
            return

        # next_hop is "addr:port" (IPv4) or "[ipv6]:port" — parse both.
        # Falls back to YGG_TUNNEL_PORT if the string is a bare address.
        fwd_host, fwd_port = _parse_hostport(next_hop)
        if fwd_host is None:
            # bare address with no port — use default
            fwd_host, fwd_port = next_hop, YGG_TUNNEL_PORT

        log.info("ONION_RELAY → %s:%d (inner type: %s)", fwd_host, fwd_port, inner_pkt.msg_type.name)
        try:
            fwd_reader, fwd_writer = await asyncio.open_connection(fwd_host, fwd_port)
        except OSError as exc:
            log.warning("ONION_RELAY: cannot reach %s:%d — %s", fwd_host, fwd_port, exc)
            return

        fwd_writer.write(inner_pkt.to_bytes())
        await fwd_writer.drain()

        prev_hop = str(writer.get_extra_info("peername") or "unknown")

        # Pipe remaining stream data + relay response back
        results = await asyncio.gather(
            _pipe(reader, fwd_writer),
            _pipe(fwd_reader, writer),
            return_exceptions=True,
        )
        if self.relay_log is not None:
            bytes_fwd = sum(r for r in results if isinstance(r, int))
            self.relay_log.record_relay(bytes_fwd, prev_hop, f"{fwd_host}:{fwd_port}")

    # ------------------------------------------------------------------
    # ONION_EXIT: decrypt, connect to target, pipe
    # ------------------------------------------------------------------

    async def _handle_onion_exit(
        self,
        pkt: Packet,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        try:
            plaintext = decrypt_layer(pkt.payload, self.identity.private_key)
        except DecryptionError as exc:
            log.warning("ONION_EXIT: decryption failed — %s", exc)
            return

        nl = plaintext.find(b"\n")
        if nl == -1:
            log.warning("ONION_EXIT: missing host:port header")
            return

        target = plaintext[:nl].decode("ascii")
        buffered = plaintext[nl + 1:]

        host, port = _parse_hostport(target)
        if host is None:
            log.warning("ONION_EXIT: cannot parse host:port from %r", target)
            return

        # Exit policy enforcement
        if self.exit_policy is not None and not self.exit_policy.allows(port):
            log.warning("ONION_EXIT: port %d denied by exit policy (%s)", port, self.exit_policy.describe())
            return

        log.info("ONION_EXIT: connecting to %s:%d", host, port)
        try:
            rem_reader, rem_writer = await asyncio.open_connection(host, port)
        except OSError as exc:
            log.warning("ONION_EXIT: cannot reach %s:%d — %s", host, port, exc)
            return

        if buffered:
            rem_writer.write(buffered)
            await rem_writer.drain()

        prev_hop = str(writer.get_extra_info("peername") or "unknown")

        results = await asyncio.gather(
            _pipe(reader, rem_writer),
            _pipe(rem_reader, writer),
            return_exceptions=True,
        )
        if self.relay_log is not None:
            bytes_fwd = sum(r for r in results if isinstance(r, int))
            self.relay_log.record_exit(bytes_fwd, prev_hop, target)

    # ------------------------------------------------------------------
    # ONION_UDP_EXIT: decrypt, send UDP datagram, return reply
    # ------------------------------------------------------------------

    async def _handle_onion_udp_exit(
        self,
        pkt: Packet,
        writer: asyncio.StreamWriter,
    ) -> None:
        import socket as _socket

        try:
            plaintext = decrypt_layer(pkt.payload, self.identity.private_key)
        except DecryptionError as exc:
            log.warning("ONION_UDP_EXIT: decryption failed — %s", exc)
            return

        nl = plaintext.find(b"\n")
        if nl == -1:
            log.warning("ONION_UDP_EXIT: missing host:port header")
            return

        target = plaintext[:nl].decode("ascii")
        data = plaintext[nl + 1:]

        host, port = _parse_hostport(target)
        if host is None:
            log.warning("ONION_UDP_EXIT: cannot parse host:port from %r", target)
            return

        if self.exit_policy is not None and not self.exit_policy.allows(port):
            log.warning("ONION_UDP_EXIT: port %d denied by exit policy", port)
            return

        log.info("ONION_UDP_EXIT: sending %d bytes to %s:%d", len(data), host, port)

        family = _socket.AF_INET6 if ":" in host else _socket.AF_INET
        sock = _socket.socket(family, _socket.SOCK_DGRAM)
        sock.setblocking(False)
        loop = asyncio.get_event_loop()
        try:
            await loop.sock_sendto(sock, data, (host, port))
            reply = await asyncio.wait_for(
                loop.sock_recv(sock, 65535), timeout=5.0
            )
            resp_pkt = Packet(MsgType.ONION_UDP_RESP, "", reply)
            writer.write(resp_pkt.to_bytes())
            await writer.drain()
        except (OSError, asyncio.TimeoutError) as exc:
            log.debug("ONION_UDP_EXIT: send/recv failed: %s", exc)
        finally:
            sock.close()



# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _parse_hostport(target: str):
    """Parse "host:port" or "[ipv6]:port". Returns (host, port) or (None, 0)."""
    try:
        if target.startswith("["):
            host, _, port_str = target[1:].rpartition("]:")
        else:
            host, _, port_str = target.rpartition(":")
        return host or None, int(port_str)
    except (ValueError, AttributeError):
        return None, 0


# ---------------------------------------------------------------------------
# GatewayNode — top-level orchestrator
# ---------------------------------------------------------------------------

class GatewayNode:
    """
    Starts all listeners for one node.

    Modes
    -----
    client  — SOCKS5 on localhost; builds onion circuits to relay peers.
              Pass circuit_manager=None to fall back to Phase-1 direct mode.
    relay   — Yggdrasil peer listener; peels ONION_RELAY, forwards.
    exit    — Same listener, additionally handles ONION_EXIT (opt-in).

    A node is typically relay + optionally exit; client mode is independent.
    """

    def __init__(
        self,
        identity: NodeIdentity,
        registry: PeerRegistry,
        *,
        socks_host: str = "127.0.0.1",
        socks_port: int = 9050,
        ygg_port: int = YGG_TUNNEL_PORT,
        exit_mode: bool = False,
        client_mode: bool = True,
        relay_mode: bool = True,
        require_ygg: bool = True,
        bootstrap_peers: Optional[list[str]] = None,
        state: Optional["AppState"] = None,
        ygg_addr_override: Optional[str] = None,
        peers_http_port: Optional[int] = 9052,
        exit_policy: Optional[ExitPolicy] = None,
        relay_log: Optional[RelayLog] = None,
        circuit_hops: int = 3,
    ) -> None:
        self.identity = identity
        self.registry = registry
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.ygg_port = ygg_port
        self.exit_mode = exit_mode
        self.client_mode = client_mode
        self.relay_mode = relay_mode
        self.require_ygg = require_ygg
        self.bootstrap_peers = bootstrap_peers or []
        self.state = state
        self.ygg_addr_override = ygg_addr_override
        self.peers_http_port = peers_http_port
        self.exit_policy = exit_policy
        self.relay_log = relay_log
        self.circuit_hops = circuit_hops

        self.ygg_addr: Optional[str] = None
        self._socks_srv: Optional[Socks5Server] = None
        self._servers: list = []

    async def start(self) -> None:
        self.ygg_addr = self.ygg_addr_override or get_local_ygg_address()
        if self.ygg_addr:
            log.info("Yggdrasil address : %s", self.ygg_addr)
        else:
            if self.require_ygg:
                raise RuntimeError(
                    "No Yggdrasil address (200::/7) found. "
                    "Is yggdrasil running? Or use --no-require-ygg."
                )
            log.warning("Yggdrasil not detected — some features disabled.")

        # -- peer crawl --
        if self.bootstrap_peers and self.ygg_addr:
            log.info("Crawling bootstrap peers: %s", self.bootstrap_peers)
            await self.registry.crawl(self.bootstrap_peers)

        # -- SOCKS5 (client mode) --
        if self.client_mode:
            if self.ygg_addr and len(self.registry) >= 2:
                circuit_manager = CircuitManager(self.registry, hops=self.circuit_hops)
                connect_handler = make_circuit_connect_handler(circuit_manager, self.state)
                udp_send_fn = circuit_manager.send_udp
                log.info("Circuit mode: %d-hop onion routing via %d known peers",
                         self.circuit_hops, len(self.registry))
            else:
                async def connect_handler(r, w, h, p):
                    await direct_connect_handler(r, w, h, p, self.state)
                udp_send_fn = None
                log.info("Circuit mode: direct (no peers / no Yggdrasil)")

            self._socks_srv = Socks5Server(
                connect_handler=connect_handler,
                host=self.socks_host,
                port=self.socks_port,
                udp_send_fn=udp_send_fn,
            )
            await self._socks_srv.start()
            self._servers.append(self._socks_srv._server)

        # -- Relay / Exit peer listener --
        if (self.relay_mode or self.exit_mode) and self.ygg_addr:
            handler = PeerHandler(
                self.identity,
                self.exit_mode,
                exit_policy=self.exit_policy,
                relay_log=self.relay_log,
            )
            peer_server = await asyncio.start_server(
                handler, self.ygg_addr, self.ygg_port
            )
            modes = "exit+relay" if self.exit_mode else "relay"
            log.info("Peer listener [%s]:%d (%s)", self.ygg_addr, self.ygg_port, modes)
            self._servers.append(peer_server)

            # self_info for /peers endpoint
            modes_list = ["relay"]
            if self.exit_mode:
                modes_list.append("exit")
            self_info = PeerInfo(
                addr=self.ygg_addr,
                pubkey_enc=self.identity.public_key_b64,
                pubkey_sign=self.identity.verify_key_b64,
                modes=modes_list,
                port=self.ygg_port,
            )
            if self.peers_http_port is not None:
                peers_http = await start_peers_http_server(
                    self.ygg_addr, self.registry, self_info, self.peers_http_port
                )
                self._servers.append(peers_http)

            # Announce self to every bootstrap node so they add us to their
            # live registry and return us on future GET /peers requests.
            if self.bootstrap_peers:
                for addr in self.bootstrap_peers:
                    asyncio.ensure_future(
                        self.registry.announce_to(addr, self_info)
                    )

        # -- Populate AppState --
        if self.state is not None:
            self.state.ygg_addr = self.ygg_addr
            self.state.socks_host = self.socks_host
            self.state.socks_port = self.socks_port
            self.state.socks_running = self.client_mode
            self.state.relay_running = self.relay_mode or self.exit_mode
            modes: list[str] = []
            if self.client_mode:
                modes.append("client")
            if self.relay_mode:
                modes.append("relay")
            if self.exit_mode:
                modes.append("exit")
            self.state.modes = modes

    # ------------------------------------------------------------------
    # Pause / resume SOCKS5 (used by the UI Connect/Disconnect button)
    # ------------------------------------------------------------------

    async def pause_socks5(self) -> None:
        if self._socks_srv and self._socks_srv._server:
            self._socks_srv._server.close()
            await self._socks_srv._server.wait_closed()
            log.info("SOCKS5 proxy paused")
        if self.state:
            self.state.socks_running = False

    async def resume_socks5(self) -> None:
        if self._socks_srv:
            await self._socks_srv.start()
            log.info("SOCKS5 proxy resumed on %s:%d", self.socks_host, self.socks_port)
        if self.state:
            self.state.socks_running = True

    # ------------------------------------------------------------------

    async def serve_forever(self, extra_coros: Optional[list] = None) -> None:
        await self.start()
        coros = [srv.serve_forever() for srv in self._servers]
        if extra_coros:
            coros.extend(extra_coros)
        if not coros:
            log.warning("No servers started — check mode flags and Yggdrasil status.")
            return
        await asyncio.gather(*coros)
