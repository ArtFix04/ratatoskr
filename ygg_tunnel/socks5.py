"""
Minimal SOCKS5 server (RFC 1928 + RFC 1929).

Supported:
  - Auth: NO AUTH (0x00) only
  - Commands: CONNECT (0x01), UDP ASSOCIATE (0x03)
  - Address types: IPv4 (0x01), domain name (0x03), IPv6 (0x04)

On CONNECT the server hands (host, port) to a *connect_handler* coroutine.
On UDP ASSOCIATE an optional *udp_send_fn* is called per datagram:
  async def udp_send_fn(host, port, data) -> bytes | None
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import socket as _socket
import struct
from typing import Awaitable, Callable, Optional, Tuple

log = logging.getLogger(__name__)

# SOCKS5 constants
SOCKS_VERSION        = 0x05
AUTH_NO_AUTH         = 0x00
AUTH_NO_ACCEPTABLE   = 0xFF
CMD_CONNECT          = 0x01
CMD_UDP_ASSOCIATE    = 0x03
ATYP_IPV4            = 0x01
ATYP_DOMAIN          = 0x03
ATYP_IPV6            = 0x04
REP_SUCCESS          = 0x00
REP_GENERAL_FAILURE  = 0x01
REP_CMD_NOT_SUPPORTED = 0x07
REP_ADDR_NOT_SUPPORTED = 0x08

ConnectHandler = Callable[
    [asyncio.StreamReader, asyncio.StreamWriter, str, int],
    Awaitable[None],
]
UdpSendFn = Callable[[str, int, bytes], Awaitable[Optional[bytes]]]


# ---------------------------------------------------------------------------
# Handshake + request parsing
# ---------------------------------------------------------------------------

async def _read_socks5_handshake(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> bool:
    data = await reader.readexactly(2)
    version, nmethods = data
    if version != SOCKS_VERSION:
        writer.close()
        return False
    methods = await reader.readexactly(nmethods)
    if AUTH_NO_AUTH not in methods:
        writer.write(bytes([SOCKS_VERSION, AUTH_NO_ACCEPTABLE]))
        await writer.drain()
        writer.close()
        return False
    writer.write(bytes([SOCKS_VERSION, AUTH_NO_AUTH]))
    await writer.drain()
    return True


async def _read_socks5_request(
    reader: asyncio.StreamReader,
) -> Tuple[int, str, int]:
    header = await reader.readexactly(4)
    version, cmd, _rsv, atyp = header

    if atyp == ATYP_IPV4:
        raw = await reader.readexactly(4)
        host = ".".join(str(b) for b in raw)
    elif atyp == ATYP_DOMAIN:
        length = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(length)).decode("ascii")
    elif atyp == ATYP_IPV6:
        raw = await reader.readexactly(16)
        host = str(ipaddress.IPv6Address(raw))
    else:
        return cmd, "", 0

    (port,) = struct.unpack("!H", await reader.readexactly(2))
    return cmd, host, port


def _make_reply(rep: int) -> bytes:
    """Minimal SOCKS5 reply with 0.0.0.0:0 bound address."""
    return struct.pack("!BBBBIH", SOCKS_VERSION, rep, 0x00, ATYP_IPV4, 0, 0)


def _make_udp_bind_reply(port: int) -> bytes:
    """SOCKS5 UDP ASSOCIATE reply advertising our relay socket on 127.0.0.1."""
    return struct.pack("!BBBBIH",
                       SOCKS_VERSION, REP_SUCCESS, 0x00, ATYP_IPV4,
                       0x7f000001,   # 127.0.0.1
                       port)


# ---------------------------------------------------------------------------
# UDP ASSOCIATE helpers
# ---------------------------------------------------------------------------

def _parse_udp_header(data: bytes) -> Tuple[Optional[str], int, bytes]:
    """
    Parse a SOCKS5 UDP datagram header.
    Returns (host, port, payload) or (None, 0, b"") on error / fragment.
    """
    if len(data) < 4:
        return None, 0, b""
    # RSV(2) | FRAG(1) | ATYP(1)
    frag = data[2]
    atyp = data[3]
    if frag != 0:
        return None, 0, b""   # fragmented datagrams not supported

    offset = 4
    if atyp == ATYP_IPV4:
        if len(data) < offset + 6:
            return None, 0, b""
        host = ".".join(str(b) for b in data[offset:offset + 4])
        offset += 4
    elif atyp == ATYP_DOMAIN:
        if len(data) < offset + 1:
            return None, 0, b""
        dlen = data[offset]; offset += 1
        if len(data) < offset + dlen + 2:
            return None, 0, b""
        host = data[offset:offset + dlen].decode("ascii", errors="replace")
        offset += dlen
    elif atyp == ATYP_IPV6:
        if len(data) < offset + 18:
            return None, 0, b""
        host = str(ipaddress.IPv6Address(data[offset:offset + 16]))
        offset += 16
    else:
        return None, 0, b""

    port = struct.unpack_from("!H", data, offset)[0]
    offset += 2
    return host, port, data[offset:]


def _make_udp_header(host: str, port: int) -> bytes:
    """Build a SOCKS5 UDP reply header (RSV=0, FRAG=0)."""
    try:
        ipaddress.IPv6Address(host)
        raw = ipaddress.IPv6Address(host).packed
        return struct.pack("!HBB", 0, 0, ATYP_IPV6) + raw + struct.pack("!H", port)
    except ValueError:
        pass
    try:
        raw = ipaddress.IPv4Address(host).packed
        return struct.pack("!HBBBBBBH", 0, 0, ATYP_IPV4,
                           raw[0], raw[1], raw[2], raw[3], port)
    except ValueError:
        pass
    # domain
    enc = host.encode("ascii")
    return (struct.pack("!HBB", 0, 0, ATYP_DOMAIN)
            + bytes([len(enc)]) + enc
            + struct.pack("!H", port))


async def _handle_udp_associate(
    client_reader: asyncio.StreamReader,
    client_writer: asyncio.StreamWriter,
    udp_send_fn: UdpSendFn,
) -> None:
    """
    Open a UDP relay socket, tell the client, then relay datagrams until the
    TCP control connection drops.
    """
    loop = asyncio.get_event_loop()

    sock = _socket.socket(_socket.AF_INET, _socket.SOCK_DGRAM)
    sock.setsockopt(_socket.SOL_SOCKET, _socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 0))
    sock.setblocking(False)
    bound_port = sock.getsockname()[1]
    log.debug("UDP relay socket bound to 127.0.0.1:%d", bound_port)

    client_writer.write(_make_udp_bind_reply(bound_port))
    await client_writer.drain()

    client_udp_addr: list = [None]

    async def relay_loop() -> None:
        while True:
            try:
                data, addr = await asyncio.wait_for(
                    loop.sock_recvfrom(sock, 65535), timeout=0.5
                )
            except asyncio.TimeoutError:
                continue
            except OSError:
                break

            client_udp_addr[0] = addr
            host, port, payload = _parse_udp_header(data)
            if host is None:
                continue

            log.debug("UDP relay %s:%d → %s:%d (%d B)", addr[0], addr[1], host, port, len(payload))
            try:
                reply = await asyncio.wait_for(
                    udp_send_fn(host, port, payload), timeout=5.0
                )
            except asyncio.TimeoutError:
                log.debug("UDP send_fn timeout for %s:%d", host, port)
                continue

            if reply is not None and client_udp_addr[0] is not None:
                hdr = _make_udp_header(host, port)
                try:
                    await loop.sock_sendto(sock, hdr + reply, client_udp_addr[0])
                except OSError:
                    pass

    async def tcp_watchdog() -> None:
        """Return when the TCP control connection closes."""
        try:
            while True:
                data = await client_reader.read(256)
                if not data:
                    break
        except OSError:
            pass

    relay_task   = asyncio.ensure_future(relay_loop())
    watchdog_task = asyncio.ensure_future(tcp_watchdog())

    done, pending = await asyncio.wait(
        [relay_task, watchdog_task],
        return_when=asyncio.FIRST_COMPLETED,
    )
    for t in pending:
        t.cancel()
        try:
            await t
        except asyncio.CancelledError:
            pass

    try:
        sock.close()
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

async def handle_socks5_client(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    connect_handler: ConnectHandler,
    udp_send_fn: Optional[UdpSendFn] = None,
) -> None:
    peer = writer.get_extra_info("peername")
    log.debug("New SOCKS5 connection from %s", peer)
    try:
        if not await _read_socks5_handshake(reader, writer):
            return

        cmd, host, port = await _read_socks5_request(reader)

        if cmd == CMD_CONNECT:
            if not host:
                writer.write(_make_reply(REP_ADDR_NOT_SUPPORTED))
                await writer.drain()
                return
            log.info("SOCKS5 CONNECT %s:%d from %s", host, port, peer)
            writer.write(_make_reply(REP_SUCCESS))
            await writer.drain()
            await connect_handler(reader, writer, host, port)

        elif cmd == CMD_UDP_ASSOCIATE:
            if udp_send_fn is not None:
                log.info("SOCKS5 UDP ASSOCIATE from %s", peer)
                await _handle_udp_associate(reader, writer, udp_send_fn)
            else:
                writer.write(_make_reply(REP_CMD_NOT_SUPPORTED))
                await writer.drain()

        else:
            writer.write(_make_reply(REP_CMD_NOT_SUPPORTED))
            await writer.drain()

    except asyncio.IncompleteReadError:
        log.debug("Client disconnected mid-handshake: %s", peer)
    except Exception as exc:
        log.warning("SOCKS5 error from %s: %s", peer, exc)
    finally:
        if not writer.is_closing():
            writer.close()


class Socks5Server:
    """Async SOCKS5 server bound to *host*:*port*."""

    def __init__(
        self,
        connect_handler: ConnectHandler,
        host: str = "127.0.0.1",
        port: int = 9050,
        udp_send_fn: Optional[UdpSendFn] = None,
    ):
        self.connect_handler = connect_handler
        self.host = host
        self.port = port
        self.udp_send_fn = udp_send_fn
        self._server: asyncio.AbstractServer | None = None

    async def start(self) -> None:
        self._server = await asyncio.start_server(
            self._client_cb,
            self.host,
            self.port,
        )
        addrs = [s.getsockname() for s in self._server.sockets]
        log.info("SOCKS5 server listening on %s", addrs)

    async def _client_cb(
        self,
        reader: asyncio.StreamReader,
        writer: asyncio.StreamWriter,
    ) -> None:
        await handle_socks5_client(reader, writer, self.connect_handler, self.udp_send_fn)

    async def serve_forever(self) -> None:
        if self._server is None:
            await self.start()
        async with self._server:
            await self._server.serve_forever()
