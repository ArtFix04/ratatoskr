"""
Level-2 integration test: full 3-hop onion circuit on a single machine.

Topology (all on 127.0.0.1, different ports — no Yggdrasil required):

  [Browser/test client]
        │  SOCKS5  127.0.0.1:19050
        ▼
  ┌─────────────┐
  │ Client node │  builds circuit, sends onion packet
  └──────┬──────┘
         │ TCP  127.0.0.1:19001
         ▼
  ┌─────────────┐
  │ Guard relay │  peels outer onion layer, forwards to Middle
  └──────┬──────┘
         │ TCP  127.0.0.1:19002
         ▼
  ┌──────────────┐
  │ Middle relay │  peels middle layer, forwards to Exit
  └──────┬───────┘
         │ TCP  127.0.0.1:19003
         ▼
  ┌───────────┐
  │ Exit node │  peels innermost layer, connects to mock HTTP server
  └──────┬────┘
         │ TCP  127.0.0.1:19000
         ▼
  ┌──────────────────┐
  │ Mock HTTP server │  replies "HTTP/1.0 200 OK ... TUNNEL_OK"
  └──────────────────┘

What this validates end-to-end:
  ✓ SOCKS5 handshake + CONNECT
  ✓ Onion packet construction (3-layer NaCl SealedBox)
  ✓ Guard decrypts outer layer, routes to correct port
  ✓ Middle decrypts middle layer, routes to correct port
  ✓ Exit decrypts innermost layer, connects to real TCP target
  ✓ Response flows back through the open connection chain
  ✓ Client receives plaintext response
"""

from __future__ import annotations

import asyncio
import struct
import sys
import pathlib

# Make the project importable when run as a script
sys.path.insert(0, str(pathlib.Path(__file__).parent.parent))

from ygg_tunnel.gateway import GatewayNode
from ygg_tunnel.keys import NodeIdentity
from ygg_tunnel.peers import PeerInfo, PeerRegistry

# ── Port assignments ──────────────────────────────────────────────────────────
HTTP_PORT   = 19000   # mock internet target
GUARD_PORT  = 19001   # guard relay peer listener
MIDDLE_PORT = 19002   # middle relay peer listener
EXIT_PORT   = 19003   # exit node peer listener
SOCKS_PORT  = 19050   # client SOCKS5 proxy


# ── Mock HTTP server (simulates the public internet) ─────────────────────────

async def _mock_http_handler(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
) -> None:
    """Accept any HTTP request and reply with a fixed 200 body."""
    try:
        await asyncio.wait_for(reader.read(4096), timeout=3.0)
        body = b"TUNNEL_OK"
        writer.write(
            b"HTTP/1.0 200 OK\r\n"
            b"Content-Length: 9\r\n"
            b"Connection: close\r\n"
            b"\r\n" + body
        )
        await writer.drain()
    finally:
        writer.close()


# ── SOCKS5 client helper ──────────────────────────────────────────────────────

async def socks5_connect(
    proxy_host: str,
    proxy_port: int,
    target_host: str,
    target_port: int,
) -> tuple[asyncio.StreamReader, asyncio.StreamWriter]:
    """
    Perform a SOCKS5 CONNECT handshake and return the open stream.
    """
    reader, writer = await asyncio.open_connection(proxy_host, proxy_port)

    # Greeting: version=5, 1 method, no-auth
    writer.write(b"\x05\x01\x00")
    await writer.drain()
    resp = await reader.readexactly(2)
    assert resp == b"\x05\x00", f"SOCKS5 auth negotiation failed: {resp!r}"

    # CONNECT request (ATYP=1 IPv4)
    import socket
    writer.write(
        b"\x05\x01\x00\x01"
        + socket.inet_aton(target_host)
        + struct.pack("!H", target_port)
    )
    await writer.drain()
    reply = await reader.read(10)
    assert reply[1] == 0x00, f"SOCKS5 CONNECT failed, rep={reply[1]:#04x}"

    return reader, writer


# ── Build the three relay/exit nodes ─────────────────────────────────────────

def _make_node(
    identity: NodeIdentity,
    ygg_port: int,
    *,
    relay: bool = True,
    exit_mode: bool = False,
    registry: PeerRegistry | None = None,
    socks_port: int | None = None,
) -> GatewayNode:
    return GatewayNode(
        identity=identity,
        registry=registry or PeerRegistry(),
        socks_host="127.0.0.1",
        socks_port=socks_port or 19999,   # ignored when client_mode=False
        ygg_port=ygg_port,
        exit_mode=exit_mode,
        client_mode=socks_port is not None,
        relay_mode=relay,
        require_ygg=False,
        ygg_addr_override="127.0.0.1",
        peers_http_port=None,             # disabled — all nodes share 127.0.0.1
    )


# ── Main test coroutine ───────────────────────────────────────────────────────

async def run_test(verbose: bool = False) -> None:
    # ── 1. Generate identities ────────────────────────────────────────────────
    guard_id  = NodeIdentity.generate()
    middle_id = NodeIdentity.generate()
    exit_id   = NodeIdentity.generate()
    client_id = NodeIdentity.generate()

    # ── 2. Describe peers for the client registry ─────────────────────────────
    #   guard  / middle → relay only  (won't be chosen as exit)
    #   exit           → exit only   (won't be chosen as middle relay)
    guard_peer  = PeerInfo("127.0.0.1", guard_id.public_key_b64,  guard_id.verify_key_b64,  ["relay"], port=GUARD_PORT)
    middle_peer = PeerInfo("127.0.0.1", middle_id.public_key_b64, middle_id.verify_key_b64, ["relay"], port=MIDDLE_PORT)
    exit_peer   = PeerInfo("127.0.0.1", exit_id.public_key_b64,   exit_id.verify_key_b64,   ["exit"],  port=EXIT_PORT)

    # ── 3. Build nodes ────────────────────────────────────────────────────────
    guard_node  = _make_node(guard_id,  GUARD_PORT)
    middle_node = _make_node(middle_id, MIDDLE_PORT)
    exit_node   = _make_node(exit_id,   EXIT_PORT,  exit_mode=True)

    client_registry = PeerRegistry()
    for p in [guard_peer, middle_peer, exit_peer]:
        client_registry.add(p)

    client_node = _make_node(
        client_id, ygg_port=19999,   # client doesn't listen for peers
        registry=client_registry,
        socks_port=SOCKS_PORT,
    )

    # ── 4. Start mock HTTP server ─────────────────────────────────────────────
    http_server = await asyncio.start_server(
        _mock_http_handler, "127.0.0.1", HTTP_PORT
    )

    # ── 5. Start all nodes ────────────────────────────────────────────────────
    for node in [guard_node, middle_node, exit_node, client_node]:
        await node.start()

    servers = [http_server]
    for node in [guard_node, middle_node, exit_node, client_node]:
        servers.extend(node._servers)

    bg_tasks = [asyncio.create_task(srv.serve_forever()) for srv in servers]

    # small pause to let everything bind
    await asyncio.sleep(0.15)

    # ── 6. Send a request through the tunnel ─────────────────────────────────
    print("  Connecting via SOCKS5 …", end=" ", flush=True)
    reader, writer = await socks5_connect(
        "127.0.0.1", SOCKS_PORT,
        "127.0.0.1", HTTP_PORT,
    )
    print("connected")

    print("  Sending HTTP GET through circuit …", end=" ", flush=True)
    writer.write(b"GET / HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n")
    await writer.drain()

    response = b""
    try:
        while True:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=5.0)
            if not chunk:
                break
            response += chunk
    except asyncio.TimeoutError:
        pass

    writer.close()
    print("done")

    # ── 7. Verify ─────────────────────────────────────────────────────────────
    assert b"200" in response,      f"Expected HTTP 200, got: {response[:200]!r}"
    assert b"TUNNEL_OK" in response, f"Expected body TUNNEL_OK, got: {response[:200]!r}"
    print(f"  Response: {response.decode(errors='replace').strip()!r}")

    # ── 8. Cleanup ────────────────────────────────────────────────────────────
    for t in bg_tasks:
        t.cancel()
    await asyncio.gather(*bg_tasks, return_exceptions=True)


# ── Entry points ──────────────────────────────────────────────────────────────

def test_full_onion_circuit():
    """pytest entry point."""
    asyncio.run(run_test(verbose=False))


if __name__ == "__main__":
    import logging
    verbose = "-v" in sys.argv
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.WARNING,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%H:%M:%S",
    )

    print("Ygg-Tunnel Level-2 Integration Test")
    print("=" * 40)
    print(f"  Mock HTTP server : 127.0.0.1:{HTTP_PORT}")
    print(f"  Guard relay      : 127.0.0.1:{GUARD_PORT}")
    print(f"  Middle relay     : 127.0.0.1:{MIDDLE_PORT}")
    print(f"  Exit node        : 127.0.0.1:{EXIT_PORT}")
    print(f"  Client SOCKS5    : 127.0.0.1:{SOCKS_PORT}")
    print()

    try:
        asyncio.run(run_test(verbose=verbose))
        print()
        print("PASSED — full 3-hop onion circuit working.")
        sys.exit(0)
    except Exception as exc:
        print()
        print(f"FAILED — {exc}")
        if verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
