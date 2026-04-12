"""
Peer registry and discovery.

Each node exposes a lightweight HTTP endpoint on its Yggdrasil address:

  GET  http://[<ygg-addr>]:9052/peers
  → { "peers": [ { "addr": "200:...", "pubkey_enc": "base64",
                   "pubkey_sign": "base64", "modes": ["relay"],
                   "port": 9051 }, ... ] }

  POST http://[<ygg-addr>]:9052/peers/announce
  Body: { "addr": "200:...", "pubkey_enc": "...", "pubkey_sign": "...",
          "modes": ["relay"], "port": 9051 }
  → { "ok": true }

  New nodes call POST /peers/announce on each bootstrap node after startup.
  Bootstrap nodes maintain a live registry and return it on GET /peers.

Liveness
--------
  A background loop probes each registered peer every PROBE_INTERVAL seconds.
  After PRUNE_AFTER_FAILURES consecutive failures the peer is dropped.
  This keeps the registry fresh — dead nodes are removed automatically.

PeerRegistry is the in-process peer list.  It can:
  - Load / save to a JSON file (peers.json in the config dir).
  - Fetch a remote node's peer list and merge it in.
  - Crawl transitively from a bootstrap address.
  - Probe all known peers and remove unreachable ones.
"""

from __future__ import annotations

import asyncio
import json
import logging
import pathlib
import time
from dataclasses import asdict, dataclass, field
from typing import Optional

from nacl.public import PublicKey

from .keys import NodeIdentity, pubkey_from_b64

log = logging.getLogger(__name__)

PEERS_HTTP_PORT   = 9052
_CRAWL_DEPTH      = 2      # hops to follow when crawling
PROBE_INTERVAL    = 60     # seconds between liveness sweeps
PRUNE_AFTER_FAILURES = 3   # consecutive failures before removal


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class PeerInfo:
    addr: str              # Yggdrasil IPv6 address (e.g. "200:1234::1")
    pubkey_enc: str        # base64 X25519 public key (for onion encryption)
    pubkey_sign: str       # base64 Ed25519 verify key (for identity)
    modes: list[str]       # subset of ["relay", "exit"]
    port: int = 9051       # tunnel port
    last_seen: float = field(default_factory=time.time)

    def public_key(self) -> PublicKey:
        return pubkey_from_b64(self.pubkey_enc)

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("last_seen", None)   # don't expose ephemeral timing to peers
        return d

    @classmethod
    def from_dict(cls, d: dict) -> "PeerInfo":
        return cls(
            addr=d["addr"],
            pubkey_enc=d["pubkey_enc"],
            pubkey_sign=d["pubkey_sign"],
            modes=d.get("modes", ["relay"]),
            port=d.get("port", 9051),
        )


# ---------------------------------------------------------------------------
# Registry
# ---------------------------------------------------------------------------

class PeerRegistry:
    """Thread-safe (asyncio-safe) in-memory peer list with liveness tracking."""

    def __init__(self) -> None:
        # Keyed by "addr:port" so multiple nodes on the same IP (e.g. during
        # single-machine testing) are treated as distinct peers.
        self._peers: dict[str, PeerInfo] = {}
        # Consecutive probe failures per peer key
        self._fail_counts: dict[str, int] = {}

    @staticmethod
    def _key(peer: "PeerInfo") -> str:
        return f"{peer.addr}:{peer.port}"

    # -- mutation --

    def add(self, peer: PeerInfo) -> None:
        key = self._key(peer)
        peer.last_seen = time.time()
        self._peers[key] = peer
        self._fail_counts.setdefault(key, 0)   # don't reset an existing failure streak

    def remove(self, addr: str) -> None:
        # Support both "addr" and "addr:port" for the remove call
        keys_to_drop = [k for k in self._peers if k == addr or k.startswith(f"{addr}:")]
        for k in keys_to_drop:
            del self._peers[k]
            self._fail_counts.pop(k, None)

    def update_from_list(self, peers: list[PeerInfo]) -> int:
        """Merge *peers* in; return count of new entries."""
        before = len(self._peers)
        for p in peers:
            key = self._key(p)
            if key not in self._peers:
                self._peers[key] = p
                self._fail_counts.setdefault(key, 0)
            else:
                self._peers[key].last_seen = time.time()
                self._fail_counts[key] = 0   # reset failures on fresh gossip
        return len(self._peers) - before

    # -- liveness tracking --

    def mark_seen(self, key: str) -> None:
        """Record a successful probe; resets failure counter."""
        if key in self._peers:
            self._peers[key].last_seen = time.time()
        self._fail_counts[key] = 0

    def mark_failed(self, key: str) -> int:
        """Record a failed probe; returns new failure count."""
        count = self._fail_counts.get(key, 0) + 1
        self._fail_counts[key] = count
        return count

    async def probe_all(
        self,
        timeout: float = 5.0,
        max_failures: int = PRUNE_AFTER_FAILURES,
    ) -> tuple[int, int]:
        """
        Probe every registered peer via GET /peers.
        Returns (alive_count, removed_count).
        """
        alive = 0
        removed = 0
        for key, peer in list(self._peers.items()):
            raw = await _http_get(peer.addr, PEERS_HTTP_PORT, "/peers", timeout)
            if raw is not None:
                self.mark_seen(key)
                alive += 1
                log.debug("Liveness OK: %s", key)
            else:
                count = self.mark_failed(key)
                log.debug("Liveness FAIL (%d/%d): %s", count, max_failures, key)
                if count >= max_failures:
                    self.remove(peer.addr)
                    removed += 1
                    log.info("Pruned unreachable peer: %s", key)
        return alive, removed

    # -- queries --

    def all(self) -> list[PeerInfo]:
        return list(self._peers.values())

    def relays(self) -> list[PeerInfo]:
        return [p for p in self._peers.values() if "relay" in p.modes]

    def exits(self) -> list[PeerInfo]:
        return [p for p in self._peers.values() if "exit" in p.modes]

    def get(self, addr: str) -> Optional[PeerInfo]:
        return self._peers.get(addr)

    def __len__(self) -> int:
        return len(self._peers)

    # -- persistence --

    def save(self, path: pathlib.Path) -> None:
        data = [p.to_dict() for p in self._peers.values()]
        path.write_text(json.dumps(data, indent=2))
        log.debug("Saved %d peers to %s", len(data), path)

    def load(self, path: pathlib.Path) -> None:
        if not path.exists():
            return
        data = json.loads(path.read_text())
        for d in data:
            try:
                self.add(PeerInfo.from_dict(d))
            except (KeyError, ValueError) as exc:
                log.warning("Skipping malformed peer entry: %s", exc)
        log.info("Loaded %d peers from %s", len(self._peers), path)

    # -- network --

    async def fetch_from(
        self,
        addr: str,
        port: int = PEERS_HTTP_PORT,
        timeout: float = 5.0,
    ) -> list[PeerInfo]:
        """
        Fetch the /peers list from a remote node.
        Returns the parsed list (does NOT auto-add them).
        """
        raw = await _http_get(addr, port, "/peers", timeout)
        if raw is None:
            return []
        try:
            data = json.loads(raw)
            return [PeerInfo.from_dict(d) for d in data.get("peers", [])]
        except (json.JSONDecodeError, KeyError) as exc:
            log.warning("Bad /peers response from %s: %s", addr, exc)
            return []

    async def announce_to(
        self,
        bootstrap_addr: str,
        self_info: PeerInfo,
        port: int = PEERS_HTTP_PORT,
        timeout: float = 5.0,
    ) -> bool:
        """
        POST our PeerInfo to a bootstrap node's /peers/announce endpoint.
        Returns True on success.
        """
        body = json.dumps(self_info.to_dict()).encode()
        raw = await _http_post(bootstrap_addr, port, "/peers/announce", body, timeout)
        if raw is None:
            log.warning("Announce to %s failed (unreachable)", bootstrap_addr)
            return False
        try:
            resp = json.loads(raw)
            if resp.get("ok"):
                log.info("Announced self to %s", bootstrap_addr)
                return True
        except json.JSONDecodeError:
            pass
        log.warning("Announce to %s: unexpected response: %s", bootstrap_addr, raw[:80])
        return False

    async def crawl(
        self,
        bootstrap_addrs: list[str],
        depth: int = _CRAWL_DEPTH,
    ) -> None:
        """
        Fetch peers from *bootstrap_addrs*, add new ones, then repeat for
        their peers up to *depth* hops.
        """
        frontier = set(bootstrap_addrs)
        visited: set[str] = set()

        for _ in range(depth):
            next_frontier: set[str] = set()
            for addr in frontier:
                if addr in visited:
                    continue
                visited.add(addr)
                peers = await self.fetch_from(addr)
                new = self.update_from_list(peers)
                log.info("Crawled %s — %d new peers", addr, new)
                for p in peers:
                    if p.addr not in visited:
                        next_frontier.add(p.addr)
            frontier = next_frontier
            if not frontier:
                break


# ---------------------------------------------------------------------------
# Minimal HTTP client helpers
# ---------------------------------------------------------------------------

async def _http_get(
    addr: str,
    port: int,
    path: str,
    timeout: float,
) -> Optional[str]:
    """
    Make a bare-minimum HTTP/1.1 GET request and return the response body.
    Returns None on error.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(addr, port),
            timeout=timeout,
        )
        request = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: [{addr}]:{port}\r\n"
            "Connection: close\r\n"
            "\r\n"
        )
        writer.write(request.encode())
        await writer.drain()

        response = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            response += chunk
        writer.close()

        if b"\r\n\r\n" in response:
            _, body = response.split(b"\r\n\r\n", 1)
        else:
            body = response
        return body.decode("utf-8", errors="replace")

    except (OSError, asyncio.TimeoutError) as exc:
        log.debug("fetch %s from %s: %s", path, addr, exc)
        return None


async def _http_post(
    addr: str,
    port: int,
    path: str,
    body: bytes,
    timeout: float,
) -> Optional[str]:
    """
    Make a bare-minimum HTTP/1.1 POST request and return the response body.
    Returns None on error.
    """
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(addr, port),
            timeout=timeout,
        )
        request = (
            f"POST {path} HTTP/1.1\r\n"
            f"Host: [{addr}]:{port}\r\n"
            "Content-Type: application/json\r\n"
            f"Content-Length: {len(body)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + body
        writer.write(request)
        await writer.drain()

        response = b""
        while True:
            chunk = await asyncio.wait_for(reader.read(65536), timeout=timeout)
            if not chunk:
                break
            response += chunk
        writer.close()

        if b"\r\n\r\n" in response:
            _, resp_body = response.split(b"\r\n\r\n", 1)
        else:
            resp_body = response
        return resp_body.decode("utf-8", errors="replace")

    except (OSError, asyncio.TimeoutError) as exc:
        log.debug("POST %s to %s: %s", path, addr, exc)
        return None


# ---------------------------------------------------------------------------
# HTTP server: GET /peers  +  POST /peers/announce
# ---------------------------------------------------------------------------

async def _handle_peers_request(
    reader: asyncio.StreamReader,
    writer: asyncio.StreamWriter,
    registry: PeerRegistry,
    self_info: Optional[PeerInfo],
) -> None:
    """
    Handle one incoming HTTP connection.

    GET  /peers           → JSON list of all known peers
    POST /peers/announce  → register a new peer; body is a PeerInfo JSON object
    """
    try:
        raw = await asyncio.wait_for(reader.read(8192), timeout=5.0)
        # Split headers and body
        if b"\r\n\r\n" in raw:
            header_block, body_bytes = raw.split(b"\r\n\r\n", 1)
        else:
            header_block, body_bytes = raw, b""

        first_line = header_block.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
        method, path, *_ = (first_line + "   ").split()

        # ── GET /peers ────────────────────────────────────────────────
        if method == "GET" and path == "/peers":
            peers = registry.all()
            if self_info and self_info.addr not in {p.addr for p in peers}:
                peers = [self_info] + peers
            body = json.dumps({"peers": [p.to_dict() for p in peers]})
            status = "200 OK"
            ctype = "application/json"

        # ── POST /peers/announce ──────────────────────────────────────
        elif method == "POST" and path == "/peers/announce":
            try:
                peer_dict = json.loads(body_bytes.decode("utf-8", errors="replace"))
                peer = PeerInfo.from_dict(peer_dict)
                registry.add(peer)
                log.info("Peer announced: %s (modes=%s)", peer.addr, peer.modes)
                body = json.dumps({"ok": True, "addr": peer.addr})
                status = "200 OK"
            except (json.JSONDecodeError, KeyError, ValueError) as exc:
                log.warning("Bad /peers/announce body: %s", exc)
                body = json.dumps({"error": str(exc)})
                status = "400 Bad Request"
            ctype = "application/json"

        # ── anything else ─────────────────────────────────────────────
        else:
            body = json.dumps({"error": "not found"})
            status = "404 Not Found"
            ctype = "application/json"

        body_bytes_out = body.encode()
        response = (
            f"HTTP/1.1 {status}\r\n"
            f"Content-Type: {ctype}\r\n"
            f"Content-Length: {len(body_bytes_out)}\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode() + body_bytes_out

        writer.write(response)
        await writer.drain()
    except Exception as exc:
        log.debug("Peers HTTP handler error: %s", exc)
    finally:
        writer.close()


async def _prune_loop(
    registry: PeerRegistry,
    interval: float = PROBE_INTERVAL,
    max_failures: int = PRUNE_AFTER_FAILURES,
) -> None:
    """Background coroutine: probe all peers every *interval* seconds."""
    while True:
        await asyncio.sleep(interval)
        alive, removed = await registry.probe_all(max_failures=max_failures)
        if removed:
            log.info("Liveness sweep: %d alive, %d removed", alive, removed)
        else:
            log.debug("Liveness sweep: %d alive", alive)


async def start_peers_http_server(
    ygg_addr: str,
    registry: PeerRegistry,
    self_info: Optional[PeerInfo] = None,
    port: int = PEERS_HTTP_PORT,
    enable_prune: bool = True,
) -> asyncio.AbstractServer:
    """
    Start the GET /peers + POST /peers/announce HTTP server on *ygg_addr*:*port*.
    Also starts the background liveness prune loop if *enable_prune* is True.
    Returns the raw asyncio server (caller is responsible for cleanup).
    """
    def handler(r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        asyncio.ensure_future(
            _handle_peers_request(r, w, registry, self_info)
        )

    server = await asyncio.start_server(handler, ygg_addr, port)
    log.info("Peers HTTP server on [%s]:%d", ygg_addr, port)

    if enable_prune:
        asyncio.ensure_future(_prune_loop(registry))
        log.debug("Liveness prune loop started (interval=%ds, max_failures=%d)",
                  PROBE_INTERVAL, PRUNE_AFTER_FAILURES)

    return server
