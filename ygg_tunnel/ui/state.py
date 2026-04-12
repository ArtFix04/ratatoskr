"""
Shared application state between the GatewayNode and the web UI.

AppState is a plain dataclass that:
  - GatewayNode writes to (ygg_addr, circuit_info, byte counters, etc.)
  - FastAPI routes read from (status JSON, template context)
  - UILogHandler appends log lines to (for the log viewer page)

It also holds a set of active WebSocket send-queues so that live-stats
updates can be broadcast to all connected browser tabs at once.
"""

from __future__ import annotations

import asyncio
import collections
import logging
import time
from dataclasses import dataclass, field
from typing import Optional


# ---------------------------------------------------------------------------
# AppState
# ---------------------------------------------------------------------------

@dataclass
class AppState:
    # Node identity / network
    ygg_addr: Optional[str] = None
    socks_host: str = "127.0.0.1"
    socks_port: int = 9050
    modes: list[str] = field(default_factory=list)   # ["client","relay","exit"]

    # Connection status
    socks_running: bool = False
    relay_running: bool = False
    circuit_info: Optional[str] = None   # "Guard=200::1 Mid=200::2 Exit=200::3"

    # Demo mode flag — shown as a banner in the UI
    demo_mode: bool = False

    # Stats — updated by the instrumented pipe in gateway.py
    bytes_in: int = 0
    bytes_out: int = 0
    active_connections: int = 0
    start_time: float = field(default_factory=time.time)

    # Throughput history — last 60 samples (1/sec), bytes/sec each
    throughput_in_history: list = field(default_factory=lambda: [0] * 60)
    throughput_out_history: list = field(default_factory=lambda: [0] * 60)
    _prev_bytes_in: int = field(default=0, init=False, repr=False)
    _prev_bytes_out: int = field(default=0, init=False, repr=False)

    # Relay log stats (refreshed each broadcast cycle from RelayLog.stats())
    relay_stats: dict = field(default_factory=dict)

    # Log ring-buffer (max 500 lines)
    log_lines: collections.deque = field(
        default_factory=lambda: collections.deque(maxlen=500)
    )

    # Active WebSocket queues — one asyncio.Queue per connected browser tab
    _ws_queues: list[asyncio.Queue] = field(default_factory=list)

    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "ygg_addr": self.ygg_addr,
            "socks_host": self.socks_host,
            "socks_port": self.socks_port,
            "modes": self.modes,
            "socks_running": self.socks_running,
            "relay_running": self.relay_running,
            "circuit_info": self.circuit_info,
            "demo_mode": self.demo_mode,
            "bytes_in": self.bytes_in,
            "bytes_out": self.bytes_out,
            "active_connections": self.active_connections,
            "uptime_secs": int(time.time() - self.start_time),
            "throughput_in_history": list(self.throughput_in_history),
            "throughput_out_history": list(self.throughput_out_history),
            "relay_stats": self.relay_stats,
        }

    def sample_throughput(self) -> None:
        """Record one bytes/sec sample; call once per second from broadcast loop."""
        bps_in  = self.bytes_in  - self._prev_bytes_in
        bps_out = self.bytes_out - self._prev_bytes_out
        self._prev_bytes_in  = self.bytes_in
        self._prev_bytes_out = self.bytes_out
        self.throughput_in_history.append(max(0, bps_in))
        if len(self.throughput_in_history) > 60:
            self.throughput_in_history.pop(0)
        self.throughput_out_history.append(max(0, bps_out))
        if len(self.throughput_out_history) > 60:
            self.throughput_out_history.pop(0)

    def add_bytes(self, direction: str, n: int) -> None:
        if direction == "in":
            self.bytes_in += n
        else:
            self.bytes_out += n

    def connection_opened(self) -> None:
        self.active_connections += 1

    def connection_closed(self) -> None:
        self.active_connections = max(0, self.active_connections - 1)

    # ------------------------------------------------------------------
    # WebSocket broadcast
    # ------------------------------------------------------------------

    def subscribe(self) -> asyncio.Queue:
        q: asyncio.Queue = asyncio.Queue(maxsize=10)
        self._ws_queues.append(q)
        return q

    def unsubscribe(self, q: asyncio.Queue) -> None:
        try:
            self._ws_queues.remove(q)
        except ValueError:
            pass

    async def broadcast(self) -> None:
        """Push current state to all subscribed WebSocket clients."""
        import json
        data = json.dumps(self.to_dict())
        dead = []
        for q in self._ws_queues:
            try:
                q.put_nowait(data)
            except asyncio.QueueFull:
                dead.append(q)
        for q in dead:
            self.unsubscribe(q)


# ---------------------------------------------------------------------------
# Logging handler that feeds log_lines
# ---------------------------------------------------------------------------

class UILogHandler(logging.Handler):
    """Captures log records into AppState.log_lines for the UI log viewer."""

    LEVEL_CLASS = {
        "DEBUG": "debug",
        "INFO": "info",
        "WARNING": "warning",
        "ERROR": "error",
        "CRITICAL": "error",
    }

    def __init__(self, state: AppState) -> None:
        super().__init__()
        self.state = state

    def emit(self, record: logging.LogRecord) -> None:
        try:
            line = {
                "ts": time.strftime("%H:%M:%S", time.localtime(record.created)),
                "level": record.levelname,
                "cls": self.LEVEL_CLASS.get(record.levelname, "info"),
                "name": record.name.replace("ygg_tunnel.", ""),
                "msg": self.format(record),
            }
            self.state.log_lines.append(line)
        except Exception:
            self.handleError(record)


def attach_ui_log_handler(state: AppState) -> None:
    """Attach a UILogHandler to the root logger."""
    handler = UILogHandler(state)
    handler.setFormatter(logging.Formatter("%(message)s"))
    logging.getLogger().addHandler(handler)
