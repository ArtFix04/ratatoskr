"""
Proof-of-relay log.

Appends one JSON line per relay event to ~/.config/ratatoskr/relay.log.
Each line records enough detail to prove that this node forwarded traffic
as part of the onion circuit — useful for the capstone demonstration and
as groundwork for a future incentive layer.

Log line format (JSONL):
  {
    "ts":        "2024-06-01T14:23:01.123456",   # UTC ISO-8601
    "role":      "relay" | "exit",               # what this node did
    "bytes":     4096,                            # bytes transferred this event
    "prev_hop":  "127.0.0.1:58064",              # inbound peer address
    "next_hop":  "127.0.0.1:19002",              # where we forwarded to
    "target":    null | "example.com:443"        # exit only: final destination
  }

Cumulative in-memory totals are exposed via .stats() for the UI dashboard.
"""

from __future__ import annotations

import json
import pathlib
import threading
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional


DEFAULT_LOG_PATH = pathlib.Path.home() / ".config" / "ratatoskr" / "relay.log"


@dataclass
class RelayLog:
    path: pathlib.Path = field(default_factory=lambda: DEFAULT_LOG_PATH)

    # in-memory accumulators (reset on process restart)
    _bytes_relayed: int = field(default=0, init=False, repr=False)
    _bytes_exited: int = field(default=0, init=False, repr=False)
    _relay_events: int = field(default=0, init=False, repr=False)
    _exit_events: int = field(default=0, init=False, repr=False)
    _lock: threading.Lock = field(default_factory=threading.Lock, init=False, repr=False)

    def __post_init__(self) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)

    # ------------------------------------------------------------------
    # Write
    # ------------------------------------------------------------------

    def record_relay(
        self,
        bytes_count: int,
        prev_hop: str,
        next_hop: str,
    ) -> None:
        """Called by a relay node when it finishes forwarding a stream."""
        entry = {
            "ts": _now(),
            "role": "relay",
            "bytes": bytes_count,
            "prev_hop": prev_hop,
            "next_hop": next_hop,
            "target": None,
        }
        self._append(entry)
        with self._lock:
            self._bytes_relayed += bytes_count
            self._relay_events += 1

    def record_exit(
        self,
        bytes_count: int,
        prev_hop: str,
        target: str,
    ) -> None:
        """Called by an exit node when it finishes a proxied connection."""
        entry = {
            "ts": _now(),
            "role": "exit",
            "bytes": bytes_count,
            "prev_hop": prev_hop,
            "next_hop": None,
            "target": target,
        }
        self._append(entry)
        with self._lock:
            self._bytes_exited += bytes_count
            self._exit_events += 1

    # ------------------------------------------------------------------
    # Read
    # ------------------------------------------------------------------

    def stats(self) -> dict:
        with self._lock:
            return {
                "bytes_relayed":  self._bytes_relayed,
                "bytes_exited":   self._bytes_exited,
                "relay_events":   self._relay_events,
                "exit_events":    self._exit_events,
                "total_bytes":    self._bytes_relayed + self._bytes_exited,
                "total_events":   self._relay_events + self._exit_events,
            }

    def recent(self, n: int = 50) -> list[dict]:
        """Return up to *n* most recent log lines as parsed dicts."""
        try:
            lines = self.path.read_text().splitlines()
        except FileNotFoundError:
            return []
        tail = lines[-n:] if len(lines) > n else lines
        entries = []
        for line in reversed(tail):
            try:
                entries.append(json.loads(line))
            except json.JSONDecodeError:
                pass
        return entries

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _append(self, entry: dict) -> None:
        try:
            with open(self.path, "a") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass   # never crash the relay on a log write failure


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="microseconds")
