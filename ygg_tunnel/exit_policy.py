"""
Exit-node port policy.

Mirrors Tor's exit policy concept: exit nodes declare which destination ports
they are willing to forward to.  Only relevant when --exit is active.

Examples
--------
  --exit-policy "*"          allow all ports (default when --exit is set)
  --exit-policy "80,443"     web-only (recommended for cautious operators)
  --exit-policy "80,443,8080,8443,19000"  web + alt HTTP + test port

The policy is serialised into the PeerInfo.modes list as "exit:80,443" so
peer-discovery clients know in advance which exit nodes accept their traffic.
"""

from __future__ import annotations

from dataclasses import dataclass

# Sensible default for a demo/capstone: common web ports only
DEFAULT_POLICY = "80,443,8080,8443"

# What we advertise when the operator explicitly chooses "allow all"
ALLOW_ALL = "*"


@dataclass(frozen=True)
class ExitPolicy:
    """Immutable set of allowed destination ports."""

    ports: frozenset[int]    # empty set means deny all; see allow_all flag
    allow_all: bool = False  # True when policy string is "*"

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def from_string(cls, s: str) -> "ExitPolicy":
        """
        Parse a policy string.

        "*"         → allow all ports
        ""          → deny all ports
        "80,443"    → allow only those ports
        """
        s = s.strip()
        if s == ALLOW_ALL:
            return cls(ports=frozenset(), allow_all=True)
        if not s:
            return cls(ports=frozenset(), allow_all=False)
        ports = frozenset(int(p.strip()) for p in s.split(",") if p.strip().isdigit())
        return cls(ports=ports, allow_all=False)

    @classmethod
    def default(cls) -> "ExitPolicy":
        return cls.from_string(DEFAULT_POLICY)

    @classmethod
    def allow_all_ports(cls) -> "ExitPolicy":
        return cls(ports=frozenset(), allow_all=True)

    # ------------------------------------------------------------------
    # Evaluation
    # ------------------------------------------------------------------

    def allows(self, port: int) -> bool:
        if self.allow_all:
            return True
        return port in self.ports

    # ------------------------------------------------------------------
    # Serialisation (stored in PeerInfo.modes as "exit:80,443")
    # ------------------------------------------------------------------

    def to_mode_string(self) -> str:
        """Return the mode tag that goes into PeerInfo.modes."""
        if self.allow_all:
            return "exit:*"
        return f"exit:{','.join(str(p) for p in sorted(self.ports))}"

    def describe(self) -> str:
        if self.allow_all:
            return "all ports"
        if not self.ports:
            return "no ports (deny all)"
        return ", ".join(str(p) for p in sorted(self.ports))

    def __str__(self) -> str:
        return ALLOW_ALL if self.allow_all else ",".join(str(p) for p in sorted(self.ports))
