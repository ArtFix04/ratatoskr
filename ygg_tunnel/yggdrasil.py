"""
Yggdrasil network utilities.

Yggdrasil assigns addresses in the 200::/7 prefix (i.e. 0x02xx:: range).
The canonical check is: the address starts with 0x02 or 0x03.
"""

from __future__ import annotations

import ipaddress
import socket
import subprocess
import sys
from typing import Optional


YGG_PREFIX = ipaddress.IPv6Network("200::/7")


def is_ygg_address(addr: str) -> bool:
    """Return True if *addr* falls within the Yggdrasil 200::/7 prefix."""
    try:
        return ipaddress.IPv6Address(addr) in YGG_PREFIX
    except ValueError:
        return False


def get_local_ygg_address() -> Optional[str]:
    """
    Return the first local interface address that belongs to 200::/7.
    Returns None if Yggdrasil does not appear to be running.
    """
    # --- platform-specific interface enumeration ---
    try:
        if sys.platform == "win32":
            return _get_ygg_windows()
        else:
            return _get_ygg_posix()
    except Exception:
        return None


# ------------------------------------------------------------------
# POSIX (Linux / macOS)
# ------------------------------------------------------------------

def _get_ygg_posix() -> Optional[str]:
    try:
        result = subprocess.run(
            ["ip", "-6", "addr", "show"],
            capture_output=True, text=True, timeout=3
        )
        output = result.stdout
    except FileNotFoundError:
        # macOS uses ifconfig
        result = subprocess.run(
            ["ifconfig"],
            capture_output=True, text=True, timeout=3
        )
        output = result.stdout

    for token in output.split():
        # Both "ip addr" and "ifconfig" print addresses as plain IPv6
        candidate = token.split("/")[0]
        if is_ygg_address(candidate):
            return candidate
    return None


# ------------------------------------------------------------------
# Windows
# ------------------------------------------------------------------

def _get_ygg_windows() -> Optional[str]:
    result = subprocess.run(
        ["netsh", "interface", "ipv6", "show", "addresses"],
        capture_output=True, text=True, timeout=3
    )
    for token in result.stdout.split():
        candidate = token.split("/")[0]
        if is_ygg_address(candidate):
            return candidate
    return None


# ------------------------------------------------------------------
# Convenience
# ------------------------------------------------------------------

def assert_yggdrasil_running() -> str:
    """
    Return the local Yggdrasil address, or raise RuntimeError if not found.
    """
    addr = get_local_ygg_address()
    if addr is None:
        raise RuntimeError(
            "No Yggdrasil address (200::/7) found on any local interface. "
            "Is yggdrasil running?"
        )
    return addr
