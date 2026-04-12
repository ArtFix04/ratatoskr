"""
Node identity key management.

Each node has two keypairs that are auto-generated on first run and persisted
to ~/.config/ratatoskr/:

  identity.sign   — Ed25519 SigningKey   (used to sign peer announcements)
  identity.enc    — X25519 PrivateKey    (used for onion encryption via NaCl Box)

Both are stored as raw 32-byte seeds in separate files, chmod 600.
"""

from __future__ import annotations

import base64
import logging
import os
import pathlib
import stat
from dataclasses import dataclass

from nacl.public import PrivateKey, PublicKey
from nacl.signing import SigningKey, VerifyKey

log = logging.getLogger(__name__)

DEFAULT_CONFIG_DIR = pathlib.Path.home() / ".config" / "ratatoskr"
SIGN_FILE = "identity.sign"
ENC_FILE = "identity.enc"


@dataclass(frozen=True)
class NodeIdentity:
    """Holds the two keypairs that define a node's identity."""

    signing_key: SigningKey    # Ed25519 — sign peer announcements
    private_key: PrivateKey    # X25519  — onion encryption

    # ------------------------------------------------------------------
    # Derived public keys
    # ------------------------------------------------------------------

    @property
    def verify_key(self) -> VerifyKey:
        return self.signing_key.verify_key

    @property
    def public_key(self) -> PublicKey:
        return self.private_key.public_key

    # ------------------------------------------------------------------
    # Serialisable representations (base64 of raw bytes)
    # ------------------------------------------------------------------

    @property
    def verify_key_b64(self) -> str:
        return base64.b64encode(bytes(self.verify_key)).decode()

    @property
    def public_key_b64(self) -> str:
        return base64.b64encode(bytes(self.public_key)).decode()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------

    def save(self, config_dir: pathlib.Path = DEFAULT_CONFIG_DIR) -> None:
        config_dir.mkdir(parents=True, exist_ok=True)
        _write_secret(config_dir / SIGN_FILE, bytes(self.signing_key))
        _write_secret(config_dir / ENC_FILE, bytes(self.private_key))
        log.debug("Identity saved to %s", config_dir)

    @classmethod
    def load(cls, config_dir: pathlib.Path = DEFAULT_CONFIG_DIR) -> "NodeIdentity":
        sign_raw = _read_secret(config_dir / SIGN_FILE)
        enc_raw = _read_secret(config_dir / ENC_FILE)
        return cls(
            signing_key=SigningKey(sign_raw),
            private_key=PrivateKey(enc_raw),
        )

    @classmethod
    def generate(cls) -> "NodeIdentity":
        return cls(
            signing_key=SigningKey.generate(),
            private_key=PrivateKey.generate(),
        )


# ------------------------------------------------------------------
# Public helper — call this at startup
# ------------------------------------------------------------------

def load_or_create(config_dir: pathlib.Path = DEFAULT_CONFIG_DIR) -> NodeIdentity:
    """
    Load the node identity from *config_dir*, or generate and persist a new
    one if the files do not exist yet.
    """
    sign_path = config_dir / SIGN_FILE
    enc_path = config_dir / ENC_FILE

    if sign_path.exists() and enc_path.exists():
        identity = NodeIdentity.load(config_dir)
        log.info(
            "Loaded identity — sign: %s... enc: %s...",
            identity.verify_key_b64[:12],
            identity.public_key_b64[:12],
        )
    else:
        log.info("No identity found at %s — generating new keypair.", config_dir)
        identity = NodeIdentity.generate()
        identity.save(config_dir)
        log.info(
            "New identity saved — sign: %s... enc: %s...",
            identity.verify_key_b64[:12],
            identity.public_key_b64[:12],
        )
    return identity


# ------------------------------------------------------------------
# Internal file helpers
# ------------------------------------------------------------------

def _write_secret(path: pathlib.Path, data: bytes) -> None:
    path.write_bytes(data)
    path.chmod(stat.S_IRUSR | stat.S_IWUSR)   # 0o600


def _read_secret(path: pathlib.Path) -> bytes:
    return path.read_bytes()


# ------------------------------------------------------------------
# Public-key-only helpers (for peer announcements)
# ------------------------------------------------------------------

def pubkey_from_b64(b64: str) -> PublicKey:
    return PublicKey(base64.b64decode(b64))


def verify_key_from_b64(b64: str) -> VerifyKey:
    return VerifyKey(base64.b64decode(b64))
