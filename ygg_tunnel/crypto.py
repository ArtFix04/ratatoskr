"""
Onion-layer encryption helpers.

Uses NaCl **SealedBox** (libsodium's `crypto_box_seal`):
  - Sender generates a one-time ephemeral X25519 keypair per message.
  - Ephemeral public key is prepended to the ciphertext automatically.
  - Recipient only needs their static PrivateKey to decrypt.
  - Provides per-message forward secrecy (ephemeral key is never stored).

Wire format produced by SealedBox.encrypt():
  ephemeral_pubkey (32 bytes) || box_ciphertext (MACBYTES=16 overhead)

No extra framing needed — SealedBox handles it internally.
"""

from __future__ import annotations

from nacl.public import PrivateKey, PublicKey, SealedBox
from nacl.exceptions import CryptoError


class DecryptionError(Exception):
    """Raised when a layer cannot be decrypted (wrong key or corrupt data)."""


def encrypt_for(message: bytes, recipient_pubkey: PublicKey) -> bytes:
    """
    Encrypt *message* for *recipient_pubkey* using a fresh ephemeral keypair.
    Returns the sealed ciphertext (safe to embed in a Packet payload).
    """
    box = SealedBox(recipient_pubkey)
    return bytes(box.encrypt(message))


def decrypt_layer(ciphertext: bytes, our_private_key: PrivateKey) -> bytes:
    """
    Decrypt one onion layer using *our_private_key*.
    Raises DecryptionError if the ciphertext is invalid or was not meant for us.
    """
    box = SealedBox(our_private_key)
    try:
        return bytes(box.decrypt(ciphertext))
    except CryptoError as exc:
        raise DecryptionError(f"Failed to decrypt onion layer: {exc}") from exc
