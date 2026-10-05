"""AES-256-GCM credential envelope encryption.

Purpose
-------
Encrypts sensitive credentials (LDAP bind passwords, OAuth client secrets)
before they are stored in the database.  Ciphertext is stored; plaintext
never touches disk or the database.

Algorithm
---------
AES-256-GCM with a random 96-bit (12-byte) IV per encryption.
The output wire format is:  ``<12-byte IV> || <ciphertext> || <16-byte tag>``
encoded as a lowercase hex string for safe storage in TEXT columns.

Master Key
----------
The 32-byte master key is derived from the ``SECRET_KEY`` environment variable
using HKDF-SHA256.  ``SECRET_KEY`` may be any length ≥ 16 bytes; we derive a
fixed-length key from it so callers never have to manage key lengths.

Usage
-----
    from app.core.crypto import encrypt_secret, decrypt_secret

    ciphertext = encrypt_secret("my-ldap-password")
    plaintext  = decrypt_secret(ciphertext)
    assert plaintext == "my-ldap-password"

Security Properties
-------------------
* Confidentiality: AES-256-GCM provides IND-CCA2 security.
* Integrity:       GCM authentication tag prevents ciphertext tampering.
* Uniqueness:      Random IV guarantees ciphertexts differ even for equal inputs.
* Key protection:  Master key is never persisted; derived fresh from SECRET_KEY
                   at startup.

Raises
------
``ValueError`` — if SECRET_KEY is missing/too short, or if decryption fails
                 (tampered ciphertext, wrong key, truncated data).
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

# Constants
_IV_BYTES = 12   # GCM recommended nonce size
_KEY_BYTES = 32  # AES-256
_HKDF_INFO = b"DataMaskingTool-credential-encryption-v1"
_HKDF_SALT = b"DataMaskingTool-salt-v1"


def _derive_key(secret_key_raw: str) -> bytes:
    """Derive a 32-byte AES key from the raw ``SECRET_KEY`` env value."""
    hkdf = HKDF(
        algorithm=SHA256(),
        length=_KEY_BYTES,
        salt=_HKDF_SALT,
        info=_HKDF_INFO,
    )
    return hkdf.derive(secret_key_raw.encode())


def _get_master_key() -> bytes:
    """Return the derived AES-256 master key.

    Reads ``SECRET_KEY`` from the environment each time it is called so that
    tests can override the env var before calling encrypt/decrypt.
    """
    raw = os.environ.get("SECRET_KEY", "").strip()
    if len(raw) < 32:
        raise ValueError(
            "SECRET_KEY must be at least 32 characters long to ensure adequate entropy. "
            "Set a strong random value in .env."
        )
    return _derive_key(raw)


def encrypt_secret(plaintext: str) -> str:
    """Encrypt *plaintext* with AES-256-GCM.

    Returns
    -------
    str
        Hex-encoded wire format: ``<12-byte IV><ciphertext+tag>``
    """
    key = _get_master_key()
    iv = os.urandom(_IV_BYTES)
    aesgcm = AESGCM(key)
    ciphertext_with_tag = aesgcm.encrypt(iv, plaintext.encode(), None)
    return (iv + ciphertext_with_tag).hex()


def decrypt_secret(ciphertext_hex: str) -> str:
    """Decrypt a hex-encoded AES-256-GCM ciphertext back to plaintext.

    Parameters
    ----------
    ciphertext_hex:
        Hex string produced by ``encrypt_secret()``.

    Returns
    -------
    str
        The original plaintext.

    Raises
    ------
    ValueError
        If the ciphertext is malformed, truncated, tampered, or the key
        is wrong.
    """
    try:
        raw = bytes.fromhex(ciphertext_hex)
    except ValueError as exc:
        raise ValueError(f"Invalid hex ciphertext: {exc}") from exc

    if len(raw) < _IV_BYTES + 16:  # IV + minimum GCM tag
        raise ValueError("Ciphertext is too short to be valid.")

    iv = raw[:_IV_BYTES]
    ciphertext_with_tag = raw[_IV_BYTES:]

    key = _get_master_key()
    aesgcm = AESGCM(key)
    try:
        plaintext_bytes = aesgcm.decrypt(iv, ciphertext_with_tag, None)
    except Exception as exc:  # cryptography raises InvalidTag
        raise ValueError(
            "Decryption failed — ciphertext may be tampered or the key is wrong."
        ) from exc

    return plaintext_bytes.decode()
