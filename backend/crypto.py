"""Symmetric encryption for sensitive tokens stored at rest.

Uses Fernet (AES-128-CBC + HMAC-SHA256) from the `cryptography` package.
Refresh tokens are NEVER stored in plaintext — they are always encrypted
before DB insertion and decrypted only at use time.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from .config import get_settings


def _get_fernet() -> Fernet:
    settings = get_settings()
    key = settings.FERNET_KEY.encode()
    return Fernet(key)


def encrypt_token(plaintext: str) -> str:
    """Encrypt a plaintext token string. Returns a URL-safe base64 string."""
    f = _get_fernet()
    return f.encrypt(plaintext.encode()).decode()


def decrypt_token(ciphertext: str) -> str:
    """Decrypt a ciphertext token string. Raises ValueError on tamper."""
    f = _get_fernet()
    try:
        return f.decrypt(ciphertext.encode()).decode()
    except InvalidToken as exc:
        raise ValueError("Token decryption failed — possible tampering") from exc


def generate_fernet_key() -> str:
    """Generate a new Fernet key. Use once during initial setup."""
    return Fernet.generate_key().decode()
