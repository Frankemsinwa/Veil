"""Cryptographic utilities using AES-256-GCM for ephemeral token encryption."""
import os
from typing import Tuple
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class VaultCrypto:
    """Provides authenticated AES-256-GCM encryption for in-memory token vaults."""

    def __init__(self, key: bytes | None = None):
        # 256-bit key (32 bytes)
        self.key = key or AESGCM.generate_key(bit_length=256)
        self.aesgcm = AESGCM(self.key)

    def encrypt(self, plaintext: str) -> Tuple[bytes, bytes]:
        """Encrypt plaintext string. Returns (nonce, ciphertext)."""
        nonce = os.urandom(12)  # Standard 96-bit nonce for AES-GCM
        ciphertext = self.aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return nonce, ciphertext

    def decrypt(self, nonce: bytes, ciphertext: bytes) -> str:
        """Decrypt ciphertext with nonce back to original string."""
        plaintext_bytes = self.aesgcm.decrypt(nonce, ciphertext, None)
        return plaintext_bytes.decode("utf-8")
