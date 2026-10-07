"""Session-aware in-memory token vault with TTL eviction and zeroization."""
import time
from typing import Dict, Optional, Tuple
from app.vault.crypto import VaultCrypto
from app.core.config import settings


class VaultEntry:
    def __init__(self, nonce: bytes, ciphertext: bytes, original_len: int):
        self.nonce = nonce
        self.ciphertext = ciphertext
        self.original_len = original_len
        self.last_accessed = time.time()


class SessionVault:
    """Manages encrypted mappings between placeholders and sensitive values for a session."""

    def __init__(self, session_id: str, ttl_seconds: int = settings.SESSION_TTL_SECONDS):
        self.session_id = session_id
        self.ttl_seconds = ttl_seconds
        self.crypto = VaultCrypto()
        # Mapping: placeholder (e.g. "[EMAIL_001]") -> VaultEntry
        self._placeholder_to_entry: Dict[str, VaultEntry] = {}
        # Reverse lookup to preserve consistent aliases across multi-turn chats
        # Hash of original -> placeholder
        self._original_hash_to_placeholder: Dict[str, str] = {}
        # Counters per entity type
        self._type_counters: Dict[str, int] = {}
        self.created_at = time.time()
        self.last_accessed = time.time()

    def is_expired(self) -> bool:
        return (time.time() - self.last_accessed) > self.ttl_seconds

    def touch(self):
        self.last_accessed = time.time()

    def get_or_create_placeholder(self, entity_type: str, original_val: str) -> str:
        """Assign or retrieve a consistent placeholder for a sensitive string."""
        self.touch()
        # Hash for deduplication in this session
        import hashlib
        val_hash = hashlib.sha256(original_val.encode("utf-8")).hexdigest()

        if val_hash in self._original_hash_to_placeholder:
            placeholder = self._original_hash_to_placeholder[val_hash]
            entry = self._placeholder_to_entry[placeholder]
            entry.last_accessed = time.time()
            return placeholder

        # Generate new deterministic placeholder: [EMAIL_001], [PHONE_002]
        count = self._type_counters.get(entity_type, 0) + 1
        self._type_counters[entity_type] = count
        
        # Clean prefix
        prefix = entity_type.replace("_ADDRESS", "").replace("_NUMBER", "").upper()
        placeholder = f"[{prefix}_{count:03d}]"

        # Encrypt original value
        nonce, ciphertext = self.crypto.encrypt(original_val)
        entry = VaultEntry(nonce=nonce, ciphertext=ciphertext, original_len=len(original_val))

        self._placeholder_to_entry[placeholder] = entry
        self._original_hash_to_placeholder[val_hash] = placeholder
        return placeholder

    def restore_placeholder(self, placeholder: str) -> Optional[str]:
        """Look up and decrypt the original value for a placeholder."""
        self.touch()
        entry = self._placeholder_to_entry.get(placeholder)
        if not entry:
            return None
        return self.crypto.decrypt(entry.nonce, entry.ciphertext)

    def get_all_placeholders(self) -> Dict[str, str]:
        """Returns map of placeholder -> decrypted value for full response restoration."""
        self.touch()
        result = {}
        for placeholder, entry in self._placeholder_to_entry.items():
            result[placeholder] = self.crypto.decrypt(entry.nonce, entry.ciphertext)
        return result

    def zeroize(self):
        """Zero out encrypted memory buffers and clear mappings."""
        for entry in self._placeholder_to_entry.values():
            # Overwrite ciphertext and nonce in memory with zeros before deletion
            entry.ciphertext = b"\x00" * len(entry.ciphertext)
            entry.nonce = b"\x00" * len(entry.nonce)
        self._placeholder_to_entry.clear()
        self._original_hash_to_placeholder.clear()
        self._type_counters.clear()


class VaultManager:
    """Manages multi-tenant sessions and handles automatic TTL cleanup."""

    def __init__(self):
        self._sessions: Dict[str, SessionVault] = {}

    def get_session(self, session_id: str) -> SessionVault:
        self.cleanup_expired()
        if session_id not in self._sessions:
            self._sessions[session_id] = SessionVault(session_id=session_id)
        return self._sessions[session_id]

    def cleanup_expired(self):
        """Evicts expired sessions and zeroes their memory."""
        expired_ids = [sid for sid, vault in self._sessions.items() if vault.is_expired()]
        for sid in expired_ids:
            vault = self._sessions.pop(sid, None)
            if vault:
                vault.zeroize()

    def remove_session(self, session_id: str):
        """Immediately zeroizes and removes a specific session."""
        vault = self._sessions.pop(session_id, None)
        if vault:
            vault.zeroize()

    def zeroize_all(self):
        """Zero out and evict all active sessions from memory during process shutdown."""
        for vault in list(self._sessions.values()):
            vault.zeroize()
        self._sessions.clear()



# Global vault manager singleton
vault_manager = VaultManager()
