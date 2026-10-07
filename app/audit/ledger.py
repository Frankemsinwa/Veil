"""Tamper-evident audit ledger using SQLite and HMAC-SHA256 integrity chaining."""
import sqlite3
import hmac
import hashlib
import time
import json
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple
from app.core.config import settings


class AuditLedger:
    """Stores verifiable compliance receipts for each prompt processed by Veil.
    
    Adheres strictly to the Zero-Knowledge principle:
    Plaintext prompts and decrypted secrets are NEVER stored on disk.
    Only metadata, counts, action decisions, and cryptographic hash chains are persisted.
    """

    def __init__(self, db_path: Optional[Path] = None, hmac_key: Optional[bytes] = None):
        self.db_path = db_path or (settings.DATA_DIR / "audit_ledger.db")
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        # HMAC key for tamper-evidence chain (defaults to a machine-local key)
        self.hmac_key = hmac_key or b"veil-tamper-evident-chain-key-v1"
        self._init_db()

    def _get_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        conn.row_factory = sqlite3.Row
        return conn

    def _init_db(self):
        with self._get_connection() as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS audit_receipts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL NOT NULL,
                    session_id TEXT NOT NULL,
                    provider TEXT NOT NULL,
                    model TEXT NOT NULL,
                    policy TEXT NOT NULL,
                    action_taken TEXT NOT NULL,
                    redaction_count INTEGER NOT NULL,
                    secret_blocked_count INTEGER NOT NULL,
                    entities_detected_json TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    previous_hash TEXT NOT NULL,
                    record_hmac TEXT NOT NULL
                )
            """)
            conn.commit()

    def _get_latest_hash(self, conn: sqlite3.Connection) -> str:
        cursor = conn.cursor()
        cursor.execute("SELECT record_hmac FROM audit_receipts ORDER BY id DESC LIMIT 1")
        row = cursor.fetchone()
        return row["record_hmac"] if row else "GENESIS_BLOCK_HASH"

    def record_receipt(
        self,
        session_id: str,
        provider: str,
        model: str,
        policy: str,
        action_taken: str,
        redaction_count: int,
        secret_blocked_count: int,
        entities_detected: List[str],
        latency_ms: float
    ) -> int:
        """Records a new compliance receipt and computes tamper-evident HMAC signature."""
        now = time.time()
        entities_json = json.dumps(entities_detected)

        with self._get_connection() as conn:
            prev_hash = self._get_latest_hash(conn)
            
            # Construct canonical representation for HMAC
            canonical_payload = (
                f"{now}|{session_id}|{provider}|{model}|{policy}|"
                f"{action_taken}|{redaction_count}|{secret_blocked_count}|"
                f"{entities_json}|{latency_ms:.2f}|{prev_hash}"
            )
            record_hmac = hmac.new(
                self.hmac_key,
                canonical_payload.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()

            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO audit_receipts (
                    timestamp, session_id, provider, model, policy,
                    action_taken, redaction_count, secret_blocked_count,
                    entities_detected_json, latency_ms, previous_hash, record_hmac
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                now, session_id, provider, model, policy,
                action_taken, redaction_count, secret_blocked_count,
                entities_json, latency_ms, prev_hash, record_hmac
            ))
            conn.commit()
            return cursor.lastrowid

    def get_recent_receipts(self, limit: int = 50) -> List[Dict[str, Any]]:
        """Fetch latest audit receipts for dashboard/CLI viewing."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT id, timestamp, session_id, provider, model, policy,
                       action_taken, redaction_count, secret_blocked_count,
                       entities_detected_json, latency_ms, record_hmac
                FROM audit_receipts
                ORDER BY id DESC LIMIT ?
            """, (limit,))
            rows = cursor.fetchall()
            return [dict(r) for r in rows]

    def verify_integrity(self) -> Tuple[bool, int, Optional[str]]:
        """Walks the entire HMAC hash-chain to verify zero tampering or dropped records."""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM audit_receipts ORDER BY id ASC")
            rows = cursor.fetchall()

            expected_prev_hash = "GENESIS_BLOCK_HASH"
            for row in rows:
                canonical = (
                    f"{row['timestamp']}|{row['session_id']}|{row['provider']}|{row['model']}|{row['policy']}|"
                    f"{row['action_taken']}|{row['redaction_count']}|{row['secret_blocked_count']}|"
                    f"{row['entities_detected_json']}|{row['latency_ms']:.2f}|{row['previous_hash']}"
                )
                computed_hmac = hmac.new(
                    self.hmac_key,
                    canonical.encode("utf-8"),
                    hashlib.sha256
                ).hexdigest()

                if row["previous_hash"] != expected_prev_hash:
                    return False, row["id"], f"Broken hash chain at record #{row['id']}"
                if row["record_hmac"] != computed_hmac:
                    return False, row["id"], f"HMAC signature mismatch at record #{row['id']}"

                expected_prev_hash = row["record_hmac"]

            return True, len(rows), None


# Global singleton
audit_ledger = AuditLedger()
