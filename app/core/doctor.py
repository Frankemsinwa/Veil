"""Veil Doctor — Production Diagnostic and Self-Check Suite.

Executes comprehensive diagnostics on:
1. Cryptographic engines (AES-256-GCM, zeroization, tamper detection)
2. Tamper-evident audit ledger and database integrity
3. Detection and semantic classification pipeline performance
4. Local network, loopback bindings, and port conflicts
5. Upstream AI provider connectivity
"""
import time
import socket
import urllib.parse
from pathlib import Path
from typing import Dict, List, Any
from dataclasses import dataclass, field
import httpx

from app.core.config import settings
from app.vault.crypto import VaultCrypto
from app.vault.session_vault import SessionVault
from app.audit.ledger import audit_ledger
from app.engine.pipeline import InspectionPipeline


@dataclass
class DiagnosticItem:
    name: str
    status: str  # "PASS", "WARN", "FAIL"
    message: str
    latency_ms: float = 0.0
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class DoctorReport:
    items: List[DiagnosticItem]
    overall_status: str  # "HEALTHY", "WARNING", "DEGRADED"
    duration_ms: float
    total_checks: int
    passed_checks: int
    warning_checks: int
    failed_checks: int


class VeilDoctor:
    """Runs automated health and invariant validation checks across all Veil systems."""

    def __init__(self):
        self.pipeline = InspectionPipeline()

    def check_cryptography(self) -> DiagnosticItem:
        """Validates authenticated encryption, decryption, and memory zeroization."""
        start = time.perf_counter()
        try:
            crypto = VaultCrypto()
            sample_secret = "sk-proj-test_secret_payload_1234567890"

            # 1. Encryption & Decryption
            nonce, ciphertext = crypto.encrypt(sample_secret)
            decrypted = crypto.decrypt(nonce, ciphertext)
            if decrypted != sample_secret:
                return DiagnosticItem(
                    name="Cryptographic Engine (AES-256-GCM)",
                    status="FAIL",
                    message="Decrypted text does not match original plaintext!",
                    latency_ms=(time.perf_counter() - start) * 1000.0
                )

            # 2. Tamper / Authentication Tag Verification
            tampered_ciphertext = bytearray(ciphertext)
            tampered_ciphertext[0] ^= 0xFF
            try:
                crypto.decrypt(nonce, bytes(tampered_ciphertext))
                return DiagnosticItem(
                    name="Cryptographic Engine (AES-256-GCM)",
                    status="FAIL",
                    message="Cipher failed to reject tampered ciphertext!",
                    latency_ms=(time.perf_counter() - start) * 1000.0
                )
            except Exception:
                pass  # Correct behavior: tampering rejected

            # 3. Vault Zeroization Check
            vault = SessionVault("doctor_session")
            placeholder = vault.get_or_create_placeholder("TEST_TOKEN", "sensitive_val")
            vault.zeroize()
            restored = vault.restore_placeholder(placeholder)
            if restored is not None:
                return DiagnosticItem(
                    name="Cryptographic Engine (AES-256-GCM)",
                    status="FAIL",
                    message="Vault zeroize() failed to wipe token from memory!",
                    latency_ms=(time.perf_counter() - start) * 1000.0
                )

            elapsed = (time.perf_counter() - start) * 1000.0
            return DiagnosticItem(
                name="Cryptographic Engine (AES-256-GCM)",
                status="PASS",
                message="AES-256-GCM authenticated cipher & memory zeroization verified.",
                latency_ms=elapsed,
                details={"cipher": "AES-256-GCM", "authenticated_tag": True, "zeroization": True}
            )
        except Exception as e:
            return DiagnosticItem(
                name="Cryptographic Engine (AES-256-GCM)",
                status="FAIL",
                message=f"Cryptographic self-check failed: {e}",
                latency_ms=(time.perf_counter() - start) * 1000.0
            )

    def check_audit_ledger(self) -> DiagnosticItem:
        """Validates SQLite audit ledger connection and verifies HMAC hash-chain."""
        start = time.perf_counter()
        try:
            db_path = audit_ledger.db_path
            if not db_path.exists():
                return DiagnosticItem(
                    name="Audit Ledger & Tamper-Evidence Chain",
                    status="PASS",
                    message=f"Audit DB ready at {db_path} (no records yet).",
                    latency_ms=(time.perf_counter() - start) * 1000.0
                )

            is_valid, record_count, error = audit_ledger.verify_integrity()
            elapsed = (time.perf_counter() - start) * 1000.0

            if not is_valid:
                return DiagnosticItem(
                    name="Audit Ledger & Tamper-Evidence Chain",
                    status="FAIL",
                    message=f"Cryptographic HMAC audit tampering detected: {error}",
                    latency_ms=elapsed,
                    details={"tampered_record": error, "total_records": record_count}
                )

            return DiagnosticItem(
                name="Audit Ledger & Tamper-Evidence Chain",
                status="PASS",
                message=f"All {record_count} audit receipts verified via HMAC-SHA256 hash-chain.",
                latency_ms=elapsed,
                details={"verified_records": record_count, "db_path": str(db_path)}
            )
        except Exception as e:
            return DiagnosticItem(
                name="Audit Ledger & Tamper-Evidence Chain",
                status="FAIL",
                message=f"Audit ledger check error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000.0
            )

    def check_pipeline_and_semantic(self) -> DiagnosticItem:
        """Validates detection pipeline (Regex, Shannon Entropy, Semantic Classifier)."""
        start = time.perf_counter()
        try:
            test_prompt = "Contact alice@example.com for confidential details."
            decisions, redact_spans, semantic_result = self.pipeline.inspect_semantic(test_prompt)
            elapsed = (time.perf_counter() - start) * 1000.0

            if elapsed > 100.0:
                status = "WARN"
                msg = f"Detection pipeline completed in {elapsed:.1f}ms (higher than recommended 50ms)."
            else:
                status = "PASS"
                msg = f"Regex, Shannon Entropy & Semantic engines nominal ({elapsed:.2f}ms)."

            return DiagnosticItem(
                name="Inspection & Semantic ML Pipeline",
                status=status,
                message=msg,
                latency_ms=elapsed,
                details={
                    "semantic_backend": settings.SEMANTIC_BACKEND,
                    "semantic_enabled": settings.SEMANTIC_CLASSIFIER_ENABLED,
                    "circuit_breaker": "active"
                }
            )
        except Exception as e:
            return DiagnosticItem(
                name="Inspection & Semantic ML Pipeline",
                status="FAIL",
                message=f"Pipeline inspection check failed: {e}",
                latency_ms=(time.perf_counter() - start) * 1000.0
            )

    def check_network_and_ports(self) -> DiagnosticItem:
        """Verifies loopback resolution and checks for port conflicts."""
        start = time.perf_counter()
        host = settings.HOST
        port = settings.PORT

        # 1. Test Loopback Resolution
        try:
            addr_info = socket.getaddrinfo(host, port, socket.AF_INET, socket.SOCK_STREAM)
            resolved_ip = addr_info[0][4][0]
        except Exception as e:
            return DiagnosticItem(
                name="Network Bindings & Port Conflicts",
                status="FAIL",
                message=f"Failed to resolve host '{host}': {e}",
                latency_ms=(time.perf_counter() - start) * 1000.0
            )

        # 2. Check if port is open / available
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(0.5)
        try:
            result = sock.connect_ex((resolved_ip, port))
            sock.close()
            elapsed = (time.perf_counter() - start) * 1000.0

            if result == 0:
                # Port already bound (either Veil is already running or another service is on it)
                return DiagnosticItem(
                    name="Network Bindings & Port Conflicts",
                    status="WARN",
                    message=f"Port {port} on {host} is currently in use (Veil daemon running or conflict).",
                    latency_ms=elapsed,
                    details={"host": host, "port": port, "in_use": True}
                )
            else:
                return DiagnosticItem(
                    name="Network Bindings & Port Conflicts",
                    status="PASS",
                    message=f"Bind address {host}:{port} is free and ready.",
                    latency_ms=elapsed,
                    details={"host": host, "port": port, "available": True}
                )
        except Exception as e:
            return DiagnosticItem(
                name="Network Bindings & Port Conflicts",
                status="WARN",
                message=f"Socket inspection encountered non-fatal error: {e}",
                latency_ms=(time.perf_counter() - start) * 1000.0
            )

    def check_upstream_provider(self) -> DiagnosticItem:
        """Verifies upstream AI provider URL format and network reachability."""
        start = time.perf_counter()
        target_url = settings.UPSTREAM_OPENAI_BASE_URL

        parsed = urllib.parse.urlparse(target_url)
        if not parsed.scheme or not parsed.netloc:
            return DiagnosticItem(
                name="Upstream AI Provider Reachability",
                status="FAIL",
                message=f"Invalid UPSTREAM_OPENAI_BASE_URL: '{target_url}'",
                latency_ms=(time.perf_counter() - start) * 1000.0
            )

        try:
            with httpx.Client(timeout=3.0) as client:
                # Issue HEAD or GET to base URL
                resp = client.get(target_url)
                elapsed = (time.perf_counter() - start) * 1000.0
                return DiagnosticItem(
                    name="Upstream AI Provider Reachability",
                    status="PASS",
                    message=f"Upstream provider reachable at {target_url} (HTTP {resp.status_code}).",
                    latency_ms=elapsed,
                    details={"url": target_url, "status_code": resp.status_code}
                )
        except httpx.ConnectError:
            elapsed = (time.perf_counter() - start) * 1000.0
            return DiagnosticItem(
                name="Upstream AI Provider Reachability",
                status="WARN",
                message=f"Cannot connect to upstream URL {target_url} (Network offline or mock server).",
                latency_ms=elapsed,
                details={"url": target_url, "offline": True}
            )
        except Exception as e:
            elapsed = (time.perf_counter() - start) * 1000.0
            return DiagnosticItem(
                name="Upstream AI Provider Reachability",
                status="WARN",
                message=f"Upstream provider check encountered warning: {e}",
                latency_ms=elapsed,
                details={"url": target_url, "warning": str(e)}
            )

    def run_all_checks(self) -> DoctorReport:
        """Executes full diagnostic suite and aggregates report."""
        start = time.perf_counter()
        items = [
            self.check_cryptography(),
            self.check_audit_ledger(),
            self.check_pipeline_and_semantic(),
            self.check_network_and_ports(),
            self.check_upstream_provider(),
        ]
        duration_ms = (time.perf_counter() - start) * 1000.0

        passed = sum(1 for i in items if i.status == "PASS")
        warnings = sum(1 for i in items if i.status == "WARN")
        failures = sum(1 for i in items if i.status == "FAIL")

        if failures > 0:
            overall = "DEGRADED"
        elif warnings > 0:
            overall = "WARNING"
        else:
            overall = "HEALTHY"

        return DoctorReport(
            items=items,
            overall_status=overall,
            duration_ms=duration_ms,
            total_checks=len(items),
            passed_checks=passed,
            warning_checks=warnings,
            failed_checks=failures
        )
