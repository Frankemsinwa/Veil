"""Tests for Phase 11: Production Hardening, Packaging, CLI, and Doctor Diagnostics."""
import logging
import pytest
from typer.testing import CliRunner

from app.cli import cli
from app.core.config import settings, PolicyLevel
from app.core.log_scrubber import scrub_string, VeilLogScrubber
from app.core.doctor import VeilDoctor
from app.core.benchmark import VeilBenchmark
from app.audit.ledger import AuditLedger
from app.vault.session_vault import VaultManager


runner = CliRunner()


def test_log_scrubber_masks_sensitive_patterns():
    # OpenAI key
    msg1 = "Connection attempt with key sk-proj-1234567890abcdef1234567890"
    scrubbed1 = scrub_string(msg1)
    assert "[REDACTED_API_KEY]" in scrubbed1
    assert "sk-proj" not in scrubbed1

    # Email and AWS key
    msg2 = "Forwarding user bob@company.com credentials with key AKIAIOSFODNN7EXAMPLE"
    scrubbed2 = scrub_string(msg2)
    assert "[REDACTED_EMAIL]" in scrubbed2
    assert "[REDACTED_AWS_KEY]" in scrubbed2
    assert "bob@company.com" not in scrubbed2
    assert "AKIAIOSFODNN7EXAMPLE" not in scrubbed2

    # Credit card
    msg3 = "Processed payment for 4532 0151 1283 0366 successfully"
    scrubbed3 = scrub_string(msg3)
    assert "[REDACTED_CREDIT_CARD]" in scrubbed3
    assert "4532 0151 1283 0366" not in scrubbed3


def test_log_scrubber_filter_integration():
    scrubber = VeilLogScrubber()
    record = logging.LogRecord(
        name="test_logger",
        level=logging.INFO,
        pathname="test.py",
        lineno=10,
        msg="Leaked secret: sk-proj-1234567890abcdef1234567890 for user %s",
        args=("admin@secret.org",),
        exc_info=None
    )
    scrubber.filter(record)
    assert "[REDACTED_API_KEY]" in record.msg
    assert "[REDACTED_EMAIL]" in record.args[0]


def test_doctor_diagnostics_nominal():
    doctor = VeilDoctor()
    report = doctor.run_all_checks()

    # Core cryptographic and pipeline checks must pass unconditionally
    crypto_item = next(i for i in report.items if "Cryptographic" in i.name)
    assert crypto_item.status == "PASS"

    audit_item = next(i for i in report.items if "Audit" in i.name)
    assert audit_item.status == "PASS"

    pipeline_item = next(i for i in report.items if "Pipeline" in i.name)
    assert pipeline_item.status == "PASS"

    # Overall system status must be healthy or warning (never degraded in clean tests)
    assert report.overall_status in ("HEALTHY", "WARNING")
    assert report.failed_checks == 0


def test_doctor_detects_tampered_audit_chain(tmp_path, monkeypatch):
    tampered_db = tmp_path / "tampered_audit.db"
    test_ledger = AuditLedger(db_path=tampered_db)

    # Insert valid records
    test_ledger.record_receipt(
        session_id="s1", provider="openai", model="gpt-4o", policy="STRICT",
        action_taken="ALLOWED_CLEAN", redaction_count=0, secret_blocked_count=0,
        entities_detected=[], latency_ms=10.0
    )
    test_ledger.record_receipt(
        session_id="s2", provider="openai", model="gpt-4o", policy="STRICT",
        action_taken="BLOCKED", redaction_count=0, secret_blocked_count=1,
        entities_detected=["OPENAI_API_KEY"], latency_ms=5.0
    )

    # Corrupt record 1 directly in SQLite
    with test_ledger._get_connection() as conn:
        conn.execute("UPDATE audit_receipts SET action_taken = 'TAMPERED' WHERE id = 1")
        conn.commit()

    monkeypatch.setattr("app.core.doctor.audit_ledger", test_ledger)
    doctor = VeilDoctor()
    item = doctor.check_audit_ledger()

    assert item.status == "FAIL"
    assert "tampering detected" in item.message.lower()


def test_benchmark_performance_and_redos_immunity():
    bench = VeilBenchmark()
    report = bench.run_benchmark(iterations=3)

    assert report.total_prompts == 24
    assert report.prompts_per_sec > 5.0
    assert report.mean_latency_ms < 150.0
    assert report.redos_immune is True
    assert report.redos_test_duration_ms < 500.0


def test_vault_manager_zeroize_all():
    mgr = VaultManager()
    v1 = mgr.get_session("sess_1")
    v2 = mgr.get_session("sess_2")
    p1 = v1.get_or_create_placeholder("EMAIL", "user1@example.com")
    p2 = v2.get_or_create_placeholder("EMAIL", "user2@example.com")

    # Assert active
    assert v1.restore_placeholder(p1) == "user1@example.com"
    assert v2.restore_placeholder(p2) == "user2@example.com"

    # Zeroize all
    mgr.zeroize_all()
    assert len(mgr._sessions) == 0
    assert v1.restore_placeholder(p1) is None
    assert v2.restore_placeholder(p2) is None


def test_cli_doctor_command():
    result = runner.invoke(cli, ["doctor"])
    assert result.exit_code == 0
    assert "Veil Doctor Diagnostic Report" in result.output
    assert "Cryptographic Engine" in result.output


def test_cli_benchmark_command():
    result = runner.invoke(cli, ["benchmark", "--iterations", "1"])
    assert result.exit_code == 0
    assert "Veil Latency & Throughput Benchmark" in result.output
    assert "ReDoS Catastrophic Backtracking Immunity" in result.output


def test_cli_policy_switch():
    result = runner.invoke(cli, ["policy", "BALANCED"])
    assert result.exit_code == 0
    assert "Switched active policy tier to: BALANCED" in result.output
    assert settings.POLICY == PolicyLevel.BALANCED

    # Restore to strict
    runner.invoke(cli, ["policy", "STRICT"])
    assert settings.POLICY == PolicyLevel.STRICT


def test_cli_audit_tail_alias():
    result = runner.invoke(cli, ["audit", "--tail", "5"])
    assert result.exit_code == 0
