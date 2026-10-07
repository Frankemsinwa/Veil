"""Veil Command-Line Interface (CLI)."""
import sys
import time
from pathlib import Path
from typing import Optional

# Ensure root package directory is in sys.path when invoked directly
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import uvicorn
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from app.core.config import settings, PolicyLevel
from app.engine.pipeline import InspectionPipeline
from app.core.exceptions import SecretDetectedException, SemanticViolationException
from app.audit.ledger import audit_ledger

cli = typer.Typer(
    name="veil",
    help="Veil — Enterprise-Grade Local AI Privacy Gateway",
    add_completion=False
)
console = Console(highlight=False)


@cli.command("start")
def start(
    host: str = typer.Option(settings.HOST, "--host", "-h", help="Bind address"),
    port: int = typer.Option(settings.PORT, "--port", "-p", help="Listening port"),
    policy: PolicyLevel = typer.Option(settings.POLICY, "--policy", help="Active privacy policy tier"),
    reload: bool = typer.Option(False, "--reload", help="Enable hot-reload for development")
):
    """Start the Veil Privacy Gateway daemon."""
    console.print(Panel.fit(
        f"[bold cyan]VEIL AI PRIVACY GATEWAY[/bold cyan]\n"
        f"Status:       [bold green]FAIL-CLOSED ACTIVE[/bold green]\n"
        f"Policy:       [bold yellow]{policy.value}[/bold yellow]\n"
        f"Endpoint:     http://{host}:{port}/v1/chat/completions\n"
        f"Health Check: http://{host}:{port}/health",
        title="[bold white]Shield Online[/bold white]",
        border_style="cyan"
    ))

    uvicorn.run(
        "app.main:app",
        host=host,
        port=port,
        reload=reload,
        log_level="info"
    )


@cli.command("scan")
def scan(
    text: str = typer.Argument(..., help="Prompt text to scan for PII, secrets, or contextual proprietary data")
):
    """Inspect a prompt locally using the Veil deterministic and semantic policy engine."""
    pipeline = InspectionPipeline()
    console.print(f"[bold cyan]Scanning payload ({len(text)} characters)...[/bold cyan]")

    try:
        decisions, redact_spans, semantic_result = pipeline.inspect_semantic(text)

        # 1. Deterministic Spans Display
        if decisions:
            table = Table(title="Deterministic Pattern & Entropy Matches")
            table.add_column("Entity Type", style="cyan")
            table.add_column("Category", style="magenta")
            table.add_column("Action", style="bold yellow")
            table.add_column("Matched Slice", style="red")
            table.add_column("Confidence", style="green")

            for d in decisions:
                table.add_row(
                    d.span.entity_type.value,
                    d.span.category.value,
                    d.action.value,
                    d.span.matched_text,
                    f"{d.span.confidence:.2f}"
                )
            console.print(table)
            console.print(f"[bold green]Ready for redaction: {len(redact_spans)} items.[/bold green]")
        else:
            console.print("[bold green][CLEAN] No regex/entropy secrets or PII detected.[/bold green]")

        # 2. Contextual Semantic Classification Display
        if semantic_result:
            sem_table = Table(title="Semantic ML Contextual Classification (Phase 10)")
            sem_table.add_column("Metric", style="cyan", no_wrap=True)
            sem_table.add_column("Assessment", style="bold white")

            status_style = "bold red" if semantic_result.is_sensitive else "bold green"
            sem_table.add_row("Detected Category", f"[{status_style}]{semantic_result.category.value}[/{status_style}]")
            sem_table.add_row("Confidence", f"{semantic_result.confidence * 100:.1f}%")
            sem_table.add_row("Is Sensitive", f"[{status_style}]{str(semantic_result.is_sensitive)}[/{status_style}]")
            sem_table.add_row("Indicators", ", ".join(semantic_result.matched_indicators) if semantic_result.matched_indicators else "None")
            sem_table.add_row("Backend", semantic_result.backend_used)
            sem_table.add_row("Rationale", semantic_result.rationale)
            console.print(sem_table)

    except SecretDetectedException as e:
        console.print(Panel.fit(
            f"[bold red][BLOCKED] OUTBOUND TRANSMISSION HALTED[/bold red]\n\n"
            f"[white]{e.message}[/white]\n"
            f"Violations detected: {len(e.violations)}",
            title="[bold red]Security Guardrail Tripped (Secret Detected)[/bold red]",
            border_style="red"
        ))
        for v in e.violations:
            console.print(f"  * [red]{v['entity_type']}[/red] (Confidence: {v['confidence']})")

    except SemanticViolationException as sve:
        console.print(Panel.fit(
            f"[bold red][BLOCKED] PROPRIETARY DATA OUTBOUND TRANSMISSION HALTED[/bold red]\n\n"
            f"[white]{sve.message}[/white]\n"
            f"Contextual Category: [bold yellow]{sve.violations[0]['category']}[/bold yellow]\n"
            f"Confidence: [bold cyan]{sve.violations[0]['confidence'] * 100:.1f}%[/bold cyan]\n"
            f"Indicators: [white]{', '.join(sve.violations[0].get('indicators', []))}[/white]\n"
            f"Rationale: [dim]{sve.violations[0].get('rationale', '')}[/dim]",
            title="[bold red]Semantic Privacy Guardrail Tripped[/bold red]",
            border_style="red"
        ))


from app.core.doctor import VeilDoctor
from app.core.benchmark import VeilBenchmark


@cli.command("audit")
def audit(
    limit: int = typer.Option(20, "--limit", "-n", "--tail", help="Number of recent receipts to show"),
    verify: bool = typer.Option(True, "--verify", help="Check HMAC cryptographic integrity")
):
    """View tamper-evident compliance audit trail."""
    receipts = audit_ledger.get_recent_receipts(limit=limit)
    if not receipts:
        console.print("[yellow]No audit receipts recorded yet.[/yellow]")
        return

    table = Table(title=f"Veil Audit Trail (Last {len(receipts)} events)")
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Time", style="white")
    table.add_column("Action", style="bold yellow")
    table.add_column("Redactions", style="green")
    table.add_column("Blocks", style="red")
    table.add_column("Latency", style="magenta")
    table.add_column("HMAC Signature", style="blue")

    for r in receipts:
        formatted_time = time.strftime("%H:%M:%S", time.localtime(r["timestamp"]))
        table.add_row(
            str(r["id"]),
            formatted_time,
            r["action_taken"],
            str(r["redaction_count"]),
            str(r["secret_blocked_count"]),
            f"{r['latency_ms']:.1f}ms",
            f"{r['record_hmac'][:12]}..."
        )
    console.print(table)

    if verify:
        valid, count, error = audit_ledger.verify_integrity()
        if valid:
            console.print(f"[bold green][VERIFIED] All {count} audit records verified via HMAC hash chain.[/bold green]")
        else:
            console.print(f"[bold red][TAMPER WARNING] Audit verification failed: {error}[/bold red]")


@cli.command("doctor")
def doctor():
    """Run full self-check diagnostics on crypto, audit chain, detection pipeline, and ports."""
    console.print("[bold cyan]Running Veil self-check diagnostics...[/bold cyan]\n")
    report = VeilDoctor().run_all_checks()

    table = Table(title="Veil Doctor Diagnostic Report")
    table.add_column("Subsystem Check", style="bold white", no_wrap=True)
    table.add_column("Status", no_wrap=True)
    table.add_column("Latency", style="magenta", justify="right")
    table.add_column("Diagnostics & Findings", style="dim white")

    for item in report.items:
        if item.status == "PASS":
            status_text = "[bold green][PASS][/bold green]"
        elif item.status == "WARN":
            status_text = "[bold yellow][WARN][/bold yellow]"
        else:
            status_text = "[bold red][FAIL][/bold red]"

        table.add_row(
            item.name,
            status_text,
            f"{item.latency_ms:.2f}ms",
            item.message
        )

    console.print(table)

    if report.overall_status == "HEALTHY":
        console.print(Panel.fit(
            f"[bold green]ALL SYSTEMS OPERATIONAL ({report.passed_checks}/{report.total_checks} PASSED)[/bold green]\n"
            f"Veil is fully hardened and ready for secure outbound proxying.\n"
            f"Total check duration: {report.duration_ms:.2f}ms",
            title="[bold green]Veil Doctor Verdict[/bold green]",
            border_style="green"
        ))
    elif report.overall_status == "WARNING":
        console.print(Panel.fit(
            f"[bold yellow]SYSTEM OPERATIONAL WITH ADVISORIES ({report.warning_checks} WARNINGS)[/bold yellow]\n"
            f"Review warnings above before high-throughput production deployment.\n"
            f"Total check duration: {report.duration_ms:.2f}ms",
            title="[bold yellow]Veil Doctor Verdict[/bold yellow]",
            border_style="yellow"
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]CRITICAL SYSTEM DEGRADATION ({report.failed_checks} FAILED)[/bold red]\n"
            f"Fail-closed guardrails will block traffic until errors are resolved.\n"
            f"Total check duration: {report.duration_ms:.2f}ms",
            title="[bold red]Veil Doctor Verdict[/bold red]",
            border_style="red"
        ))


@cli.command("benchmark")
def benchmark(
    iterations: int = typer.Option(50, "--iterations", "-i", help="Iterations per test prompt")
):
    """Profile latency distributions, throughput (prompts/sec), and ReDoS immunity."""
    console.print(f"[bold cyan]Running Veil performance & ReDoS benchmark ({iterations * 8} runs)...[/bold cyan]")
    bench = VeilBenchmark()
    report = bench.run_benchmark(iterations=iterations)

    table = Table(title="Veil Latency & Throughput Benchmark")
    table.add_column("Metric", style="cyan", no_wrap=True)
    table.add_column("Measured Value", style="bold white")

    table.add_row("Total Prompts Processed", str(report.total_prompts))
    table.add_row("Total Characters Scanned", f"{report.total_characters:,}")
    table.add_row("Execution Duration", f"{report.duration_seconds:.3f}s")
    table.add_row("Throughput (Prompts/sec)", f"[bold green]{report.prompts_per_sec:,.1f}[/bold green]")
    table.add_row("Throughput (Chars/sec)", f"[bold green]{report.characters_per_sec:,.1f}[/bold green]")
    table.add_row("Mean Latency", f"{report.mean_latency_ms:.3f}ms")
    table.add_row("Median (p50) Latency", f"{report.median_latency_ms:.3f}ms")
    table.add_row("p95 Latency", f"{report.p95_latency_ms:.3f}ms")
    table.add_row("p99 Latency", f"{report.p99_latency_ms:.3f}ms")
    redos_style = "bold green" if report.redos_immune else "bold red"
    table.add_row("ReDoS Catastrophic Backtracking Immunity", f"[{redos_style}]{report.redos_immune} ({report.redos_test_duration_ms:.1f}ms for 50k chars)[/{redos_style}]")

    console.print(table)


@cli.command("policy")
def policy(
    tier: PolicyLevel = typer.Argument(None, help="Policy tier to set: STRICT, BALANCED, or PERMISSIVE")
):
    """View or switch active privacy policy tier."""
    if tier is None:
        console.print(f"Current policy tier: [bold cyan]{settings.POLICY.value}[/bold cyan]")
        console.print("Available tiers: STRICT, BALANCED, PERMISSIVE")
        return
    settings.POLICY = tier
    console.print(f"[bold green]Switched active policy tier to: {tier.value}[/bold green]")


@cli.command("status")
def status():
    """Display current Veil Gateway runtime configuration and policy settings."""
    table = Table(title="Veil Configuration & Security Invariants")
    table.add_column("Parameter", style="cyan", no_wrap=True)
    table.add_column("Current Value", style="magenta")
    table.add_column("Security Impact", style="green")

    table.add_row("Policy Tier", settings.POLICY.value, "Determines redaction vs block actions")
    table.add_row("Fail-Closed Mode", str(settings.FAIL_CLOSED), "Blocks outbound requests if privacy engine errors")
    table.add_row("Semantic Classifier", str(settings.SEMANTIC_CLASSIFIER_ENABLED), "Contextual proprietary/NDA sensitivity detection")
    table.add_row("Semantic Backend", settings.SEMANTIC_BACKEND, "Active classifier backend ('embedded', 'ollama', 'onnx')")
    table.add_row("Semantic Conf. Threshold", f"{settings.SEMANTIC_CONFIDENCE_THRESHOLD:.2f}", "Advisory warning threshold")
    table.add_row("Semantic Block Threshold", f"{settings.SEMANTIC_BLOCK_THRESHOLD:.2f}", "Automatic block threshold in STRICT mode")
    table.add_row("Upstream OpenAI URL", settings.UPSTREAM_OPENAI_BASE_URL, "Target remote model provider API")
    table.add_row("Session Vault TTL", f"{settings.SESSION_TTL_SECONDS}s", "Automatic token mapping memory zeroization")
    table.add_row("Audit Ledger DB", str(audit_ledger.db_path), "Cryptographic append-only compliance record")

    console.print(table)


from app.clients import client_manager


@cli.command("clients")
def list_clients():
    """Discover installed AI IDEs, CLI tools, and display connection status."""
    clients = client_manager.get_all_clients()
    table = Table(title="Detected AI Clients & Proxy Status")
    table.add_column("Client ID", style="cyan", no_wrap=True)
    table.add_column("Name", style="bold white")
    table.add_column("Status", no_wrap=True)
    table.add_column("Target Config Path", style="dim white")
    table.add_column("Current Base URL", style="magenta")

    for c in clients:
        if c.status.value == "CONNECTED":
            status_text = "[bold green][CONNECTED][/bold green]"
        elif c.status.value == "DETECTED":
            status_text = "[bold yellow][DETECTED][/bold yellow]"
        elif c.status.value == "NOT_INSTALLED":
            status_text = "[dim]NOT INSTALLED[/dim]"
        else:
            status_text = "[bold red][ERROR][/bold red]"

        table.add_row(
            c.id,
            f"{c.name}",
            status_text,
            c.config_path or "-",
            c.current_base_url or "Direct / None"
        )
    console.print(table)


@cli.command("connect")
def connect_client(
    client_id: str = typer.Argument(..., help="Client ID to connect: cursor, continue, claude_code, aider, system_env"),
    url: Optional[str] = typer.Option(None, "--url", "-u", help="Custom gateway base URL")
):
    """1-Click connect an AI client to route outbound prompts through Veil."""
    result = client_manager.connect_client(client_id, gateway_url=url)
    if result.success:
        console.print(f"[bold green][OK] {result.message}[/bold green]")
        if result.backup_path:
            console.print(f"  [dim]Backup saved to: {result.backup_path}[/dim]")
    else:
        console.print(f"[bold red][FAIL] {result.message}[/bold red]")


@cli.command("disconnect")
def disconnect_client(
    client_id: str = typer.Argument(..., help="Client ID to disconnect: cursor, continue, claude_code, aider, system_env")
):
    """1-Click disconnect an AI client and rollback its configuration."""
    result = client_manager.disconnect_client(client_id)
    if result.success:
        console.print(f"[bold green][OK] {result.message}[/bold green]")
    else:
        console.print(f"[bold red][FAIL] {result.message}[/bold red]")


@cli.command("disconnect-all")
def disconnect_all_clients():
    """Roll back all connected AI clients and restore original configurations (uninstaller hook)."""
    results = client_manager.disconnect_all()
    if not results:
        console.print("[dim]No connected clients to disconnect.[/dim]")
        return
    for cid, res in results.items():
        if res.success:
            console.print(f"[bold green][OK] {cid}: {res.message}[/bold green]")
        else:
            console.print(f"[bold red][FAIL] {cid}: {res.message}[/bold red]")


@cli.command("gui")
def gui(
    host: str = typer.Option(settings.HOST, "--host", "-h", help="Bind address"),
    port: int = typer.Option(settings.PORT, "--port", "-p", help="Listening port"),
    debug: bool = typer.Option(False, "--debug", help="Enable dev tools and verbose logging")
):
    """Launch Veil Enterprise Cockpit in a native desktop window with system tray resident."""
    from app.gui.runner import launch_gui
    launch_gui(host=host, port=port, debug=debug)


if __name__ == "__main__":
    cli()
