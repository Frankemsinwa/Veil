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


@cli.command("plans")
def list_plans():
    """Display available commercial pricing tiers, rates (NGN/USD), and active status."""
    from app.licensing.manager import license_manager

    plans = license_manager.get_all_plans()
    table = Table(title="Veil Commercial Pricing Plans & Feature Entitlements")
    table.add_column("Tier", style="bold cyan", no_wrap=True)
    table.add_column("Monthly Price", style="bold green", no_wrap=True)
    table.add_column("Max Clients", style="magenta", justify="center")
    table.add_column("Status", no_wrap=True)
    table.add_column("Key Capabilities", style="dim white")

    for p in plans:
        status_text = "[bold green]ACTIVE[/bold green]" if p.is_active else "[dim]Available[/dim]"
        if p.price_usd_monthly == 0:
            price_str = "Free"
        else:
            price_str = f"NGN {p.price_ngn_monthly:,} / ${p.price_usd_monthly:.0f}"

        table.add_row(
            p.name,
            price_str,
            str(p.max_clients) if p.max_clients < 900 else "Unlimited",
            status_text,
            "; ".join(p.features[:3]) + "..."
        )
    console.print(table)


@cli.command("license")
def show_license():
    """View active cryptographic license details, customer email, and entitlements."""
    from app.licensing.manager import license_manager
    lic = license_manager.get_active_license()

    status_color = "red" if lic.is_expired() else "green"
    status_label = "EXPIRED" if lic.is_expired() else "ACTIVE"

    table = Table(title="Veil Active Cryptographic License")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="bold white")

    table.add_row("License ID", lic.license_id)
    table.add_row("Commercial Tier", f"[bold yellow]{lic.tier.value}[/bold yellow]")
    table.add_row("Status", f"[{status_color}]{status_label}[/{status_color}]")
    table.add_row("Licensed To", lic.customer_email)
    table.add_row("Issued At", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lic.issued_at)))
    table.add_row("Expires At", time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(lic.expires_at)) if lic.expires_at else "Never (Perpetual / Free)")
    table.add_row("Max Simultaneous Clients", str(lic.max_clients) if lic.max_clients < 900 else "Unlimited")
    table.add_row("Entitled Features", ", ".join(f.value for f in lic.features))

    console.print(table)


@cli.command("activate")
def activate_key(
    key: str = typer.Argument(..., help="Cryptographically signed Veil license key string")
):
    """Activate a commercial Veil Pro or Enterprise license key."""
    from app.licensing.manager import license_manager
    valid, message, payload = license_manager.activate_license(key)

    if valid and payload:
        console.print(Panel.fit(
            f"[bold green]LICENSE ACTIVATION SUCCESSFUL[/bold green]\n\n"
            f"Tier:          [bold yellow]{payload.tier.value}[/bold yellow]\n"
            f"License ID:    {payload.license_id}\n"
            f"Customer:      {payload.customer_email}\n"
            f"Expires:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(payload.expires_at)) if payload.expires_at else 'Never'}",
            title="[bold green]Veil Licensing[/bold green]",
            border_style="green"
        ))
    else:
        console.print(Panel.fit(
            f"[bold red]ACTIVATION FAILED[/bold red]\n\n"
            f"[white]{message}[/white]",
            title="[bold red]Licensing Error[/bold red]",
            border_style="red"
        ))


@cli.command("checkout")
def checkout_cli(
    email: str = typer.Option(..., "--email", "-e", help="Customer email for invoice and license issuance"),
    tier: str = typer.Option("pro", "--tier", "-t", help="Target plan tier: pro or enterprise"),
    currency: str = typer.Option("NGN", "--currency", "-c", help="Payment currency: NGN or USD")
):
    """Generate a Paystack checkout link to upgrade your plan."""
    import asyncio
    from app.licensing.models import LicenseTier
    from app.billing.paystack import paystack_client
    from app.billing.routes import PLAN_PRICING

    target_tier = LicenseTier.PRO if tier.lower() == "pro" else LicenseTier.ENTERPRISE
    curr = currency.upper() if currency.upper() in ("NGN", "USD") else "NGN"
    amount = PLAN_PRICING[target_tier][curr]

    async def _run_checkout():
        return await paystack_client.initialize_transaction(
            email=email,
            amount=amount,
            currency=curr,
            metadata={"tier": target_tier.value, "email": email}
        )

    console.print(f"[bold cyan]Initializing {target_tier.value} checkout via Paystack ({curr})...[/bold cyan]")
    success, res = asyncio.run(_run_checkout())

    if success:
        formatted_price = f"NGN {amount // 100:,}" if curr == "NGN" else f"${amount / 100:.2f}"
        console.print(Panel.fit(
            f"[bold green]CHECKOUT READY ({formatted_price} / month)[/bold green]\n\n"
            f"Reference:  [bold yellow]{res['reference']}[/bold yellow]\n"
            f"Payment URL:\n[bold cyan]{res['authorization_url']}[/bold cyan]\n\n"
            f"[dim]Complete payment in your browser, then run: veil verify-payment {res['reference']}[/dim]",
            title="[bold green]Paystack Checkout[/bold green]",
            border_style="green"
        ))
    else:
        console.print(f"[bold red]Failed to create checkout: {res.get('error')}[/bold red]")


@cli.command("verify-payment")
def verify_payment_cli(
    reference: str = typer.Argument(..., help="Paystack transaction reference to verify")
):
    """Verify a completed Paystack transaction reference and activate the license."""
    import asyncio
    from app.billing.paystack import paystack_client
    from app.licensing.manager import license_manager
    from app.licensing.models import LicenseTier

    async def _verify():
        return await paystack_client.verify_transaction(reference)

    console.print(f"[bold cyan]Verifying transaction reference '{reference}'...[/bold cyan]")
    success, txn = asyncio.run(_verify())

    if success:
        meta = txn.get("metadata", {})
        tier_str = meta.get("tier", "PRO")
        email = txn.get("customer", {}).get("email") or meta.get("email", "customer@veil.local")
        tier_enum = LicenseTier.PRO if tier_str == "PRO" else LicenseTier.ENTERPRISE

        key_str, payload = license_manager.issue_license(tier_enum, email, duration_days=30)
        license_manager.activate_license(key_str)

        console.print(Panel.fit(
            f"[bold green]PAYMENT VERIFIED & PLAN ACTIVATED![/bold green]\n\n"
            f"Tier:         [bold yellow]{tier_enum.value}[/bold yellow]\n"
            f"Customer:     {email}\n"
            f"License ID:   {payload.license_id}\n"
            f"License Key:\n[bold cyan]{key_str}[/bold cyan]",
            title="[bold green]Upgrade Complete[/bold green]",
            border_style="green"
        ))
    else:
        console.print(f"[bold red]Verification failed: {txn.get('error')}[/bold red]")



# ------------------ Phase 1: Transparent Proxy & CA CLI ------------------

proxy_cli = typer.Typer(
    name="proxy",
    help="Manage Windows System Proxy and Local Certificate Authority (Zero-Config Interception)",
    add_completion=False
)
cli.add_typer(proxy_cli, name="proxy")


@proxy_cli.command("status")
def proxy_status_cli():
    """Display the current status of the Windows System Proxy and Veil Root CA."""
    from app.proxy.ca import ca_instance
    from app.proxy.wininet import proxy_manager
    from app.proxy.interceptor import transparent_proxy_server

    win_status = proxy_manager.get_status()
    ca_installed = ca_instance.is_root_ca_installed()

    table = Table(title="Veil Transparent System Proxy Status")
    table.add_column("Property", style="cyan", no_wrap=True)
    table.add_column("Value", style="bold white")

    proxy_style = "bold green" if win_status.get("enabled") else "bold yellow"
    table.add_row("Windows System Proxy", f"[{proxy_style}]{'ENABLED' if win_status.get('enabled') else 'DISABLED'}[/{proxy_style}]")
    table.add_row("Proxy Target Server", str(win_status.get("server") or f"{settings.PROXY_HOST}:{settings.PROXY_PORT}"))
    table.add_row("Proxy Bypass Rules", str(win_status.get("override") or "None"))

    ca_style = "bold green" if ca_installed else "bold red"
    table.add_row("Root CA Trusted", f"[{ca_style}]{'YES (Installed)' if ca_installed else 'NO (Run: veil proxy install-ca)'}[/{ca_style}]")
    table.add_row("Root CA Cert Path", str(ca_instance.ca_cert_path))
    table.add_row("Intercepted Domains", ", ".join(transparent_proxy_server.classifier.intercepted_domains))

    console.print(table)


@proxy_cli.command("enable")
def proxy_enable_cli(
    server: str = typer.Option(f"{settings.PROXY_HOST}:{settings.PROXY_PORT}", "--server", "-s", help="Proxy address:port")
):
    """Enable Windows System Proxy pointing to Veil (1-click transparent AI interception)."""
    from app.proxy.ca import ca_instance
    from app.proxy.wininet import proxy_manager

    # Ensure Root CA is installed
    if not ca_instance.is_root_ca_installed():
        console.print("[bold yellow]Root CA not detected in trust store. Installing Veil Root CA...[/bold yellow]")
        success, msg = ca_instance.install_root_ca()
        if success:
            console.print(f"[bold green][OK] {msg}[/bold green]")
        else:
            console.print(f"[bold red][FAIL] Failed to install CA: {msg}[/bold red]")

    ok = proxy_manager.enable_proxy(server=server)
    if ok:
        console.print(Panel.fit(
            f"[bold green]SYSTEM PROXY ACTIVATED[/bold green]\n\n"
            f"All outbound AI traffic will now route transparently through Veil at [bold cyan]{server}[/bold cyan].\n"
            f"Zero manual configuration required in OpenCode, Cursor, Continue, or browsers.\n\n"
            f"[dim]Run 'veil proxy disable' to restore normal network settings at any time.[/dim]",
            title="[bold green]Shield Active[/bold green]",
            border_style="green"
        ))
    else:
        console.print("[bold red]Failed to enable Windows System Proxy.[/bold red]")


@proxy_cli.command("disable")
def proxy_disable_cli():
    """Disable Windows System Proxy and restore direct network access."""
    from app.proxy.wininet import proxy_manager

    ok = proxy_manager.disable_proxy()
    if ok:
        console.print(Panel.fit(
            f"[bold yellow]SYSTEM PROXY DEACTIVATED[/bold yellow]\n\n"
            f"Windows network settings restored to direct bypass mode.",
            title="[bold yellow]Shield Standby[/bold yellow]",
            border_style="yellow"
        ))
    else:
        console.print("[bold red]Failed to disable Windows System Proxy.[/bold red]")


@proxy_cli.command("install-ca")
def proxy_install_ca_cli():
    """Install and trust Veil Root CA in the CurrentUser certificate store."""
    from app.proxy.ca import ca_instance

    console.print("[bold cyan]Installing Veil Root CA into Windows CurrentUser root store...[/bold cyan]")
    success, msg = ca_instance.install_root_ca()
    if success:
        console.print(f"[bold green][OK] {msg}[/bold green]")
    else:
        console.print(f"[bold red][FAIL] {msg}[/bold red]")


@proxy_cli.command("uninstall-ca")
def proxy_uninstall_ca_cli():
    """Uninstall Veil Root CA from the CurrentUser certificate store."""
    from app.proxy.ca import ca_instance

    console.print("[bold cyan]Removing Veil Root CA from Windows CurrentUser root store...[/bold cyan]")
    success, msg = ca_instance.uninstall_root_ca()
    if success:
        console.print(f"[bold green][OK] {msg}[/bold green]")
    else:
        console.print(f"[bold red][FAIL] {msg}[/bold red]")


if __name__ == "__main__":
    cli()

