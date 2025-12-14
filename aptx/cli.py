"""
APT-X Command Line Interface
============================

Main CLI entry point for the APT-X penetration testing framework.
Provides commands for scanning, configuration, reporting, and management.
"""

import sys
import asyncio
from pathlib import Path
from typing import List, Optional
from datetime import datetime

import click
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.prompt import Confirm
from rich import print as rprint

from aptx import __version__
from aptx.core.config import get_config, Config
from aptx.core.database import get_database, ScanStatus
from aptx.core.logger import get_logger
from aptx.core.scope import ScopeValidator, ScopeConfig
from aptx.core.rate_limiter import RateLimiter, RateLimitConfig
from aptx.core.pipeline import Pipeline, create_default_pipeline
from aptx.core.exceptions import APTXError, ScopeViolationError, AuthorizationError

console = Console()

# Authorization banner
AUTHORIZATION_BANNER = """
[bold red]WARNING: AUTHORIZED USE ONLY[/bold red]

APT-X is a penetration testing framework designed for authorized
security assessments only. Unauthorized access to computer systems
is illegal and unethical.

By using this tool, you confirm that:

  1. You have explicit written authorization to test the target(s)
  2. You understand the legal implications of penetration testing
  3. You will only test systems within your authorized scope
  4. You accept full responsibility for your actions

[bold yellow]Unauthorized use may result in criminal prosecution.[/bold yellow]
"""


def show_banner():
    """Display the APT-X banner."""
    banner = f"""
[bold blue]
    ___    ____  ______   _  __
   /   |  / __ \\/_  __/  | |/ /
  / /| | / /_/ / / /     |   /
 / ___ |/ ____/ / /     /   |
/_/  |_/_/     /_/     /_/|_|
[/bold blue]
[dim]Automated Penetration Testing - eXtended[/dim]
[dim]Version {__version__}[/dim]
"""
    console.print(banner)


def require_authorization() -> bool:
    """
    Display authorization warning and require confirmation.

    Returns:
        True if user confirms authorization
    """
    console.print(Panel(AUTHORIZATION_BANNER, title="Authorization Required", border_style="red"))

    if not Confirm.ask("\n[bold]Do you have authorization to perform this test?[/bold]"):
        console.print("[red]Authorization declined. Exiting.[/red]")
        return False

    # Log authorization
    logger = get_logger()
    logger.audit(
        "auth_accepted",
        "User confirmed authorization",
        user=Path.home().name
    )

    return True


@click.group()
@click.version_option(version=__version__, prog_name="APT-X")
@click.option("--config", "-c", type=click.Path(exists=True), help="Path to config file")
@click.option("--debug", is_flag=True, help="Enable debug mode")
@click.option("--quiet", "-q", is_flag=True, help="Suppress banner and non-essential output")
@click.pass_context
def main(ctx, config, debug, quiet):
    """
    APT-X - Automated Penetration Testing Framework

    Enterprise-grade security assessment automation tool.
    """
    ctx.ensure_object(dict)

    # Load configuration
    cfg = get_config(config_path=config)
    cfg.ensure_directories()
    ctx.obj["config"] = cfg

    # Setup logging
    log_level = "DEBUG" if debug else cfg.get("logging.level", "INFO")
    logger = get_logger(level=log_level)
    ctx.obj["logger"] = logger
    ctx.obj["debug"] = debug
    ctx.obj["quiet"] = quiet

    # Show banner unless quiet mode
    if not quiet and ctx.invoked_subcommand != "version":
        show_banner()


@main.command()
@click.argument("target")
@click.option("--name", "-n", help="Scan name")
@click.option(
    "--vulns", "-v",
    help="Vulnerability types to check (comma-separated: sqli,xss,idor,ssrf)"
)
@click.option(
    "--stages", "-s",
    help="Pipeline stages to run (comma-separated)"
)
@click.option("--safe-mode/--no-safe-mode", default=True, help="Enable safe/non-destructive mode")
@click.option("--scope-file", type=click.Path(exists=True), help="Path to scope YAML file")
@click.option("--rate-limit", type=float, default=10.0, help="Requests per second limit")
@click.option("--output", "-o", type=click.Path(), help="Output directory for results")
@click.option("--skip-auth", is_flag=True, hidden=True, help="Skip authorization (for testing)")
@click.pass_context
def scan(ctx, target, name, vulns, stages, safe_mode, scope_file, rate_limit, output, skip_auth):
    """
    Run a penetration test scan against a target.

    TARGET can be a domain, IP address, or URL.

    Examples:

        aptx scan example.com

        aptx scan example.com --vulns sqli,xss --safe-mode

        aptx scan https://example.com/app --scope-file scope.yaml
    """
    config = ctx.obj["config"]
    logger = ctx.obj["logger"]

    # Require authorization
    if not skip_auth and config.get("safety.require_authorization", True):
        if not require_authorization():
            sys.exit(1)

    # Parse options
    vuln_types = [v.strip() for v in vulns.split(",")] if vulns else []
    stage_list = [s.strip() for s in stages.split(",")] if stages else None

    # Setup scope validator
    scope = None
    if scope_file:
        scope = ScopeValidator(config_file=scope_file)
        console.print(f"[green]Loaded scope from {scope_file}[/green]")
    elif config.get("scope.strict_mode", True):
        # Create default scope with target
        scope_config = ScopeConfig(
            name="auto",
            strict_mode=True,
            allowed_domains=[target]
        )
        scope = ScopeValidator(config=scope_config)
        console.print("[yellow]Auto-created scope for target only (strict mode)[/yellow]")

    # Setup rate limiter
    rate_limiter = RateLimiter(RateLimitConfig(
        requests_per_second=rate_limit,
        burst_size=int(rate_limit * 2)
    ))

    # Create pipeline
    pipeline = create_default_pipeline()
    pipeline.scope = scope
    pipeline.rate_limiter = rate_limiter

    # Progress display
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        console=console
    ) as progress:
        scan_task = progress.add_task(f"Scanning {target}...", total=100)

        def update_progress(stage, status, pct, message):
            progress.update(scan_task, completed=pct, description=f"[{stage}] {message or status}")

        pipeline.on_progress(update_progress)

        # Run scan
        console.print(f"\n[bold]Starting scan of [cyan]{target}[/cyan][/bold]")
        console.print(f"  Safe mode: {'[green]ON[/green]' if safe_mode else '[red]OFF[/red]'}")
        console.print(f"  Rate limit: {rate_limit} req/s")
        if vuln_types:
            console.print(f"  Vulnerability types: {', '.join(vuln_types)}")
        console.print()

        try:
            # Run async pipeline
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            context = loop.run_until_complete(
                pipeline.run(
                    target=target,
                    stages=stage_list,
                    vuln_types=vuln_types,
                    safe_mode=safe_mode,
                    scan_name=name
                )
            )
            loop.close()

            progress.update(scan_task, completed=100)

        except ScopeViolationError as e:
            console.print(f"\n[red]Scope Violation: {e}[/red]")
            sys.exit(1)
        except APTXError as e:
            console.print(f"\n[red]Error: {e}[/red]")
            sys.exit(1)

    # Display results summary
    console.print("\n[bold green]Scan Complete![/bold green]\n")

    # Results table
    table = Table(title="Scan Results", show_header=True, header_style="bold")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="white")

    table.add_row("Scan ID", context.scan_id)
    table.add_row("Target", target)
    table.add_row("Subdomains Found", str(len(context.subdomains)))
    table.add_row("Web Servers", str(len(context.web_servers)))
    table.add_row("Endpoints", str(len(context.endpoints)))
    table.add_row("Total Findings", str(len(context.findings)))

    console.print(table)

    # Findings breakdown by severity
    if context.findings:
        console.print("\n[bold]Findings by Severity:[/bold]")
        severity_counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in context.findings:
            sev = finding.get("severity", "info").lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

        severity_colors = {
            "critical": "red",
            "high": "orange1",
            "medium": "yellow",
            "low": "blue",
            "info": "dim"
        }
        for sev, count in severity_counts.items():
            if count > 0:
                color = severity_colors.get(sev, "white")
                console.print(f"  [{color}]{sev.upper()}: {count}[/{color}]")

    console.print(f"\n[dim]Scan ID: {context.scan_id}[/dim]")
    console.print("[dim]Use 'aptx report <scan_id>' to generate a detailed report[/dim]")


@main.command()
@click.pass_context
def init(ctx):
    """
    Initialize APT-X configuration and directories.

    Creates the necessary directory structure and default configuration files.
    """
    config = ctx.obj["config"]

    console.print("[bold]Initializing APT-X...[/bold]\n")

    # Create directories
    config.ensure_directories()
    console.print("[green]Created data directories[/green]")

    # Initialize database
    db = get_database()
    db.create_tables()
    console.print("[green]Initialized database[/green]")

    # Create default scope template
    scope_template = Path.home() / ".aptx" / "scope_template.yaml"
    if not scope_template.exists():
        scope_content = """# APT-X Scope Configuration Template
# Copy this file and customize for your engagement

name: "Example Engagement"
description: "Authorized penetration test for Example Corp"

# Strict mode requires explicit allowlist entries
strict_mode: true

# Block private IP ranges and localhost
block_private_ips: true
block_localhost: true

# Allowed targets
allowed_domains:
  - "example.com"
  - "*.example.com"

allowed_ips: []

allowed_cidrs: []

# Explicitly blocked
blocked_domains:
  - "production.example.com"

blocked_paths:
  - "/admin/delete"
  - "/api/v1/users/delete"
"""
        scope_template.write_text(scope_content)
        console.print(f"[green]Created scope template: {scope_template}[/green]")

    console.print("\n[bold green]APT-X initialized successfully![/bold green]")
    console.print(f"\nConfiguration directory: [cyan]{Path.home() / '.aptx'}[/cyan]")


@main.command()
@click.option("--status", type=click.Choice(["pending", "running", "completed", "failed"]))
@click.option("--limit", default=20, help="Number of scans to show")
@click.pass_context
def scans(ctx, status, limit):
    """
    List all scans.

    Shows recent scans with their status and findings count.
    """
    db = get_database()
    scan_list = db.list_scans(status=status, limit=limit)

    if not scan_list:
        console.print("[yellow]No scans found[/yellow]")
        return

    table = Table(title="Scans", show_header=True, header_style="bold")
    table.add_column("ID", style="cyan", max_width=12)
    table.add_column("Target")
    table.add_column("Status")
    table.add_column("Findings", justify="right")
    table.add_column("Created")

    status_styles = {
        "pending": "yellow",
        "running": "blue",
        "completed": "green",
        "failed": "red",
        "cancelled": "dim"
    }

    for scan in scan_list:
        status_style = status_styles.get(scan["status"], "white")
        table.add_row(
            scan["id"][:12],
            scan["target"][:40],
            f"[{status_style}]{scan['status']}[/{status_style}]",
            str(scan.get("total_findings", 0)),
            scan["created_at"][:19] if scan.get("created_at") else "-"
        )

    console.print(table)


@main.command()
@click.argument("scan_id")
@click.option("--format", "-f", "fmt", type=click.Choice(["html", "pdf", "json"]), default="html")
@click.option("--output", "-o", type=click.Path(), help="Output file path")
@click.pass_context
def report(ctx, scan_id, fmt, output):
    """
    Generate a report for a scan.

    SCAN_ID is the ID of the scan to report on.
    """
    db = get_database()
    scan = db.get_scan(scan_id)

    if not scan:
        console.print(f"[red]Scan not found: {scan_id}[/red]")
        sys.exit(1)

    console.print(f"[bold]Generating {fmt.upper()} report for scan {scan_id}...[/bold]")

    # Get findings
    findings = db.get_findings(scan_id)

    if not output:
        output = f"report_{scan_id[:8]}.{fmt}"

    # Import and use reporting module
    try:
        from aptx.reporting.generator import ReportGenerator
        generator = ReportGenerator()
        report_path = generator.generate(
            scan=scan,
            findings=findings,
            format=fmt,
            output_path=output
        )
        console.print(f"[green]Report saved to: {report_path}[/green]")
    except ImportError:
        console.print("[yellow]Reporting module not available. Outputting JSON summary.[/yellow]")
        import json
        report_data = {
            "scan": scan,
            "findings": findings,
            "generated_at": datetime.utcnow().isoformat()
        }
        Path(output).write_text(json.dumps(report_data, indent=2))
        console.print(f"[green]Report saved to: {output}[/green]")


@main.group()
def feed():
    """Manage intelligence data feeds."""
    pass


@feed.command("ingest")
@click.argument("source")
@click.option("--type", "-t", "source_type", help="Source type (file, url, github)")
@click.pass_context
def feed_ingest(ctx, source, source_type):
    """
    Ingest data from a source into the intelligence engine.

    SOURCE can be a file path, URL, or GitHub repository.
    """
    console.print(f"[bold]Ingesting data from: {source}[/bold]")

    try:
        from aptx.data_feeds.ingestor import DataIngestor
        ingestor = DataIngestor()
        result = ingestor.ingest(source, source_type=source_type)
        console.print(f"[green]Ingested {result['items_added']} items[/green]")
    except ImportError:
        console.print("[yellow]Data feed module not fully implemented[/yellow]")


@feed.command("list")
@click.pass_context
def feed_list(ctx):
    """List available data feeds and their status."""
    db = get_database()

    console.print("[bold]Intelligence Data Summary:[/bold]\n")

    # Count by type
    table = Table(show_header=True, header_style="bold")
    table.add_column("Data Type")
    table.add_column("Count", justify="right")

    for data_type in ["payload", "wordlist", "bypass", "detection_logic"]:
        items = db.get_intelligence(data_type=data_type, limit=1)
        # This is simplified - would need a count query in production
        table.add_row(data_type, str(len(items)))

    console.print(table)


@main.group()
def config():
    """Manage APT-X configuration."""
    pass


@config.command("show")
@click.option("--section", "-s", help="Show specific section")
@click.pass_context
def config_show(ctx, section):
    """Display current configuration."""
    cfg = ctx.obj["config"]

    if section:
        data = cfg.get_section(section)
        console.print(f"[bold]{section}:[/bold]")
    else:
        data = cfg.to_dict()
        console.print("[bold]Current Configuration:[/bold]")

    import yaml
    console.print(yaml.dump(data, default_flow_style=False))


@config.command("path")
@click.pass_context
def config_path(ctx):
    """Show configuration file paths."""
    cfg = ctx.obj["config"]

    console.print("[bold]Configuration Files:[/bold]\n")
    for path in cfg.loaded_files:
        console.print(f"  [cyan]{path}[/cyan]")

    console.print(f"\n[bold]Data Directory:[/bold] {cfg.get('general.data_dir')}")
    console.print(f"[bold]Log Directory:[/bold] {cfg.get('general.log_dir')}")


@main.command()
@click.option("--host", default="127.0.0.1", help="Host to bind to")
@click.option("--port", default=8080, help="Port to bind to")
@click.pass_context
def ui(ctx, host, port):
    """
    Start the web UI server.

    Launches the FastAPI-based web interface for APT-X.
    """
    config = ctx.obj["config"]

    console.print(f"[bold]Starting APT-X Web UI...[/bold]")
    console.print(f"  Host: {host}")
    console.print(f"  Port: {port}")
    console.print(f"\n  Access at: [cyan]http://{host}:{port}[/cyan]")
    console.print("  Press Ctrl+C to stop\n")

    try:
        import uvicorn
        from aptx.ui.app import create_app

        app = create_app()
        uvicorn.run(app, host=host, port=port, log_level="info")
    except ImportError as e:
        console.print(f"[red]Failed to start UI: {e}[/red]")
        console.print("[yellow]Make sure uvicorn and fastapi are installed[/yellow]")
        sys.exit(1)


@main.command()
def version():
    """Show version information."""
    console.print(f"APT-X version [bold]{__version__}[/bold]")
    console.print("Automated Penetration Testing - eXtended Framework")


@main.command()
@click.argument("target")
@click.pass_context
def check_scope(ctx, target):
    """
    Check if a target is within scope.

    Useful for validating targets before scanning.
    """
    scope_file = ctx.obj["config"].get("scope.allowlist_file")

    if scope_file:
        scope = ScopeValidator(config_file=scope_file)
    else:
        console.print("[yellow]No scope file configured. Using permissive mode.[/yellow]")
        scope = ScopeValidator(config=ScopeConfig(strict_mode=False))

    valid, reason = scope.validate(target)

    if valid:
        console.print(f"[green]Target '{target}' is within scope[/green]")
        console.print(f"  Reason: {reason}")
    else:
        console.print(f"[red]Target '{target}' is OUT OF SCOPE[/red]")
        console.print(f"  Reason: {reason}")


if __name__ == "__main__":
    main()
