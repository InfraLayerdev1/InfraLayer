"""
InfraLayer Python SDK - CLI
============================

Command-line interface for InfraLayer.
"""

from __future__ import annotations

import asyncio
import json
import sys
from typing import Optional

import typer
from rich.console import Console
from rich.json import JSON
from rich.panel import Panel
from rich.syntax import Syntax

from . import (
    create_local_infralayer,
    create_remote_infralayer,
    InfraLayer,
    UserContext,
    RawContext,
    SanitizeOptionsInner,
)

app = typer.Typer(
    name="infralayer",
    help="InfraLayer CLI - Pre-LLM security filtering and sanitization",
    add_completion=False,
)
console = Console()


@app.command()
def sanitize(
    text: str = typer.Argument(..., help="Text to sanitize"),
    user_id: str = typer.Option(..., "--user-id", "-u", help="User ID"),
    tenant_id: str = typer.Option(..., "--tenant-id", "-t", help="Tenant ID"),
    role: str = typer.Option("employee", "--role", "-r", help="User role"),
    permissions: str = typer.Option("", "--permissions", "-p", help="Comma-separated permissions"),
    department: Optional[str] = typer.Option(None, "--department", "-d", help="User department"),
    access_level: Optional[int] = typer.Option(None, "--access-level", "-a", help="User access level"),
    remote: bool = typer.Option(False, "--remote", help="Use remote API mode"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Remote API URL"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Remote API key"),
    strict: bool = typer.Option(False, "--strict", help="Enable strict mode"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Sanitize text using InfraLayer."""
    user_context = UserContext(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        department=department,
        access_level=access_level,
        permissions=permissions.split(",") if permissions else [],
    )

    if remote:
        if not api_url or not api_key:
            console.print("[red]Error: --api-url and --api-key required for remote mode[/red]")
            sys.exit(1)
        infra = create_remote_infralayer(api_url, api_key, user_context)
    else:
        infra = create_local_infralayer()

    options = SanitizeOptionsInner(strict_mode=strict)

    async def run() -> None:
        try:
            result = await infra.sanitize(text, user_context, options)
            if json_output:
                console.print(JSON.from_data(result.model_dump()))
            else:
                _print_result(result)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            await infra.close()

    asyncio.run(run())


@app.command()
def scan(
    text: str = typer.Argument(..., help="Text to scan for injections"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Scan text for injection attempts (local mode only)."""
    infra = create_local_infralayer()

    async def run() -> None:
        try:
            details = await infra.scan_for_injections(text)
            if json_output:
                console.print(JSON.from_data([d.model_dump() for d in details]))
            else:
                _print_injection_details(details)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            await infra.close()

    asyncio.run(run())


@app.command()
def check_permission(
    user_id: str = typer.Option(..., "--user-id", "-u", help="User ID"),
    tenant_id: str = typer.Option(..., "--tenant-id", "-t", help="Tenant ID"),
    role: str = typer.Option("employee", "--role", "-r", help="User role"),
    permissions: str = typer.Option("", "--permissions", "-p", help="Comma-separated user permissions"),
    required_permissions: str = typer.Option(..., "--required", help="Comma-separated required permissions"),
    required_role: Optional[str] = typer.Option(None, "--required-role", help="Required role"),
    required_access_level: Optional[int] = typer.Option(None, "--required-access-level", help="Required access level"),
    required_department: Optional[str] = typer.Option(None, "--required-department", help="Required department"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check if user has permission for specific action (local mode only)."""
    user_context = UserContext(
        user_id=user_id,
        tenant_id=tenant_id,
        role=role,
        permissions=permissions.split(",") if permissions else [],
    )

    infra = create_local_infralayer()

    async def run() -> None:
        try:
            result = await infra.check_permission(
                user_context,
                required_permissions.split(",") if required_permissions else [],
                required_role,
                required_access_level,
                required_department,
            )
            if json_output:
                console.print(JSON.from_data(result.model_dump()))
            else:
                _print_permission_result(result)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            await infra.close()

    asyncio.run(run())


@app.command()
def health(
    remote: bool = typer.Option(False, "--remote", help="Check remote API health"),
    api_url: Optional[str] = typer.Option(None, "--api-url", help="Remote API URL"),
    api_key: Optional[str] = typer.Option(None, "--api-key", help="Remote API key"),
    json_output: bool = typer.Option(False, "--json", help="Output as JSON"),
) -> None:
    """Check health status."""
    if remote:
        if not api_url or not api_key:
            console.print("[red]Error: --api-url and --api-key required for remote mode[/red]")
            sys.exit(1)
        infra = create_remote_infralayer(api_url, api_key)
    else:
        infra = create_local_infralayer()

    async def run() -> None:
        try:
            result = await infra.health_check()
            if json_output:
                console.print(JSON.from_data(result.model_dump()))
            else:
                _print_health(result)
        except Exception as e:
            console.print(f"[red]Error: {e}[/red]")
            sys.exit(1)
        finally:
            await infra.close()

    asyncio.run(run())


@app.command()
def version() -> None:
    """Show version information."""
    from . import __version__
    console.print(f"InfraLayer Python SDK v{__version__}")


def _print_result(result) -> None:
    """Print sanitization result in human-readable format."""
    if result.sanitized_context:
        ctx = result.sanitized_context
        console.print(Panel(
            f"[green]Success[/green]\n\n"
            f"Original length: {ctx.original_length}\n"
            f"Sanitized length: {ctx.sanitized_length}\n"
            f"Segments removed: {len(ctx.removed_segments)}\n"
            f"Injections detected: {'Yes' if ctx.injection_detected else 'No'}\n"
            f"Processing time: {result.telemetry.processing_time_ms}ms",
            title="Sanitization Result",
            border_style="green",
        ))

        if ctx.removed_segments:
            console.print("\n[bold]Removed Segments:[/bold]")
            for seg in ctx.removed_segments:
                console.print(f"  [{seg.reason.value}] {seg.original_text[:50]}...")

        if ctx.injection_details:
            console.print("\n[bold]Injection Details:[/bold]")
            for det in ctx.injection_details:
                console.print(f"  [{det.severity.value}] {det.category.value}: {det.match}")

        console.print("\n[bold]Sanitized Text:[/bold]")
        console.print(Syntax(ctx.text, "text", theme="monokai", line_numbers=False))

    if result.permission_evaluation:
        perm = result.permission_evaluation
        style = "green" if perm.allowed else "red"
        console.print(Panel(
            f"Allowed: {'Yes' if perm.allowed else 'No'}\n"
            f"Reason: {perm.reason}\n"
            f"Required: {', '.join(perm.required_permissions) or 'None'}\n"
            f"User has: {', '.join(perm.user_permissions) or 'None'}",
            title="Permission Evaluation",
            border_style=style,
        ))


def _print_injection_details(details: list) -> None:
    """Print injection scan results."""
    if not details:
        console.print(Panel("No injections detected", title="Scan Result", border_style="green"))
        return

    console.print(Panel(
        f"[red]Found {len(details)} injection attempt(s)[/red]",
        title="Injection Scan",
        border_style="red",
    ))
    for det in details:
        console.print(f"  [{det.severity.value}] {det.category.value}: {det.match} (pos: {det.position})")


def _print_permission_result(result) -> None:
    """Print permission check result."""
    style = "green" if result.allowed else "red"
    console.print(Panel(
        f"Allowed: {'Yes' if result.allowed else 'No'}\n"
        f"Reason: {result.reason}\n"
        f"Required permissions: {', '.join(result.required_permissions) or 'None'}\n"
        f"User permissions: {', '.join(result.user_permissions) or 'None'}\n"
        f"Missing: {', '.join(result.missing_permissions or []) or 'None'}",
        title="Permission Check",
        border_style=style,
    ))


def _print_health(result) -> None:
    """Print health check result."""
    style = "green" if result.status == "healthy" else ("yellow" if result.status == "degraded" else "red")
    console.print(Panel(
        f"Status: {result.status}\n"
        f"Version: {result.version}\n"
        f"Timestamp: {result.timestamp}\n"
        f"Checks: {', '.join(f'{k}: {v}' for k, v in result.checks.items())}",
        title="Health Check",
        border_style=style,
    ))


def main() -> None:
    """Entry point for CLI."""
    app()


if __name__ == "__main__":
    main()