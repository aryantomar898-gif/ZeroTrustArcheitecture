"""
S1: Session Revocation CLI.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
from rich.table import Table

from sentinelcommand.core.config import get_settings
from sentinelcommand.modules.session_revoke.engine import get_session_engine, save_revocation_log

console = Console()
_settings = get_settings()


@click.group(name="session-revoke", help="Manage and revoke Microsoft Entra ID user sessions.")
def session_revoke_cli():
    pass


@session_revoke_cli.command(name="list-users")
@click.option("--department", "-d", help="Filter by department (e.g., 'IT', 'Finance')")
def list_users(department: str | None):
    """List all users from Entra ID."""
    import asyncio
    
    async def _run():
        engine = get_session_engine()
        with console.status("[bold blue]Connecting to Entra ID..."):
            await engine.authenticate()
            users = await engine.list_users(department)
        
        table = Table(title=f"Entra ID Users {'(Department: ' + department + ')' if department else ''}")
        table.add_column("Display Name", style="cyan")
        table.add_column("Email", style="green")
        table.add_column("Department", justify="right", style="magenta")
        table.add_column("Status", justify="right")
        
        for u in users:
            status_color = "green" if u.account_enabled else "red"
            status_text = "Enabled" if u.account_enabled else "Disabled"
            table.add_row(u.display_name, u.email, u.department, f"[{status_color}]{status_text}[/]")
            
        console.print(table)
        console.print(f"Total users: {len(users)}")
        
    asyncio.run(_run())


@session_revoke_cli.command(name="revoke-all")
@click.option("--department", "-d", help="Target specific department only")
@click.option("--confirm/--no-confirm", default=False, help="Skip confirmation prompt")
def revoke_all(department: str | None, confirm: bool):
    """Revoke sessions for all users (or a specific department)."""
    import asyncio
    
    if not confirm:
        target = f"the '{department}' department" if department else "ALL users in the tenant"
        click.confirm(
            f"⚠️ WARNING: You are about to revoke sessions for {target}. Continue?",
            abort=True,
        )
        
    async def _run():
        engine = get_session_engine()
        await engine.authenticate()
        
        users = await engine.list_users(department)
        if not users:
            console.print("[yellow]No users found matching criteria.[/]")
            return
            
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            console=console,
        ) as progress:
            task = progress.add_task("[cyan]Revoking sessions...", total=len(users))
            
            def on_progress(current, total, name):
                progress.update(task, advance=1, description=f"[cyan]Revoking: {name}")
                
            results = await engine.revoke_all_sessions(
                department=department,
                progress_callback=on_progress
            )
            
        successes = sum(1 for r in results if r.success)
        failures = sum(1 for r in results if not r.success)
        
        console.print("\n[bold green]Revocation Complete![/]")
        console.print(f"Success: {successes} | Failed: {failures}")
        
        log_file = save_revocation_log(results)
        console.print(f"Log saved to: {log_file}")
        
    asyncio.run(_run())


@session_revoke_cli.command(name="revoke-user")
@click.argument("user_id")
def revoke_user(user_id: str):
    """Revoke sessions for a specific user ID."""
    import asyncio
    
    async def _run():
        engine = get_session_engine()
        with console.status(f"[bold blue]Revoking sessions for {user_id}..."):
            await engine.authenticate()
            result = await engine.revoke_user_sessions(user_id)
            
        if result.success:
            console.print(f"[bold green]✓ Successfully revoked sessions for {result.user_email}[/]")
        else:
            console.print(f"[bold red]✗ Failed to revoke sessions: {result.error}[/]")
            
    asyncio.run(_run())
