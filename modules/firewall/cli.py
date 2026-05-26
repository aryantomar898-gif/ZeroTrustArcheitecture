"""
S2: Firewall Manager CLI.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.prompt import Confirm
from rich.table import Table
from rich.panel import Panel

from sentinelcommand.modules.firewall.engine import get_firewall_engine

console = Console()


@click.group(name="firewall", help="Manage ransomware defense firewall rules (iptables).")
def firewall_cli():
    pass


@firewall_cli.command(name="menu")
def interactive_menu():
    """Interactive firewall management menu."""
    import asyncio
    
    async def _run():
        engine = get_firewall_engine()
        
        while True:
            console.clear()
            console.print(Panel("[bold cyan]Ransomware Firewall Manager (S2)[/]", expand=False))
            console.print("1. [red]Block SMB Ports (Anti-Ransomware)[/]")
            console.print("2. [yellow]Emergency Microsegmentation[/]")
            console.print("3. [green]Reset All Rules (Allow All)[/]")
            console.print("4. [blue]Show Current Rules[/]")
            console.print("5. [dim]Exit[/]")
            
            choice = click.prompt("\nSelect an option", type=int)
            
            if choice == 1:
                if Confirm.ask("Block SMB ports (445, 139) globally?"):
                    result = await engine.block_smb_ports()
                    _print_result(result)
            elif choice == 2:
                if Confirm.ask("Apply emergency subnet isolation rules?"):
                    result = await engine.emergency_microsegmentation()
                    _print_result(result)
            elif choice == 3:
                if Confirm.ask("Reset all iptables rules? This drops all active blocks."):
                    result = await engine.reset_all_rules()
                    _print_result(result)
            elif choice == 4:
                rules = await engine.get_current_rules()
                console.print(f"\n[bold]Current Rules (Simulated: {rules['simulated']}):[/]")
                console.print(rules["iptables_output"])
            elif choice == 5:
                break
                
            if choice != 5:
                click.prompt("\nPress Enter to continue", default="", show_default=False)
                
    asyncio.run(_run())


@firewall_cli.command(name="block-smb")
def block_smb():
    """Block SMB ports immediately."""
    import asyncio
    async def _run():
        engine = get_firewall_engine()
        result = await engine.block_smb_ports()
        _print_result(result)
    asyncio.run(_run())
    

@firewall_cli.command(name="microsegment")
def microsegment():
    """Apply emergency microsegmentation immediately."""
    import asyncio
    async def _run():
        engine = get_firewall_engine()
        result = await engine.emergency_microsegmentation()
        _print_result(result)
    asyncio.run(_run())


@firewall_cli.command(name="reset")
def reset():
    """Reset all firewall rules immediately."""
    import asyncio
    async def _run():
        engine = get_firewall_engine()
        result = await engine.reset_all_rules()
        _print_result(result)
    asyncio.run(_run())


@firewall_cli.command(name="status")
def status():
    """Show current firewall rules."""
    import asyncio
    async def _run():
        engine = get_firewall_engine()
        rules = await engine.get_current_rules()
        console.print(f"\n[bold]Current Rules (Simulated: {rules['simulated']}):[/]")
        console.print(rules["iptables_output"])
    asyncio.run(_run())


def _print_result(result):
    if result.success:
        console.print(f"\n[bold green]✓ Success: {result.action}[/]")
    else:
        console.print(f"\n[bold red]✗ Failed: {result.action}[/]")
        if result.error:
            console.print(f"[red]{result.error}[/]")
            
    if result.simulated:
        console.print("[dim yellow](Action was simulated)[/]")
        
    if result.rules_applied:
        console.print("\nApplied Rules:")
        for r in result.rules_applied:
            console.print(f"  {r}")
