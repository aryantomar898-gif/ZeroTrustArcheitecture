"""
S4: Kill-Switch CLI.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.panel import Panel

from sentinelcommand.core.database import async_session_factory
from sentinelcommand.modules.killswitch.engine import KillSwitchEngine

console = Console()


@click.group(name="killswitch", help="Manage Zero-Trust Kill-Switch.")
def killswitch_cli():
    pass


@killswitch_cli.command(name="status")
def status():
    """Show current kill-switch level."""
    import asyncio
    async def _run():
        async with async_session_factory() as db:
            engine = KillSwitchEngine(db)
            state = await engine.get_state()
            
            level = state.kill_switch_level
            color = "green" if level == 0 else "red" if level >= 4 else "yellow"
            
            console.print(Panel(
                f"Current Level: [bold {color}]{level}[/]\n"
                f"Activated By: {state.kill_switch_activated_by or 'N/A'}\n"
                f"Reason: {state.kill_switch_reason or 'N/A'}",
                title="Kill-Switch Status",
                expand=False
            ))
    asyncio.run(_run())


@killswitch_cli.command(name="activate")
@click.option("--level", "-l", type=click.IntRange(1, 5), required=True, help="Level to activate (1-5)")
@click.option("--reason", "-r", required=True, help="Reason for activation")
def activate(level: int, reason: str):
    """Activate a kill-switch level."""
    import asyncio
    async def _run():
        async with async_session_factory() as db:
            engine = KillSwitchEngine(db)
            console.print(f"[bold yellow]Activating Level {level}...[/]")
            result = await engine.activate_level(level, "CLI_ADMIN", reason)
            
            if result["status"] == "success":
                console.print(f"[bold red]✓ Kill-Switch Level {level} ACTIVATED[/]")
                for action in result.get("actions_taken", []):
                    console.print(f"  - {action}")
            else:
                console.print(f"[yellow]{result.get('message')}[/]")
    asyncio.run(_run())


@killswitch_cli.command(name="reset")
def reset():
    """Reset kill-switch to Level 0."""
    import asyncio
    async def _run():
        async with async_session_factory() as db:
            engine = KillSwitchEngine(db)
            result = await engine.reset("CLI_ADMIN")
            console.print(f"[bold green]✓ {result.get('message')}[/]")
    asyncio.run(_run())
