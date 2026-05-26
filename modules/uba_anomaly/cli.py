"""
S5: UBA Anomaly Detection CLI.
"""

from __future__ import annotations

import click
import json
from rich.console import Console
from rich.table import Table

from sentinelcommand.core.database import async_session_factory
from sentinelcommand.modules.uba_anomaly.engine import UBAAnomalyEngine

console = Console()


@click.group(name="uba", help="User Behavior Analytics anomaly detection.")
def uba_cli():
    pass


@uba_cli.command(name="ingest")
@click.argument("file_path", type=click.Path(exists=True))
def ingest(file_path: str):
    """Ingest historical logs (CSV/JSON) to build baselines."""
    import asyncio
    async def _run():
        async with async_session_factory() as db:
            engine = UBAAnomalyEngine(db)
            with console.status(f"[cyan]Ingesting {file_path} (building baselines)..."):
                result = await engine.ingest_logs(file_path)
            
            console.print("[bold green]✓ Ingestion Complete[/]")
            console.print(f"Users processed: {result['users']}")
            console.print(f"Events processed: {result['events']}")
    asyncio.run(_run())


@uba_cli.command(name="analyze")
@click.argument("json_event")
def analyze(json_event: str):
    """Analyze a single real-time event (JSON string)."""
    import asyncio
    async def _run():
        try:
            event = json.loads(json_event)
        except json.JSONDecodeError:
            console.print("[bold red]Invalid JSON string[/]")
            return
            
        async with async_session_factory() as db:
            engine = UBAAnomalyEngine(db)
            alerts = await engine.analyze_event(event)
            
            if not alerts:
                console.print("[bold green]✓ No anomalies detected.[/]")
            else:
                console.print(f"[bold red]⚠ Detected {len(alerts)} anomalies![/]")
                for a in alerts:
                    console.print(f"  - [red]{a.title}[/]: {a.description} (Risk: {a.risk_score:.1f})")
    asyncio.run(_run())
