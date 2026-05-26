"""
S3: Backup Hash Verifier CLI.
"""

from __future__ import annotations

import click
from rich.console import Console
from rich.table import Table
import os

from sentinelcommand.modules.backup_verify.engine import BackupVerifier

console = Console()


@click.group(name="backup-verify", help="Verify backup integrity using file hashing.")
def backup_verify_cli():
    pass


@backup_verify_cli.command(name="hash")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--algo", default="sha256", help="Hash algorithm")
def calculate_hash(file_path: str, algo: str):
    """Calculate the hash of a file."""
    try:
        verifier = BackupVerifier(algorithm=algo)
        with console.status(f"[cyan]Calculating {algo} hash for {file_path}..."):
            file_hash = verifier.calculate_hash(file_path)
        console.print(f"[bold green]Hash:[/] {file_hash}")
    except Exception as e:
        console.print(f"[bold red]Error:[/] {e}")


@backup_verify_cli.command(name="check")
@click.argument("file_path", type=click.Path(exists=True))
@click.option("--manifest", required=True, type=click.Path(exists=True), help="Path to JSON manifest")
def check_file(file_path: str, manifest: str):
    """Verify a file against a JSON manifest."""
    verifier = BackupVerifier()
    with console.status("[cyan]Verifying file..."):
        result = verifier.verify_against_manifest(file_path, manifest)
        
    if result.is_valid:
        console.print(f"[bold green]✓ PASS:[/] {file_path}")
    else:
        console.print(f"[bold red]✗ FAIL:[/] {file_path}")
        console.print(f"  Expected: {result.expected_hash}")
        console.print(f"  Actual:   {result.actual_hash}")
        if result.error:
            console.print(f"  Error:    {result.error}")


@backup_verify_cli.command(name="batch")
@click.argument("csv_path", type=click.Path(exists=True))
@click.option("--report/--no-report", default=True, help="Generate HTML report")
def batch_verify(csv_path: str, report: bool):
    """Verify multiple files from a CSV list."""
    import asyncio
    
    async def _run():
        verifier = BackupVerifier()
        with console.status("[cyan]Verifying batch files..."):
            results = verifier.verify_batch(csv_path)
            
        table = Table(title="Batch Verification Results")
        table.add_column("File", style="cyan")
        table.add_column("Status", justify="center")
        
        passed = 0
        for r in results:
            if r.is_valid:
                passed += 1
                table.add_row(os.path.basename(r.file_path), "[green]PASS[/]")
            else:
                table.add_row(os.path.basename(r.file_path), f"[red]FAIL: {r.error or 'Hash mismatch'}[/]")
                
        console.print(table)
        console.print(f"Summary: {passed}/{len(results)} passed.")
        
        if report:
            report_path = await verifier.generate_report(results, format="html")
            console.print(f"Detailed HTML report saved to: [blue]{report_path}[/]")
            
    asyncio.run(_run())


@backup_verify_cli.command(name="generate-manifest")
@click.argument("directory", type=click.Path(exists=True, file_okay=False))
@click.option("--algo", default="sha256", help="Hash algorithm")
@click.option("--output", "-o", help="Output JSON path")
def generate_manifest(directory: str, algo: str, output: str | None):
    """Generate a hash manifest for all files in a directory."""
    verifier = BackupVerifier(algorithm=algo)
    with console.status(f"[cyan]Generating {algo} manifest for {directory}..."):
        manifest_path = verifier.generate_manifest(directory, output)
    console.print(f"[bold green]✓ Manifest generated:[/] {manifest_path}")
