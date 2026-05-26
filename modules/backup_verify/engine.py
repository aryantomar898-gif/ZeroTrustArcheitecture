"""
S3: Backup Hash Verifier Engine
Verifies backup integrity using SHA-256 hashes against stored manifests.
Supports single file, batch (CSV), and manifest generation.
"""

from __future__ import annotations

import csv
import hashlib
import json
import logging
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.events import Event, get_event_bus

logger = logging.getLogger(__name__)
_settings = get_settings()


@dataclass
class VerificationResult:
    """Result of a single file hash verification."""
    file_path: str
    expected_hash: str
    actual_hash: str
    algorithm: str
    is_valid: bool
    file_size_bytes: int = 0
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None


class BackupVerifier:
    """
    Backup integrity verification engine.
    Calculates SHA-256 (or other) hashes and compares against manifests.
    """

    SUPPORTED_ALGORITHMS = {"sha256", "sha512", "sha1", "md5"}
    CHUNK_SIZE = 8192  # Read files in 8KB chunks for memory efficiency

    def __init__(self, algorithm: str = "sha256"):
        if algorithm not in self.SUPPORTED_ALGORITHMS:
            raise ValueError(f"Unsupported algorithm: {algorithm}. Use: {self.SUPPORTED_ALGORITHMS}")
        self.algorithm = algorithm

    def calculate_hash(self, file_path: str) -> str:
        """
        Calculate the hash of a file using streaming (constant memory).
        Works with files of any size.
        """
        hasher = hashlib.new(self.algorithm)
        path = Path(file_path)

        if not path.exists():
            raise FileNotFoundError(f"File not found: {file_path}")

        with open(path, "rb") as f:
            while True:
                chunk = f.read(self.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)

        return hasher.hexdigest()

    def verify_against_manifest(
        self, file_path: str, manifest_path: str
    ) -> VerificationResult:
        """
        Verify a file's hash against a stored manifest.

        Manifest format (JSON):
        {
            "files": {
                "backup_2024.tar.gz": {
                    "hash": "abc123...",
                    "algorithm": "sha256",
                    "size": 1048576
                }
            }
        }
        """
        with open(manifest_path, "r") as f:
            manifest = json.load(f)

        filename = Path(file_path).name
        files = manifest.get("files", {})

        if filename not in files:
            return VerificationResult(
                file_path=file_path,
                expected_hash="NOT_IN_MANIFEST",
                actual_hash="",
                algorithm=self.algorithm,
                is_valid=False,
                error=f"File '{filename}' not found in manifest",
            )

        entry = files[filename]
        expected_hash = entry.get("hash", "")
        algo = entry.get("algorithm", self.algorithm)

        # Use the manifest's algorithm
        verifier = BackupVerifier(algorithm=algo)

        try:
            actual_hash = verifier.calculate_hash(file_path)
            file_size = os.path.getsize(file_path)
        except FileNotFoundError as e:
            return VerificationResult(
                file_path=file_path,
                expected_hash=expected_hash,
                actual_hash="FILE_NOT_FOUND",
                algorithm=algo,
                is_valid=False,
                error=str(e),
            )

        is_valid = actual_hash == expected_hash
        return VerificationResult(
            file_path=file_path,
            expected_hash=expected_hash,
            actual_hash=actual_hash,
            algorithm=algo,
            is_valid=is_valid,
            file_size_bytes=file_size,
        )

    def verify_batch(self, csv_path: str) -> list[VerificationResult]:
        """
        Verify multiple backups from a CSV file.

        CSV format:
        file_path,expected_hash,algorithm
        /backups/db.tar.gz,abc123...,sha256
        """
        results = []
        with open(csv_path, "r") as f:
            reader = csv.DictReader(f)
            for row in reader:
                file_path = row.get("file_path", "")
                expected_hash = row.get("expected_hash", "")
                algo = row.get("algorithm", self.algorithm)

                verifier = BackupVerifier(algorithm=algo)
                try:
                    actual_hash = verifier.calculate_hash(file_path)
                    file_size = os.path.getsize(file_path)
                    is_valid = actual_hash == expected_hash
                    results.append(VerificationResult(
                        file_path=file_path,
                        expected_hash=expected_hash,
                        actual_hash=actual_hash,
                        algorithm=algo,
                        is_valid=is_valid,
                        file_size_bytes=file_size,
                    ))
                except Exception as e:
                    results.append(VerificationResult(
                        file_path=file_path,
                        expected_hash=expected_hash,
                        actual_hash="ERROR",
                        algorithm=algo,
                        is_valid=False,
                        error=str(e),
                    ))

        return results

    def generate_manifest(self, directory: str, output_path: str | None = None) -> str:
        """
        Generate a hash manifest for all files in a directory.
        Returns the path to the generated manifest.
        """
        dir_path = Path(directory)
        if not dir_path.is_dir():
            raise NotADirectoryError(f"Not a directory: {directory}")

        manifest = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "algorithm": self.algorithm,
            "directory": str(dir_path.resolve()),
            "files": {},
        }

        for file_path in sorted(dir_path.rglob("*")):
            if file_path.is_file():
                rel_path = file_path.relative_to(dir_path)
                file_hash = self.calculate_hash(str(file_path))
                manifest["files"][str(rel_path)] = {
                    "hash": file_hash,
                    "algorithm": self.algorithm,
                    "size": os.path.getsize(file_path),
                    "modified": datetime.fromtimestamp(
                        file_path.stat().st_mtime, tz=timezone.utc
                    ).isoformat(),
                }

        if output_path is None:
            output_path = str(
                Path(_settings.DATA_DIR) / f"manifest_{datetime.now(timezone.utc).strftime('%Y%m%d_%H%M%S')}.json"
            )

        Path(output_path).parent.mkdir(parents=True, exist_ok=True)
        with open(output_path, "w") as f:
            json.dump(manifest, f, indent=2)

        return output_path

    async def generate_report(
        self, results: list[VerificationResult], format: str = "json"
    ) -> str:
        """
        Generate a verification report in JSON or HTML format.
        Returns the path to the generated report.
        """
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_dir = Path(_settings.DATA_DIR) / "reports"
        report_dir.mkdir(parents=True, exist_ok=True)

        total = len(results)
        passed = sum(1 for r in results if r.is_valid)
        failed = total - passed

        if format == "html":
            report_path = str(report_dir / f"verification_report_{timestamp}.html")
            html = self._generate_html_report(results, total, passed, failed)
            with open(report_path, "w") as f:
                f.write(html)
        else:
            report_path = str(report_dir / f"verification_report_{timestamp}.json")
            report_data = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "summary": {"total": total, "passed": passed, "failed": failed},
                "results": [
                    {
                        "file_path": r.file_path,
                        "expected_hash": r.expected_hash,
                        "actual_hash": r.actual_hash,
                        "algorithm": r.algorithm,
                        "is_valid": r.is_valid,
                        "file_size_bytes": r.file_size_bytes,
                        "error": r.error,
                    }
                    for r in results
                ],
            }
            with open(report_path, "w") as f:
                json.dump(report_data, f, indent=2)

        # Emit event
        bus = get_event_bus()
        await bus.emit(Event(
            type="backup.verification_complete",
            source="backup_verify",
            data={"total": total, "passed": passed, "failed": failed},
        ))

        return report_path

    def _generate_html_report(
        self, results: list[VerificationResult], total: int, passed: int, failed: int
    ) -> str:
        """Generate a styled HTML verification report."""
        rows = ""
        for r in results:
            status_class = "pass" if r.is_valid else "fail"
            status_text = "✓ PASS" if r.is_valid else "✗ FAIL"
            error_text = f'<br><small class="error">{r.error}</small>' if r.error else ""
            rows += f"""
            <tr class="{status_class}">
                <td>{Path(r.file_path).name}</td>
                <td><code>{r.expected_hash[:16]}...</code></td>
                <td><code>{r.actual_hash[:16]}...</code></td>
                <td>{r.algorithm}</td>
                <td>{r.file_size_bytes:,} B</td>
                <td class="status">{status_text}{error_text}</td>
            </tr>"""

        pass_pct = (passed / total * 100) if total > 0 else 0

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Backup Verification Report — SentinelCommand</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{
        font-family: 'Segoe UI', system-ui, sans-serif;
        background: #0f1923; color: #e0e6ed;
        padding: 2rem;
    }}
    .header {{
        background: linear-gradient(135deg, #1a2332, #2d3748);
        border: 1px solid #2d3748;
        border-radius: 12px; padding: 2rem; margin-bottom: 2rem;
    }}
    .header h1 {{ color: #60a5fa; font-size: 1.8rem; }}
    .header p {{ color: #94a3b8; margin-top: 0.5rem; }}
    .summary {{
        display: grid; grid-template-columns: repeat(3, 1fr);
        gap: 1rem; margin-bottom: 2rem;
    }}
    .card {{
        background: #1a2332; border: 1px solid #2d3748;
        border-radius: 8px; padding: 1.5rem; text-align: center;
    }}
    .card .value {{ font-size: 2.5rem; font-weight: 700; }}
    .card .label {{ color: #94a3b8; margin-top: 0.25rem; }}
    .card.pass .value {{ color: #34d399; }}
    .card.fail .value {{ color: #f87171; }}
    .card.total .value {{ color: #60a5fa; }}
    table {{
        width: 100%; border-collapse: collapse;
        background: #1a2332; border-radius: 8px; overflow: hidden;
    }}
    th {{ background: #2d3748; padding: 1rem; text-align: left; color: #94a3b8; font-weight: 600; }}
    td {{ padding: 0.75rem 1rem; border-bottom: 1px solid #2d3748; }}
    tr.pass .status {{ color: #34d399; font-weight: 600; }}
    tr.fail .status {{ color: #f87171; font-weight: 600; }}
    tr.fail {{ background: rgba(248, 113, 113, 0.05); }}
    code {{ background: #2d3748; padding: 0.2rem 0.4rem; border-radius: 4px; font-size: 0.85rem; }}
    .error {{ color: #f87171; }}
    .footer {{ text-align: center; margin-top: 2rem; color: #64748b; font-size: 0.9rem; }}
</style>
</head>
<body>
    <div class="header">
        <h1>🛡 Backup Verification Report</h1>
        <p>Generated: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')} | SentinelCommand v{_settings.APP_VERSION}</p>
    </div>
    <div class="summary">
        <div class="card total"><div class="value">{total}</div><div class="label">Total Files</div></div>
        <div class="card pass"><div class="value">{passed}</div><div class="label">Passed</div></div>
        <div class="card fail"><div class="value">{failed}</div><div class="label">Failed</div></div>
    </div>
    <table>
        <thead><tr><th>File</th><th>Expected</th><th>Actual</th><th>Algorithm</th><th>Size</th><th>Status</th></tr></thead>
        <tbody>{rows}</tbody>
    </table>
    <div class="footer">SentinelCommand — Integrity is non-negotiable. Pass rate: {pass_pct:.1f}%</div>
</body>
</html>"""
