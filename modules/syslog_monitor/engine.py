"""
S10: System Log Monitor Engine.
Uses PowerShell to collect real-time Windows Event logs and provides analysis.
"""

from __future__ import annotations

import asyncio
import json
import logging
import subprocess
from datetime import datetime, timezone
from typing import Any

from sqlalchemy.ext.asyncio import AsyncSession

logger = logging.getLogger(__name__)


class SyslogEngine:
    """Collects and analyzes system logs."""

    def __init__(self, db: AsyncSession | None = None):
        self.db = db

    async def fetch_windows_logs(self, log_name: str = "System", max_events: int = 50) -> list[dict[str, Any]]:
        """
        Executes a PowerShell command to fetch recent event logs.
        Using Get-WinEvent which is faster and modern compared to Get-EventLog.
        """
        ps_script = (
            f"Get-WinEvent -LogName {log_name} -MaxEvents {max_events} "
            "| Select-Object TimeCreated, Id, LevelDisplayName, ProviderName, Message "
            "| ConvertTo-Json -Compress"
        )
        
        try:
            # Run PowerShell asynchronously
            process = await asyncio.create_subprocess_exec(
                "powershell.exe", "-NoProfile", "-Command", ps_script,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            
            if process.returncode != 0:
                logger.error(f"PowerShell error: {stderr.decode(errors='ignore')}")
                return []
                
            output = stdout.decode('utf-8', errors='ignore').strip()
            if not output:
                return []
                
            logs = json.loads(output)
            # If only 1 event, PS ConvertTo-Json returns a dict instead of a list
            if isinstance(logs, dict):
                logs = [logs]
                
            return logs
        except Exception as e:
            logger.error(f"Failed to fetch Windows logs: {e}")
            return []

    def analyze_logs(self, logs: list[dict[str, Any]]) -> dict[str, Any]:
        """
        Categorizes logs and determines necessary remediation steps.
        """
        summary = {
            "critical": 0,
            "error": 0,
            "warning": 0,
            "information": 0
        }
        
        actions = []
        analyzed_events = []
        
        seen_action_ids = set()
        
        for entry in logs:
            level = str(entry.get("LevelDisplayName", "Information")).lower()
            event_id = entry.get("Id")
            provider = entry.get("ProviderName", "")
            message = entry.get("Message", "")
            
            # Map PS severity string to our counter
            if level in ["critical"]:
                summary["critical"] += 1
            elif level in ["error"]:
                summary["error"] += 1
            elif level in ["warning"]:
                summary["warning"] += 1
            else:
                summary["information"] += 1
                
            # Rule-based analysis
            action = None
            
            if event_id == 7036 and "stopped" in message.lower():
                action = {
                    "id": f"svc_stop_{provider}",
                    "severity": "MEDIUM",
                    "title": "Service Stopped Unexpectedly",
                    "description": f"The '{provider}' service stopped. This could be normal, but if it's a critical security service, it needs investigation.",
                    "steps": [
                        "Verify if the service was stopped manually.",
                        "Check dependencies for failure.",
                        "Restart the service if required."
                    ]
                }
                
            elif event_id in [4625, 4624]:  # Logon failures/successes (Security log)
                if event_id == 4625:
                    action = {
                        "id": "brute_force_suspect",
                        "severity": "HIGH",
                        "title": "Authentication Failure Detected",
                        "description": "A user failed to log on. Multiple failures could indicate a brute force attack.",
                        "steps": [
                            "Check UBA anomalies for this user.",
                            "If part of a spike, isolate the source IP using Firewall Manager.",
                            "Force password reset via Session Revocation CLI."
                        ]
                    }
            elif level in ["error", "critical"] and "disk" in provider.lower():
                action = {
                    "id": f"disk_err_{provider}",
                    "severity": "CRITICAL",
                    "title": "Disk/Storage Subsystem Error",
                    "description": "Hardware or filesystem corruption detected.",
                    "steps": [
                        "Immediately run the S3 Backup Verifier to ensure backup integrity.",
                        "Schedule chkdsk or hardware replacement.",
                        "Prevent write operations if degradation worsens."
                    ]
                }
                
            if action and action["id"] not in seen_action_ids:
                seen_action_ids.add(action["id"])
                actions.append(action)
                
            # Add normalized entry
            # Extract timestamp: "/Date(1716738908852)/" -> actual datetime
            time_str = entry.get("TimeCreated", "")
            if isinstance(time_str, str) and time_str.startswith("/Date("):
                import re
                m = re.search(r'\d+', time_str)
                if m:
                    ts_ms = int(m.group(0))
                    dt = datetime.fromtimestamp(ts_ms / 1000.0, timezone.utc)
                    time_str = dt.isoformat()
            
            analyzed_events.append({
                "timestamp": time_str,
                "event_id": event_id,
                "severity": level.upper(),
                "provider": provider,
                "message": message[:150] + "..." if len(message) > 150 else message
            })
            
        return {
            "summary": summary,
            "actions": sorted(actions, key=lambda x: {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}.get(x["severity"], 99)),
            "logs": analyzed_events
        }

    async def get_system_health_report(self) -> dict[str, Any]:
        """Fetches System and Application logs, merges, and analyzes them."""
        system_logs = await self.fetch_windows_logs("System", max_events=40)
        app_logs = await self.fetch_windows_logs("Application", max_events=40)
        
        # Security logs often require Admin privileges and can be noisy, so we'll optionally include
        # security_logs = await self.fetch_windows_logs("Security", max_events=20)
        
        combined_logs = system_logs + app_logs
        
        # Sort by TimeCreated (most recent first) before analysis
        # (Handling the PS Date format if necessary)
        def get_time(log):
            ts = log.get("TimeCreated", "")
            if isinstance(ts, str) and "Date" in ts:
                import re
                m = re.search(r'\d+', ts)
                if m: return int(m.group(0))
            return 0
            
        combined_logs.sort(key=get_time, reverse=True)
        
        return self.analyze_logs(combined_logs)
