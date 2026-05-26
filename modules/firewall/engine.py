"""
S2: Ransomware Iptables Firewall Manager Engine
Applies/removes iptables rules for SMB blocking and microsegmentation.
Auto-detects platform and falls back to simulation on non-Linux systems.
"""

from __future__ import annotations

import asyncio
import json
import logging
import platform
import subprocess
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from sentinelcommand.core.config import get_settings
from sentinelcommand.core.events import Event, get_event_bus

logger = logging.getLogger(__name__)
_settings = get_settings()


@dataclass
class FirewallAction:
    """Record of a firewall action."""
    action: str
    rules_applied: list[str]
    success: bool
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    error: str | None = None
    simulated: bool = False


# ── SMB ports to block (ransomware propagation vectors) ──────────────

SMB_RULES = [
    {"protocol": "tcp", "port": 445, "description": "SMB/CIFS"},
    {"protocol": "tcp", "port": 139, "description": "NetBIOS Session"},
    {"protocol": "udp", "port": 137, "description": "NetBIOS Name Service"},
    {"protocol": "udp", "port": 138, "description": "NetBIOS Datagram"},
]

# ── Microsegmentation rules (isolate critical subnets) ───────────────

MICROSEG_RULES = [
    {"src": "10.0.1.0/24", "dst": "10.0.2.0/24", "description": "Block Admin→Finance"},
    {"src": "10.0.2.0/24", "dst": "10.0.1.0/24", "description": "Block Finance→Admin"},
    {"src": "10.0.3.0/24", "dst": "10.0.1.0/24", "description": "Block HR→Admin"},
    {"src": "10.0.1.0/24", "dst": "10.0.3.0/24", "description": "Block Admin→HR"},
    {"src": "10.0.4.0/24", "dst": "10.0.0.0/16", "description": "Isolate Guest Network"},
]


class BaseFirewallEngine(ABC):
    """Abstract base for firewall engines."""

    @abstractmethod
    async def block_smb_ports(self) -> FirewallAction:
        """Block SMB-related ports to prevent ransomware lateral movement."""
        ...

    @abstractmethod
    async def emergency_microsegmentation(self) -> FirewallAction:
        """Apply emergency microsegmentation rules."""
        ...

    @abstractmethod
    async def reset_all_rules(self) -> FirewallAction:
        """Flush all iptables rules and restore defaults."""
        ...

    @abstractmethod
    async def get_current_rules(self) -> dict[str, Any]:
        """Get current firewall rules."""
        ...

    @abstractmethod
    async def persist_rules(self) -> FirewallAction:
        """Save rules to survive reboot."""
        ...


class SimulatedFirewallEngine(BaseFirewallEngine):
    """
    Simulated firewall engine for Windows/macOS and demo mode.
    Logs all actions without executing real commands.
    """

    def __init__(self):
        self._active_rules: list[dict] = []
        self._smb_blocked = False
        self._microseg_active = False
        self._log_file = Path(_settings.LOG_DIR) / "ransomware_firewall.log"
        self._log_file.parent.mkdir(parents=True, exist_ok=True)

    def _log(self, message: str):
        """Write to log file."""
        entry = f"[{datetime.now(timezone.utc).isoformat()}] [SIMULATED] {message}\n"
        with open(self._log_file, "a") as f:
            f.write(entry)
        logger.info(f"[SIMULATED] {message}")

    async def block_smb_ports(self) -> FirewallAction:
        rules = []
        for rule in SMB_RULES:
            cmd = f"iptables -A INPUT -p {rule['protocol']} --dport {rule['port']} -j DROP"
            rules.append(cmd)
            self._active_rules.append(rule)
            self._log(f"BLOCKED {rule['description']} (port {rule['port']}/{rule['protocol']})")

        self._smb_blocked = True
        bus = get_event_bus()
        await bus.emit(Event(
            type="firewall.smb_blocked",
            source="firewall",
            data={"ports": [r["port"] for r in SMB_RULES], "simulated": True},
        ))

        return FirewallAction(
            action="block_smb_ports",
            rules_applied=rules,
            success=True,
            simulated=True,
        )

    async def emergency_microsegmentation(self) -> FirewallAction:
        rules = []
        for seg in MICROSEG_RULES:
            cmd = f"iptables -A FORWARD -s {seg['src']} -d {seg['dst']} -j DROP"
            rules.append(cmd)
            self._active_rules.append(seg)
            self._log(f"MICROSEG: {seg['description']} ({seg['src']} → {seg['dst']})")

        self._microseg_active = True
        bus = get_event_bus()
        await bus.emit(Event(
            type="firewall.microsegmentation_active",
            source="firewall",
            data={"segments": len(MICROSEG_RULES), "simulated": True},
        ))

        return FirewallAction(
            action="emergency_microsegmentation",
            rules_applied=rules,
            success=True,
            simulated=True,
        )

    async def reset_all_rules(self) -> FirewallAction:
        rules = [
            "iptables -F",
            "iptables -X",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT",
        ]
        self._active_rules.clear()
        self._smb_blocked = False
        self._microseg_active = False
        self._log("RESET: All iptables rules flushed, policies set to ACCEPT")

        bus = get_event_bus()
        await bus.emit(Event(
            type="firewall.rules_reset",
            source="firewall",
            data={"simulated": True},
        ))

        return FirewallAction(
            action="reset_all_rules",
            rules_applied=rules,
            success=True,
            simulated=True,
        )

    async def get_current_rules(self) -> dict[str, Any]:
        return {
            "smb_blocked": self._smb_blocked,
            "microsegmentation_active": self._microseg_active,
            "active_rules_count": len(self._active_rules),
            "active_rules": self._active_rules,
            "simulated": True,
            "iptables_output": (
                "Chain INPUT (policy ACCEPT)\n"
                "Chain FORWARD (policy ACCEPT)\n"
                "Chain OUTPUT (policy ACCEPT)\n"
                + ("\n".join(
                    f"DROP  {r.get('protocol', 'all')}  --  0.0.0.0/0  0.0.0.0/0  "
                    f"dpt:{r.get('port', 'N/A')}"
                    for r in self._active_rules if 'port' in r
                ) if self._active_rules else "")
            ),
        }

    async def persist_rules(self) -> FirewallAction:
        self._log("PERSIST: Rules saved (simulated — iptables-persistent)")
        return FirewallAction(
            action="persist_rules",
            rules_applied=["netfilter-persistent save"],
            success=True,
            simulated=True,
        )


class LinuxFirewallEngine(BaseFirewallEngine):
    """
    Real iptables firewall engine for Linux systems.
    Requires root/sudo privileges.
    """

    def __init__(self):
        self._log_file = Path("/var/log/ransomware_firewall.log")

    def _log(self, message: str):
        entry = f"[{datetime.now(timezone.utc).isoformat()}] {message}\n"
        try:
            with open(self._log_file, "a") as f:
                f.write(entry)
        except PermissionError:
            logger.warning(f"Cannot write to {self._log_file}, logging to stdout only")
        logger.info(message)

    async def _run_cmd(self, cmd: str) -> tuple[bool, str]:
        """Run a shell command and return (success, output)."""
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await proc.communicate()
            success = proc.returncode == 0
            output = stdout.decode().strip() or stderr.decode().strip()
            return success, output
        except Exception as e:
            return False, str(e)

    async def block_smb_ports(self) -> FirewallAction:
        rules = []
        errors = []
        for rule in SMB_RULES:
            cmd = f"iptables -A INPUT -p {rule['protocol']} --dport {rule['port']} -j DROP"
            success, output = await self._run_cmd(cmd)
            rules.append(cmd)
            if success:
                self._log(f"BLOCKED {rule['description']} (port {rule['port']}/{rule['protocol']})")
            else:
                errors.append(f"{cmd}: {output}")
                self._log(f"ERROR blocking {rule['description']}: {output}")

        bus = get_event_bus()
        await bus.emit(Event(
            type="firewall.smb_blocked",
            source="firewall",
            data={"ports": [r["port"] for r in SMB_RULES], "simulated": False},
        ))

        return FirewallAction(
            action="block_smb_ports",
            rules_applied=rules,
            success=len(errors) == 0,
            error="; ".join(errors) if errors else None,
        )

    async def emergency_microsegmentation(self) -> FirewallAction:
        rules = []
        errors = []
        for seg in MICROSEG_RULES:
            cmd = f"iptables -A FORWARD -s {seg['src']} -d {seg['dst']} -j DROP"
            success, output = await self._run_cmd(cmd)
            rules.append(cmd)
            if success:
                self._log(f"MICROSEG: {seg['description']}")
            else:
                errors.append(f"{cmd}: {output}")

        bus = get_event_bus()
        await bus.emit(Event(
            type="firewall.microsegmentation_active",
            source="firewall",
            data={"segments": len(MICROSEG_RULES), "simulated": False},
        ))

        return FirewallAction(
            action="emergency_microsegmentation",
            rules_applied=rules,
            success=len(errors) == 0,
            error="; ".join(errors) if errors else None,
        )

    async def reset_all_rules(self) -> FirewallAction:
        commands = [
            "iptables -F",
            "iptables -X",
            "iptables -P INPUT ACCEPT",
            "iptables -P FORWARD ACCEPT",
            "iptables -P OUTPUT ACCEPT",
        ]
        errors = []
        for cmd in commands:
            success, output = await self._run_cmd(cmd)
            if not success:
                errors.append(f"{cmd}: {output}")

        self._log("RESET: All iptables rules flushed")

        bus = get_event_bus()
        await bus.emit(Event(
            type="firewall.rules_reset",
            source="firewall",
            data={"simulated": False},
        ))

        return FirewallAction(
            action="reset_all_rules",
            rules_applied=commands,
            success=len(errors) == 0,
            error="; ".join(errors) if errors else None,
        )

    async def get_current_rules(self) -> dict[str, Any]:
        success, output = await self._run_cmd("iptables -L -n -v --line-numbers")
        return {
            "simulated": False,
            "iptables_output": output if success else f"Error: {output}",
        }

    async def persist_rules(self) -> FirewallAction:
        # Try iptables-persistent first, then service iptables save
        success, output = await self._run_cmd("netfilter-persistent save")
        if not success:
            success, output = await self._run_cmd("service iptables save")

        self._log(f"PERSIST: {'Success' if success else 'Failed'} — {output}")
        return FirewallAction(
            action="persist_rules",
            rules_applied=["netfilter-persistent save OR service iptables save"],
            success=success,
            error=output if not success else None,
        )


def get_firewall_engine() -> BaseFirewallEngine:
    """Factory: return appropriate engine based on platform and config."""
    if _settings.SIMULATION_MODE or platform.system() != "Linux":
        return SimulatedFirewallEngine()
    return LinuxFirewallEngine()
