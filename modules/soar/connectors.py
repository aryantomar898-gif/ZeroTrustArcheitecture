"""
S9: Pluggable Connectors for SOAR Engine.
"""

from __future__ import annotations

import logging
from abc import ABC, abstractmethod
from typing import Any

from sentinelcommand.modules.session_revoke.engine import get_session_engine
from sentinelcommand.modules.firewall.engine import get_firewall_engine
from sentinelcommand.modules.killswitch.engine import KillSwitchEngine

logger = logging.getLogger(__name__)


class ConnectorResult:
    def __init__(self, success: bool, output: Any = None, error: str | None = None):
        self.success = success
        self.output = output
        self.error = error


class BaseConnector(ABC):
    @abstractmethod
    async def execute(self, action: str, params: dict[str, Any], context: dict[str, Any]) -> ConnectorResult:
        ...


class MicrosoftGraphConnector(BaseConnector):
    """Integration with Microsoft Entra ID / Graph API."""
    
    async def execute(self, action: str, params: dict[str, Any], context: dict[str, Any]) -> ConnectorResult:
        engine = get_session_engine()
        
        if action == "revoke_sessions":
            user_id = params.get("user_id")
            if not user_id:
                # Try to resolve from context
                user_id = context.get("target_user")
                
            if not user_id:
                return ConnectorResult(False, error="user_id not provided in params or context")
                
            result = await engine.revoke_user_sessions(user_id)
            return ConnectorResult(result.success, output={"email": result.user_email}, error=result.error)
            
        return ConnectorResult(False, error=f"Unknown action: {action}")


class FirewallConnector(BaseConnector):
    """Integration with local firewall manager."""
    
    async def execute(self, action: str, params: dict[str, Any], context: dict[str, Any]) -> ConnectorResult:
        engine = get_firewall_engine()
        
        if action == "block_smb":
            result = await engine.block_smb_ports()
            return ConnectorResult(result.success, error=result.error)
            
        if action == "microsegment":
            result = await engine.emergency_microsegmentation()
            return ConnectorResult(result.success, error=result.error)
            
        return ConnectorResult(False, error=f"Unknown action: {action}")


class KillSwitchConnector(BaseConnector):
    """Integration with internal Kill-Switch."""
    
    async def execute(self, action: str, params: dict[str, Any], context: dict[str, Any]) -> ConnectorResult:
        # Require passing db in context for this internal connector
        db = context.get("db")
        if not db:
            return ConnectorResult(False, error="Database session not in context")
            
        engine = KillSwitchEngine(db)
        
        if action == "activate_level":
            level = params.get("level")
            reason = params.get("reason", "SOAR automated response")
            if not level:
                return ConnectorResult(False, error="level parameter required")
                
            result = await engine.activate_level(level, "SOAR_SYSTEM", reason)
            return ConnectorResult(result["status"] == "success", output=result)
            
        return ConnectorResult(False, error=f"Unknown action: {action}")


class SimulatedConnector(BaseConnector):
    """Mock connector for testing/simulation."""
    
    async def execute(self, action: str, params: dict[str, Any], context: dict[str, Any]) -> ConnectorResult:
        import asyncio
        await asyncio.sleep(1)  # Simulate network latency
        logger.info(f"[SIMULATED CONNECTOR] Executed {action} with {params}")
        return ConnectorResult(True, output={"simulated": True, "action": action})


# Registry
CONNECTORS: dict[str, BaseConnector] = {
    "msgraph": MicrosoftGraphConnector(),
    "firewall": FirewallConnector(),
    "killswitch": KillSwitchConnector(),
    "simulated": SimulatedConnector(),
}

def get_connector(name: str) -> BaseConnector:
    if name not in CONNECTORS:
        raise ValueError(f"Unknown connector: {name}")
    return CONNECTORS[name]
