"""
S2: Pydantic schemas for Firewall Manager API.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any


class FirewallActionResponse(BaseModel):
    """Response from a firewall action."""
    action: str
    rules_applied: list[str]
    success: bool
    simulated: bool = False
    error: str | None = None
    timestamp: datetime


class FirewallRulesResponse(BaseModel):
    """Current firewall rules."""
    simulated: bool
    smb_blocked: bool | None = None
    microsegmentation_active: bool | None = None
    active_rules_count: int | None = None
    iptables_output: str = ""


class FirewallActionRequest(BaseModel):
    """Request body for firewall actions."""
    persist: bool = Field(False, description="Save rules to survive reboot")
    reason: str = Field("Manual action", description="Reason for the action")
