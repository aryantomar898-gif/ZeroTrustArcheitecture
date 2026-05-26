"""
S4: Pydantic schemas for Kill-Switch API.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class KillSwitchRequest(BaseModel):
    """Request to change kill-switch level."""
    reason: str = Field(..., description="Justification for this action")


class KillSwitchResponse(BaseModel):
    """Response after changing level."""
    status: str
    new_level: int | None = None
    actions_taken: list[str] = []
    message: str | None = None


class SystemStateResponse(BaseModel):
    """Current system state."""
    level: int
    activated_by: str | None
    activated_at: datetime | None
    reason: str | None


class ApprovalRequestResponse(BaseModel):
    """Approval request details."""
    id: int
    action: str
    level: int
    requester: str
    reason: str | None
    status: str
    created_at: datetime
    approver: str | None
    approved_at: datetime | None
