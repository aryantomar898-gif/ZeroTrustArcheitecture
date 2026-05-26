"""
S2: FastAPI routes for Ransomware Firewall Manager.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.audit import log_action
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, UserRole
from sentinelcommand.core.metrics import firewall_actions_total
from sentinelcommand.modules.firewall.engine import get_firewall_engine
from sentinelcommand.modules.firewall.schemas import (
    FirewallActionRequest,
    FirewallActionResponse,
    FirewallRulesResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/firewall", tags=["S2: Firewall Manager"])


@router.post("/block-smb", response_model=FirewallActionResponse)
async def block_smb_ports(
    request: FirewallActionRequest = FirewallActionRequest(),
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Block SMB ports (445, 139, 137, 138) to prevent ransomware lateral movement."""
    engine = get_firewall_engine()
    result = await engine.block_smb_ports()

    if request.persist and result.success:
        await engine.persist_rules()

    firewall_actions_total.labels(action="block_smb").inc()
    await log_action(
        db, action="block_smb_ports", module="firewall",
        details=f"Blocked SMB ports. Persist: {request.persist}. Reason: {request.reason}",
        user_id=current_user.id,
    )

    return FirewallActionResponse(
        action=result.action, rules_applied=result.rules_applied,
        success=result.success, simulated=result.simulated,
        error=result.error, timestamp=result.timestamp,
    )


@router.post("/microsegment", response_model=FirewallActionResponse)
async def emergency_microsegmentation(
    request: FirewallActionRequest = FirewallActionRequest(),
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Apply emergency microsegmentation to isolate network segments."""
    engine = get_firewall_engine()
    result = await engine.emergency_microsegmentation()

    if request.persist and result.success:
        await engine.persist_rules()

    firewall_actions_total.labels(action="microsegmentation").inc()
    await log_action(
        db, action="emergency_microsegmentation", module="firewall",
        details=f"Applied microsegmentation. Reason: {request.reason}",
        user_id=current_user.id,
    )

    return FirewallActionResponse(
        action=result.action, rules_applied=result.rules_applied,
        success=result.success, simulated=result.simulated,
        error=result.error, timestamp=result.timestamp,
    )


@router.post("/reset", response_model=FirewallActionResponse)
async def reset_firewall(
    request: FirewallActionRequest = FirewallActionRequest(),
    current_user: User = Depends(require_role(UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Reset all firewall rules to default (ACCEPT all)."""
    engine = get_firewall_engine()
    result = await engine.reset_all_rules()

    firewall_actions_total.labels(action="reset").inc()
    await log_action(
        db, action="reset_firewall", module="firewall",
        details=f"Reset all rules. Reason: {request.reason}",
        user_id=current_user.id,
    )

    return FirewallActionResponse(
        action=result.action, rules_applied=result.rules_applied,
        success=result.success, simulated=result.simulated,
        error=result.error, timestamp=result.timestamp,
    )


@router.get("/rules")
async def get_current_rules(
    current_user: User = Depends(get_current_user),
):
    """Get current firewall rules."""
    engine = get_firewall_engine()
    return await engine.get_current_rules()
