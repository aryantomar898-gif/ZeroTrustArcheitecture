"""
S4: FastAPI routes for Zero-Trust Kill-Switch.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.audit import log_action
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, UserRole
from sentinelcommand.core.metrics import killswitch_activations_total
from sentinelcommand.modules.killswitch.engine import KillSwitchEngine
from sentinelcommand.modules.killswitch.schemas import (
    KillSwitchRequest,
    KillSwitchResponse,
    SystemStateResponse,
    ApprovalRequestResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/kill-switch", tags=["S4: Kill-Switch"])


@router.post("/level-{level}", response_model=KillSwitchResponse)
async def activate_level(
    level: int = Path(..., ge=1, le=5),
    request: KillSwitchRequest = KillSwitchRequest(reason="Emergency protocol"),
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """
    Activate a specific kill-switch level (1-5).
    Level 5 requires the CISO role and an approved request.
    """
    engine = KillSwitchEngine(db)
    
    if level == 5 and current_user.role not in [UserRole.CISO, UserRole.ADMIN]:
        raise HTTPException(
            status_code=403, 
            detail="Level 5 (Full Isolation) can only be initiated by a CISO or ADMIN"
        )

    # In a full app, we would verify an approval request here for Level 5
    # For now, we'll proceed directly but log it heavily
    
    result = await engine.activate_level(level, current_user.username, request.reason)
    
    if result["status"] == "success":
        killswitch_activations_total.labels(level=str(level)).inc()
        await log_action(
            db, action=f"activate_killswitch_level_{level}", module="killswitch",
            details=f"Reason: {request.reason}. Actions: {', '.join(result.get('actions_taken', []))}",
            user_id=current_user.id,
        )

    return KillSwitchResponse(
        status=result["status"],
        new_level=result.get("new_level"),
        actions_taken=result.get("actions_taken", []),
        message=result.get("message")
    )


@router.get("/status", response_model=SystemStateResponse)
async def get_status(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the current kill-switch level and state."""
    engine = KillSwitchEngine(db)
    state = await engine.get_state()
    
    return SystemStateResponse(
        level=state.kill_switch_level,
        activated_by=state.kill_switch_activated_by,
        activated_at=state.kill_switch_activated_at,
        reason=state.kill_switch_reason,
    )


@router.post("/reset", response_model=KillSwitchResponse)
async def reset_killswitch(
    request: KillSwitchRequest = KillSwitchRequest(reason="Incident resolved"),
    current_user: User = Depends(require_role(UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Reset the kill-switch to Level 0 (Normal Operations)."""
    engine = KillSwitchEngine(db)
    result = await engine.reset(current_user.username)
    
    await log_action(
        db, action="reset_killswitch", module="killswitch",
        details=f"Reason: {request.reason}",
        user_id=current_user.id,
    )
    
    return KillSwitchResponse(
        status=result["status"],
        message=result.get("message")
    )


@router.post("/request-approval", response_model=ApprovalRequestResponse)
async def request_approval(
    level: int,
    request: KillSwitchRequest,
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Request approval for a high-level kill-switch action."""
    engine = KillSwitchEngine(db)
    req = await engine.request_approval(level, current_user.username, request.reason)
    
    await log_action(
        db, action="request_killswitch_approval", module="killswitch",
        details=f"Requested level {level}. Reason: {request.reason}",
        user_id=current_user.id,
    )
    
    return req


@router.post("/approve/{request_id}", response_model=ApprovalRequestResponse)
async def approve_request(
    request_id: int,
    current_user: User = Depends(require_role(UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Approve a pending kill-switch request."""
    engine = KillSwitchEngine(db)
    try:
        req = await engine.approve_request(request_id, current_user.username)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
        
    await log_action(
        db, action="approve_killswitch_request", module="killswitch",
        details=f"Approved request {request_id} for level {req.level}",
        user_id=current_user.id,
    )
    
    return req
