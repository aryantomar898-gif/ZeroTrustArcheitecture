"""
S1: FastAPI routes for Session Revocation.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.audit import log_action
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, UserRole, SessionRevocationLog
from sentinelcommand.core.metrics import sessions_revoked_total
from sentinelcommand.modules.session_revoke.engine import get_session_engine, save_revocation_log
from sentinelcommand.modules.session_revoke.schemas import (
    BulkRevocationResponse,
    RevocationRequest,
    RevocationResultSchema,
    UserListResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/sessions", tags=["S1: Session Revocation"])


@router.post("/revoke", response_model=BulkRevocationResponse)
async def revoke_sessions(
    request: RevocationRequest,
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Revoke user sessions — targets a specific user or entire department."""
    engine = get_session_engine()

    if request.user_id:
        # Single user revocation
        result = await engine.revoke_user_sessions(request.user_id)
        results = [result]
    else:
        # Bulk revocation
        results = await engine.revoke_all_sessions(department=request.department)

    # Log to database
    for r in results:
        log_entry = SessionRevocationLog(
            target_user_id=r.user_id,
            target_user_email=r.user_email,
            target_department=r.department,
            success=r.success,
            error_message=r.error,
            initiated_by=current_user.username,
        )
        db.add(log_entry)
        if r.success:
            sessions_revoked_total.labels(department=r.department or "all").inc()

    # Audit trail
    await log_action(
        db,
        action="session_revocation",
        module="session_revoke",
        details=f"Revoked {sum(1 for r in results if r.success)} sessions. "
                f"Department: {request.department or 'all'}. Reason: {request.reason}",
        user_id=current_user.id,
    )

    # Save JSON log
    log_file = save_revocation_log(results)

    return BulkRevocationResponse(
        total=len(results),
        success_count=sum(1 for r in results if r.success),
        failure_count=sum(1 for r in results if not r.success),
        results=[
            RevocationResultSchema(
                user_id=r.user_id,
                user_email=r.user_email,
                department=r.department,
                success=r.success,
                error=r.error,
                timestamp=r.timestamp,
            )
            for r in results
        ],
        log_file=log_file,
    )


@router.get("/users", response_model=UserListResponse)
async def list_entra_users(
    department: str | None = None,
    current_user: User = Depends(get_current_user),
):
    """List users from the identity provider."""
    engine = get_session_engine()
    users = await engine.list_users(department=department)

    return UserListResponse(
        total=len(users),
        users=[
            {
                "id": u.id,
                "display_name": u.display_name,
                "email": u.email,
                "department": u.department,
                "job_title": u.job_title,
                "account_enabled": u.account_enabled,
            }
            for u in users
        ],
    )


@router.get("/logs")
async def get_revocation_logs(
    limit: int = 100,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get session revocation audit logs."""
    from sqlalchemy import select
    result = await db.execute(
        select(SessionRevocationLog)
        .order_by(SessionRevocationLog.timestamp.desc())
        .limit(limit)
    )
    logs = result.scalars().all()
    return {
        "total": len(logs),
        "logs": [
            {
                "id": l.id,
                "timestamp": l.timestamp.isoformat() if l.timestamp else None,
                "target_user_id": l.target_user_id,
                "target_user_email": l.target_user_email,
                "target_department": l.target_department,
                "success": l.success,
                "error_message": l.error_message,
                "initiated_by": l.initiated_by,
            }
            for l in logs
        ],
    }
