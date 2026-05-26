"""
S9: FastAPI routes for SOAR Orchestrator.
"""

from __future__ import annotations

import logging
import json

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, UserRole, PlaybookExecution
from sentinelcommand.modules.soar.engine import SOAREngine
from sentinelcommand.modules.soar.schemas import (
    ExecutePlaybookRequest,
    PlaybookSchema,
    ExecutionResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/soar", tags=["S9: SOAR"])


@router.get("/playbooks", response_model=list[PlaybookSchema])
async def list_playbooks(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List available playbooks."""
    engine = SOAREngine(db)
    return engine.list_playbooks()


@router.post("/playbooks/{playbook_id}/execute")
async def execute_playbook(
    playbook_id: str = Path(...),
    request: ExecutePlaybookRequest = ExecutePlaybookRequest(),
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Trigger a playbook execution."""
    engine = SOAREngine(db)
    try:
        execution = await engine.execute_playbook(playbook_id, request.context, current_user.username)
        return {"status": "started", "execution_id": execution.id}
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Playbook not found")


@router.get("/executions/{execution_id}", response_model=ExecutionResponse)
async def get_execution(
    execution_id: int = Path(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get status of a specific execution."""
    execution = await db.get(PlaybookExecution, execution_id)
    if not execution:
        raise HTTPException(status_code=404, detail="Execution not found")
        
    try:
        log_data = json.loads(execution.execution_log) if execution.execution_log else []
    except json.JSONDecodeError:
        log_data = []
        
    return ExecutionResponse(
        id=execution.id,
        playbook_name=execution.playbook_name,
        status=execution.status.value,
        started_at=execution.started_at,
        completed_at=execution.completed_at,
        current_step=execution.current_step,
        total_steps=execution.total_steps,
        execution_log=log_data,
    )


@router.get("/executions")
async def list_executions(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List recent executions."""
    result = await db.execute(
        select(PlaybookExecution).order_by(PlaybookExecution.started_at.desc()).limit(limit)
    )
    return [
        {
            "id": e.id,
            "playbook_name": e.playbook_name,
            "status": e.status.value,
            "started_at": e.started_at,
            "completed_at": e.completed_at,
        }
        for e in result.scalars().all()
    ]
