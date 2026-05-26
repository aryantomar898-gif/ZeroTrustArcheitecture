"""
S5: FastAPI routes for UBA Anomaly Detection.
"""

from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, UserRole, UBABaseline, Alert
from sentinelcommand.modules.uba_anomaly.engine import UBAAnomalyEngine
from sentinelcommand.modules.uba_anomaly.schemas import (
    IngestRequest,
    IngestResponse,
    AnalyzeRequest,
    BaselineResponse,
    AlertResponse,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/uba", tags=["S5: UBA Anomaly"])


@router.post("/ingest", response_model=IngestResponse)
async def ingest_logs(
    request: IngestRequest,
    current_user: User = Depends(require_role(UserRole.MANAGER, UserRole.CISO, UserRole.ADMIN)),
    db: AsyncSession = Depends(get_db),
):
    """Ingest historical logs (CSV/JSON) to train baselines."""
    engine = UBAAnomalyEngine(db)
    try:
        result = await engine.ingest_logs(request.file_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail="Log file not found")
        
    return IngestResponse(
        users_processed=result["users"],
        events_processed=result["events"]
    )


@router.post("/analyze", response_model=list[AlertResponse])
async def analyze_event(
    request: AnalyzeRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Analyze a single real-time event and return any generated alerts."""
    engine = UBAAnomalyEngine(db)
    alerts = await engine.analyze_event(request.event)
    
    return [
        AlertResponse(
            id=a.id,
            timestamp=a.timestamp,
            title=a.title,
            description=a.description,
            risk_score=a.risk_score,
            severity=a.severity.value,
            target_user=a.target_user,
        )
        for a in alerts
    ]


@router.get("/baselines/{user_id}", response_model=BaselineResponse)
async def get_baseline(
    user_id: str = Path(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Get the calculated baseline statistics for a user."""
    result = await db.execute(select(UBABaseline).where(UBABaseline.user_identifier == user_id))
    baseline = result.scalar_one_or_none()
    
    if not baseline:
        raise HTTPException(status_code=404, detail="Baseline not found for user")
        
    return BaselineResponse(
        user_identifier=baseline.user_identifier,
        avg_login_hour=baseline.avg_login_hour,
        std_login_hour=baseline.std_login_hour,
        avg_file_access_count=baseline.avg_file_access_count,
        std_file_access_count=baseline.std_file_access_count,
        event_count=baseline.event_count,
        last_updated=baseline.last_updated,
    )


@router.get("/alerts", response_model=list[AlertResponse])
async def list_alerts(
    limit: int = 50,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List recent UBA alerts."""
    result = await db.execute(
        select(Alert)
        .where(Alert.source_module == "uba_anomaly")
        .order_by(Alert.timestamp.desc())
        .limit(limit)
    )
    alerts = result.scalars().all()
    
    return [
        AlertResponse(
            id=a.id,
            timestamp=a.timestamp,
            title=a.title,
            description=a.description,
            risk_score=a.risk_score,
            severity=a.severity.value,
            target_user=a.target_user,
        )
        for a in alerts
    ]
