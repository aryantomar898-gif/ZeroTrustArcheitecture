"""
S8: FastAPI routes for Production UBA Service.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends, Path
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user, require_role
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, UserRole, Alert, UBABaseline
from sentinelcommand.modules.uba_production.engine import ProductionUBAEngine
from sentinelcommand.modules.uba_production.schemas import StreamEventRequest, RuleSchema

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/uba-prod", tags=["S8: Production UBA"])


@router.post("/events")
async def ingest_event(
    request: StreamEventRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Inject a single event directly into the production UBA engine (HTTP fallback to Kafka)."""
    engine = ProductionUBAEngine(db)
    # Note: custom rules not loaded for brevity in this single-shot endpoint, 
    # but would be in a real deployment
    alerts = await engine.process_event(request.event)
    
    return {
        "status": "processed",
        "alerts_generated": len(alerts)
    }


@router.get("/rules", response_model=list[RuleSchema])
async def list_active_rules(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List all active UBA detection rules."""
    engine = ProductionUBAEngine(db)
    return [
        RuleSchema(
            name=r.name,
            description=r.description,
            severity=r.severity.value,
        )
        for r in engine.rules
    ]


@router.get("/risk-score/{user_id}")
async def get_user_risk_score(
    user_id: str = Path(...),
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Calculate the current aggregate risk score for a user."""
    # Simplified logic: aggregate active alerts
    result = await db.execute(
        select(Alert).where(
            Alert.target_user == user_id,
            Alert.status != "RESOLVED"
        )
    )
    alerts = result.scalars().all()
    
    total_risk = min(100.0, sum(a.risk_score for a in alerts))
    
    return {
        "user_id": user_id,
        "active_alerts": len(alerts),
        "aggregate_risk_score": total_risk
    }
