"""
S10: FastAPI routes for System Log Monitor.
"""

from __future__ import annotations

import logging

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User
from sentinelcommand.modules.syslog_monitor.engine import SyslogEngine
from sentinelcommand.modules.syslog_monitor.schemas import SystemHealthReport

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/syslog", tags=["S10: Syslog Monitor"])


@router.get("/analyze", response_model=SystemHealthReport)
async def analyze_system_logs(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """
    Fetches real-time Windows Event logs, categorizes them, 
    and generates actionable remediation steps.
    """
    engine = SyslogEngine(db)
    report = await engine.get_system_health_report()
    return report
