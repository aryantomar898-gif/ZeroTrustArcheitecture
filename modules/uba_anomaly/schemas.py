"""
S5: Pydantic schemas for UBA Anomaly Detection API.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field
from typing import Any


class IngestRequest(BaseModel):
    """Request to ingest training logs."""
    file_path: str = Field(..., description="Path to CSV or JSON log file")


class IngestResponse(BaseModel):
    """Response after ingestion."""
    users_processed: int
    events_processed: int


class AnalyzeRequest(BaseModel):
    """Request to analyze a single real-time event."""
    event: dict[str, Any] = Field(..., description="JSON event data (must contain user_id)")


class BaselineResponse(BaseModel):
    """User baseline data."""
    user_identifier: str
    avg_login_hour: float
    std_login_hour: float
    avg_file_access_count: float
    std_file_access_count: float
    event_count: int
    last_updated: datetime


class AlertResponse(BaseModel):
    """Alert response schema."""
    id: int
    timestamp: datetime
    title: str
    description: str | None
    risk_score: float
    severity: str
    target_user: str | None
