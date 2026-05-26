"""
S8: Pydantic schemas for Production UBA.
"""

from __future__ import annotations

from typing import Any
from pydantic import BaseModel, Field


class StreamEventRequest(BaseModel):
    """Direct injection of an event into the stream (for testing/HTTP ingest)."""
    event: dict[str, Any] = Field(..., description="JSON event payload")


class RuleSchema(BaseModel):
    """Rule definition metadata."""
    name: str
    description: str
    severity: str
