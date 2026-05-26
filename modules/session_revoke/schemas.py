"""
S1: Pydantic schemas for Session Revocation API.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class RevocationRequest(BaseModel):
    """Request to revoke sessions."""
    department: str | None = Field(None, description="Target department (null = all)")
    user_id: str | None = Field(None, description="Specific user ID to revoke")
    reason: str = Field("Manual revocation", description="Reason for revocation")


class RevocationResultSchema(BaseModel):
    """Single revocation result."""
    user_id: str
    user_email: str
    department: str
    success: bool
    error: str | None = None
    timestamp: datetime


class BulkRevocationResponse(BaseModel):
    """Bulk revocation response."""
    total: int
    success_count: int
    failure_count: int
    results: list[RevocationResultSchema]
    log_file: str | None = None


class UserListResponse(BaseModel):
    """User listing response."""
    total: int
    users: list[dict]


class RevocationLogEntry(BaseModel):
    """Audit log entry for a revocation."""
    id: int
    timestamp: datetime
    target_user_id: str
    target_user_email: str | None
    target_department: str | None
    success: bool
    error_message: str | None
    initiated_by: str
