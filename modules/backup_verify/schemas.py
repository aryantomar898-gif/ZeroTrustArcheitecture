"""
S3: Pydantic schemas for Backup Hash Verifier API.
"""

from __future__ import annotations

from datetime import datetime
from pydantic import BaseModel, Field


class HashRequest(BaseModel):
    """Request to calculate a file hash."""
    file_path: str = Field(..., description="Path to the file to hash")
    algorithm: str = Field("sha256", description="Hash algorithm")


class HashResponse(BaseModel):
    """File hash result."""
    file_path: str
    hash: str
    algorithm: str
    file_size_bytes: int


class VerifyRequest(BaseModel):
    """Request to verify a file against a manifest."""
    file_path: str
    manifest_path: str


class BatchVerifyRequest(BaseModel):
    """Request to verify multiple files from CSV."""
    csv_path: str


class GenerateManifestRequest(BaseModel):
    """Request to generate a manifest."""
    directory: str
    output_path: str | None = None


class VerificationResultSchema(BaseModel):
    """Single file verification result."""
    file_path: str
    expected_hash: str
    actual_hash: str
    algorithm: str
    is_valid: bool
    file_size_bytes: int = 0
    error: str | None = None


class VerificationReportResponse(BaseModel):
    """Verification report summary."""
    total: int
    passed: int
    failed: int
    report_path: str
    results: list[VerificationResultSchema]
