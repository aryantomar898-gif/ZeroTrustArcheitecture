"""
S3: FastAPI routes for Backup Hash Verifier.
"""

from __future__ import annotations

import logging
import os

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from sentinelcommand.core.auth import get_current_user
from sentinelcommand.core.audit import log_action
from sentinelcommand.core.database import get_db
from sentinelcommand.core.models import User, BackupVerification
from sentinelcommand.core.metrics import backup_verifications_total
from sentinelcommand.modules.backup_verify.engine import BackupVerifier
from sentinelcommand.modules.backup_verify.schemas import (
    BatchVerifyRequest,
    GenerateManifestRequest,
    HashRequest,
    HashResponse,
    VerificationReportResponse,
    VerificationResultSchema,
    VerifyRequest,
)

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/v1/backup", tags=["S3: Backup Verifier"])


@router.post("/hash", response_model=HashResponse)
async def calculate_hash(
    request: HashRequest,
    current_user: User = Depends(get_current_user),
):
    """Calculate the hash of a backup file."""
    verifier = BackupVerifier(algorithm=request.algorithm)
    try:
        file_hash = verifier.calculate_hash(request.file_path)
        file_size = os.path.getsize(request.file_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"File not found: {request.file_path}")

    return HashResponse(
        file_path=request.file_path,
        hash=file_hash,
        algorithm=request.algorithm,
        file_size_bytes=file_size,
    )


@router.post("/verify", response_model=VerificationResultSchema)
async def verify_backup(
    request: VerifyRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify a backup file against a stored manifest."""
    verifier = BackupVerifier()
    try:
        result = verifier.verify_against_manifest(request.file_path, request.manifest_path)
    except FileNotFoundError as e:
        raise HTTPException(status_code=404, detail=str(e))

    # Record in database
    record = BackupVerification(
        file_path=result.file_path,
        expected_hash=result.expected_hash,
        actual_hash=result.actual_hash,
        algorithm=result.algorithm,
        is_valid=result.is_valid,
        file_size_bytes=result.file_size_bytes,
        verified_by=current_user.username,
    )
    db.add(record)

    backup_verifications_total.labels(result="pass" if result.is_valid else "fail").inc()
    await log_action(
        db, action="verify_backup", module="backup_verify",
        details=f"Verified {result.file_path}: {'PASS' if result.is_valid else 'FAIL'}",
        user_id=current_user.id,
    )

    return VerificationResultSchema(
        file_path=result.file_path,
        expected_hash=result.expected_hash,
        actual_hash=result.actual_hash,
        algorithm=result.algorithm,
        is_valid=result.is_valid,
        file_size_bytes=result.file_size_bytes,
        error=result.error,
    )


@router.post("/batch-verify", response_model=VerificationReportResponse)
async def batch_verify(
    request: BatchVerifyRequest,
    report_format: str = "json",
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Verify multiple backup files from a CSV list."""
    verifier = BackupVerifier()
    try:
        results = verifier.verify_batch(request.csv_path)
    except FileNotFoundError:
        raise HTTPException(status_code=404, detail=f"CSV not found: {request.csv_path}")

    report_path = await verifier.generate_report(results, format=report_format)

    passed = sum(1 for r in results if r.is_valid)
    failed = len(results) - passed

    await log_action(
        db, action="batch_verify_backup", module="backup_verify",
        details=f"Batch verified {len(results)} files: {passed} passed, {failed} failed",
        user_id=current_user.id,
    )

    return VerificationReportResponse(
        total=len(results),
        passed=passed,
        failed=failed,
        report_path=report_path,
        results=[
            VerificationResultSchema(
                file_path=r.file_path,
                expected_hash=r.expected_hash,
                actual_hash=r.actual_hash,
                algorithm=r.algorithm,
                is_valid=r.is_valid,
                file_size_bytes=r.file_size_bytes,
                error=r.error,
            )
            for r in results
        ],
    )


@router.post("/generate-manifest")
async def generate_manifest(
    request: GenerateManifestRequest,
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """Generate a hash manifest for all files in a directory."""
    verifier = BackupVerifier()
    try:
        manifest_path = verifier.generate_manifest(request.directory, request.output_path)
    except NotADirectoryError as e:
        raise HTTPException(status_code=400, detail=str(e))

    await log_action(
        db, action="generate_manifest", module="backup_verify",
        details=f"Generated manifest for {request.directory} → {manifest_path}",
        user_id=current_user.id,
    )

    return {"manifest_path": manifest_path}


@router.get("/reports")
async def list_reports(
    current_user: User = Depends(get_current_user),
    db: AsyncSession = Depends(get_db),
):
    """List recent backup verification records."""
    from sqlalchemy import select
    result = await db.execute(
        select(BackupVerification)
        .order_by(BackupVerification.timestamp.desc())
        .limit(100)
    )
    records = result.scalars().all()
    return {
        "total": len(records),
        "verifications": [
            {
                "id": r.id,
                "timestamp": r.timestamp.isoformat() if r.timestamp else None,
                "file_path": r.file_path,
                "is_valid": r.is_valid,
                "algorithm": r.algorithm,
                "verified_by": r.verified_by,
            }
            for r in records
        ],
    }
