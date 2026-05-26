"""
Shared SQLAlchemy ORM models for the entire platform.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentinelcommand.core.database import Base


# ── Enums ────────────────────────────────────────────────────────────

class UserRole(str, enum.Enum):
    ANALYST = "ANALYST"
    MANAGER = "MANAGER"
    CISO = "CISO"
    ADMIN = "ADMIN"


class AlertSeverity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class AlertStatus(str, enum.Enum):
    NEW = "NEW"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    IN_PROGRESS = "IN_PROGRESS"
    RESOLVED = "RESOLVED"
    FALSE_POSITIVE = "FALSE_POSITIVE"


class KillSwitchLevel(int, enum.Enum):
    NORMAL = 0
    SOFT_LOCK = 1
    TOKEN_REVOCATION = 2
    NETWORK_BLOCK = 3
    REPLICATION_PAUSE = 4
    FULL_ISOLATION = 5


class PlaybookStatus(str, enum.Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    AWAITING_APPROVAL = "AWAITING_APPROVAL"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


# ── Helper ───────────────────────────────────────────────────────────

def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


# ── Models ───────────────────────────────────────────────────────────

class User(Base):
    """Platform user with role-based access."""
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[UserRole] = mapped_column(Enum(UserRole), default=UserRole.ANALYST, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_login: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

    audit_logs: Mapped[list["AuditLog"]] = relationship(back_populates="user", lazy="selectin")


class AuditLog(Base):
    """Tamper-evident audit trail entry."""
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )
    user_id: Mapped[int | None] = mapped_column(
        Integer, ForeignKey("users.id"), nullable=True
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    module: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    details: Mapped[str | None] = mapped_column(Text, nullable=True)
    ip_address: Mapped[str | None] = mapped_column(String(45), nullable=True)
    hmac_signature: Mapped[str] = mapped_column(String(64), nullable=False)
    previous_hash: Mapped[str] = mapped_column(String(64), nullable=False, default="0" * 64)

    user: Mapped[User | None] = relationship(back_populates="audit_logs")

    __table_args__ = (Index("ix_audit_module_action", "module", "action"),)


class Alert(Base):
    """Unified alert from any detection module."""
    __tablename__ = "alerts"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False, index=True
    )
    source_module: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    severity: Mapped[AlertSeverity] = mapped_column(
        Enum(AlertSeverity), default=AlertSeverity.MEDIUM, nullable=False
    )
    status: Mapped[AlertStatus] = mapped_column(
        Enum(AlertStatus), default=AlertStatus.NEW, nullable=False
    )
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    target_user: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    raw_data: Mapped[str | None] = mapped_column(Text, nullable=True)
    resolved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    resolved_by: Mapped[str | None] = mapped_column(String(100), nullable=True)

    __table_args__ = (Index("ix_alert_sev_status", "severity", "status"),)


class SystemState(Base):
    """Current platform state — singleton row."""
    __tablename__ = "system_state"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, default=1)
    kill_switch_level: Mapped[int] = mapped_column(Integer, default=0)
    kill_switch_activated_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    kill_switch_activated_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    kill_switch_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    active_simulation_id: Mapped[str | None] = mapped_column(String(100), nullable=True)
    active_playbook_ids: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class ApprovalRequest(Base):
    """Approval workflow for high-impact actions."""
    __tablename__ = "approval_requests"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, nullable=False
    )
    action: Mapped[str] = mapped_column(String(100), nullable=False)
    level: Mapped[int] = mapped_column(Integer, nullable=False)
    requester: Mapped[str] = mapped_column(String(100), nullable=False)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(20), default="PENDING")  # PENDING | APPROVED | DENIED
    approver: Mapped[str | None] = mapped_column(String(100), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class PlaybookExecution(Base):
    """SOAR playbook execution record."""
    __tablename__ = "playbook_executions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    playbook_name: Mapped[str] = mapped_column(String(100), nullable=False)
    status: Mapped[PlaybookStatus] = mapped_column(
        Enum(PlaybookStatus), default=PlaybookStatus.PENDING
    )
    started_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    triggered_by: Mapped[str] = mapped_column(String(100), nullable=False)
    context: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON
    current_step: Mapped[int] = mapped_column(Integer, default=0)
    total_steps: Mapped[int] = mapped_column(Integer, default=0)
    execution_log: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON array


class SessionRevocationLog(Base):
    """Log of session revocation actions (S1)."""
    __tablename__ = "session_revocation_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    target_user_id: Mapped[str] = mapped_column(String(255), nullable=False)
    target_user_email: Mapped[str | None] = mapped_column(String(255), nullable=True)
    target_department: Mapped[str | None] = mapped_column(String(100), nullable=True)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[str | None] = mapped_column(Text, nullable=True)
    initiated_by: Mapped[str] = mapped_column(String(100), nullable=False)


class BackupVerification(Base):
    """Backup integrity verification record (S3)."""
    __tablename__ = "backup_verifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    expected_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    actual_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    algorithm: Mapped[str] = mapped_column(String(20), default="sha256")
    is_valid: Mapped[bool] = mapped_column(Boolean, nullable=False)
    file_size_bytes: Mapped[int | None] = mapped_column(Integer, nullable=True)
    verified_by: Mapped[str] = mapped_column(String(100), nullable=False)


class UBABaseline(Base):
    """User behavior baseline for anomaly detection (S5/S8)."""
    __tablename__ = "uba_baselines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user_identifier: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    avg_login_hour: Mapped[float] = mapped_column(Float, default=9.0)
    std_login_hour: Mapped[float] = mapped_column(Float, default=2.0)
    avg_file_access_count: Mapped[float] = mapped_column(Float, default=20.0)
    std_file_access_count: Mapped[float] = mapped_column(Float, default=10.0)
    common_locations: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    common_ips: Mapped[str | None] = mapped_column(Text, nullable=True)  # JSON list
    baseline_days: Mapped[int] = mapped_column(Integer, default=90)
    last_updated: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
