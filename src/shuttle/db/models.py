"""SQLAlchemy 2.0 ORM models for Shuttle."""

import uuid
from datetime import UTC, datetime

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship


class Base(DeclarativeBase):
    pass


class Node(Base):
    """SSH node / host connection configuration."""

    __tablename__ = "nodes"

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    host: Mapped[str] = mapped_column(String(255), nullable=False)
    port: Mapped[int] = mapped_column(Integer, nullable=False, default=22)
    username: Mapped[str] = mapped_column(String(255), nullable=False)
    auth_type: Mapped[str] = mapped_column(String(50), nullable=False)
    encrypted_credential: Mapped[str] = mapped_column(Text, nullable=False)
    jump_host_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("nodes.id"), nullable=True
    )
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    pool_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    latency_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    last_seen_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )

    # Self-referential relationship for jump host
    jump_host: Mapped["Node | None"] = relationship(
        "Node", remote_side="Node.id", foreign_keys=[jump_host_id]
    )

    # Relationships
    security_rules: Mapped[list["SecurityRule"]] = relationship(
        "SecurityRule", back_populates="node", cascade="all, delete-orphan"
    )
    sessions: Mapped[list["Session"]] = relationship(
        "Session", back_populates="node", cascade="all, delete-orphan"
    )
    command_logs: Mapped[list["CommandLog"]] = relationship(
        "CommandLog", back_populates="node", cascade="all, delete-orphan"
    )


class SecurityRule(Base):
    """Pattern-based security rule for command filtering."""

    __tablename__ = "security_rules"
    __table_args__ = (Index("ix_security_rules_node", "node_id"),)

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    pattern: Mapped[str] = mapped_column(Text, nullable=False)
    level: Mapped[str] = mapped_column(String(50), nullable=False)
    node_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("nodes.id"), nullable=True
    )
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    priority: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    enabled: Mapped[bool] = mapped_column(Boolean, nullable=False, default=True)
    source_rule_id: Mapped[str | None] = mapped_column(
        String(36), nullable=True, default=None
    )
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    # Relationships
    node: Mapped["Node | None"] = relationship("Node", back_populates="security_rules")


class Session(Base):
    """Active SSH session tracking."""

    __tablename__ = "sessions"
    __table_args__ = (Index("ix_sessions_node_status", "node_id", "status"),)

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    node_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("nodes.id"), nullable=False
    )
    working_directory: Mapped[str | None] = mapped_column(String(1024), nullable=True)
    env_vars: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    status: Mapped[str] = mapped_column(String(50), nullable=False, default="active")
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )
    closed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    # Relationships
    node: Mapped["Node"] = relationship("Node", back_populates="sessions")
    command_logs: Mapped[list["CommandLog"]] = relationship(
        "CommandLog", back_populates="session"
    )


class CommandLog(Base):
    """Log of executed commands."""

    __tablename__ = "command_logs"
    __table_args__ = (
        Index("ix_command_logs_node_executed", "node_id", "executed_at"),
        Index("ix_command_logs_session", "session_id"),
    )

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    # session_id is NULLABLE — supports stateless execution without a session
    session_id: Mapped[str | None] = mapped_column(
        String(36), ForeignKey("sessions.id"), nullable=True
    )
    node_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("nodes.id"), nullable=False
    )
    command: Mapped[str] = mapped_column(Text, nullable=False)
    exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    stdout: Mapped[str | None] = mapped_column(Text, nullable=True)
    stderr: Mapped[str | None] = mapped_column(Text, nullable=True)
    security_level: Mapped[str | None] = mapped_column(String(50), nullable=True)
    security_rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Plain string, no FK — links the log row to its approval decision.
    approval_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    bypassed: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, nullable=True)
    executed_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
    )

    # Relationships
    session: Mapped["Session | None"] = relationship(
        "Session", back_populates="command_logs"
    )
    node: Mapped["Node"] = relationship("Node", back_populates="command_logs")


class PendingApproval(Base):
    """Durable approval request for CONFIRM-level commands.

    Replaces the in-memory ConfirmTokenStore: the decision is made by a human
    in the web panel and stored here, so it survives restarts and works across
    multiple server processes.

    State machine: pending → approved → executed, pending → rejected,
    pending → expired. ``expires_at`` gates both deciding and claiming.
    """

    __tablename__ = "pending_approvals"
    __table_args__ = (Index("ix_pending_approvals_status", "status", "expires_at"),)

    id: Mapped[str] = mapped_column(
        String(36), primary_key=True, default=lambda: str(uuid.uuid4())
    )
    node_id: Mapped[str] = mapped_column(
        String(36), ForeignKey("nodes.id"), nullable=False
    )
    # Informational only — the originating session may close before the decision.
    session_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    # Exact command string; the approval authorizes exactly (command, node_id).
    command: Mapped[str] = mapped_column(Text, nullable=False)
    # Plain string, no FK — rules may be deleted later (matches CommandLog.security_rule_id).
    rule_id: Mapped[str | None] = mapped_column(String(36), nullable=True)
    rule_description: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Records that the requesting call passed bypass_scope="session".
    bypass_scope: Mapped[str | None] = mapped_column(String(20), nullable=True)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="pending")
    requested_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=lambda: datetime.now(UTC)
    )
    expires_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False
    )
    decided_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    # Reserved for future panel identity; always NULL today.
    decided_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reject_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    executed_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )
    exec_exit_code: Mapped[int | None] = mapped_column(Integer, nullable=True)

    node: Mapped["Node"] = relationship("Node")


class AppConfig(Base):
    """Application key-value configuration store."""

    __tablename__ = "app_config"

    key: Mapped[str] = mapped_column(String(255), primary_key=True)
    value: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True),
        nullable=False,
        default=lambda: datetime.now(UTC),
        onupdate=lambda: datetime.now(UTC),
    )
