from datetime import datetime, timezone
from typing import List, Optional, Callable
from decimal import Decimal

from sqlalchemy import (
    Column, Integer, String, Text, DateTime, ForeignKey, Index,
    Numeric, Boolean, JSON, Enum as SAEnum
)
from sqlalchemy.orm import relationship, Mapped, mapped_column
import enum

from database import Base


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


class SeverityEnum(str, enum.Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class VulnStatusEnum(str, enum.Enum):
    ACTIVE = "active"
    MITIGATED = "mitigated"
    FIXED = "fixed"
    CLOSED = "closed"


class FixStatusEnum(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    FIXED = "fixed"
    VERIFIED = "verified"
    FAILED = "failed"
    ACCEPTED_RISK = "accepted_risk"


class WorkOrderStatusEnum(str, enum.Enum):
    PENDING = "pending"
    FIXING = "fixing"
    FIXED = "fixed"
    VERIFYING = "verifying"
    CLOSED = "closed"


class NotificationTypeEnum(str, enum.Enum):
    EMAIL = "email"
    DINGTALK = "dingtalk"
    WECHAT = "wechat"
    FEISHU = "feishu"


class NotificationStatusEnum(str, enum.Enum):
    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"


class IncidentTypeEnum(str, enum.Enum):
    DATA_BREACH = "data_breach"
    MALWARE = "malware"
    UNAUTHORIZED_ACCESS = "unauthorized_access"
    DOS_ATTACK = "dos_attack"
    PHISHING = "phishing"
    INSIDER_THREAT = "insider_threat"
    OTHER = "other"


class IncidentStatusEnum(str, enum.Enum):
    OPEN = "open"
    INVESTIGATING = "investigating"
    CONTAINED = "contained"
    ERADICATED = "eradicated"
    RECOVERED = "recovered"
    CLOSED = "closed"


class IncidentEventTypeEnum(str, enum.Enum):
    DETECTED = "detected"
    TRIAGED = "triaged"
    ESCALATED = "escalated"
    MITIGATED = "mitigated"
    RESOLVED = "resolved"
    COMMENT = "comment"


class ReportTypeEnum(str, enum.Enum):
    DAILY = "daily"
    WEEKLY = "weekly"
    MONTHLY = "monthly"
    QUARTERLY = "quarterly"


class MeasureStatus(str, enum.Enum):
    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class PlanStatus(str, enum.Enum):
    CREATED = "created"
    CONFIRMED = "confirmed"
    EXECUTING = "executing"
    COMPLETED = "completed"
    CLOSED = "closed"


class VulnType(str, enum.Enum):
    RCE = "rce"
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    DATA_BREACH = "data_breach"
    DOS = "dos"
    PRIVILEGE_ESCALATION = "privilege_escalation"
    INFO_DISCLOSURE = "info_disclosure"
    CSRF = "csrf"
    SSRF = "ssrf"
    RANSOMWARE = "ransomware"
    OTHER = "other"


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    name: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    importance: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    owner: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    department: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    vuln_instances: Mapped[List["VulnerabilityInstance"]] = relationship(
        "VulnerabilityInstance", back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_assets_ip_type", "ip", "type"),
        Index("idx_assets_department_importance", "department", "importance"),
    )


class Vulnerability(Base):
    __tablename__ = "vulnerabilities"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    cve_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True, index=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    severity: Mapped[SeverityEnum] = mapped_column(SAEnum(SeverityEnum), nullable=False, index=True)
    cvss_score: Mapped[Optional[Decimal]] = mapped_column(Numeric(4, 1), nullable=True, index=True)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    reference: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    source: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    status: Mapped[VulnStatusEnum] = mapped_column(SAEnum(VulnStatusEnum), default=VulnStatusEnum.ACTIVE, nullable=False, index=True)
    extra_data: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    vuln_instances: Mapped[List["VulnerabilityInstance"]] = relationship(
        "VulnerabilityInstance", back_populates="vulnerability", cascade="all, delete-orphan"
    )
    response_plans: Mapped[List["ResponsePlan"]] = relationship(
        "ResponsePlan", back_populates="vulnerability"
    )

    __table_args__ = (
        Index("idx_vulns_severity_status", "severity", "status"),
        Index("idx_vulns_cvss_score", "cvss_score"),
        Index("idx_vulns_source_last_seen", "source", "last_seen"),
    )


class VulnerabilityInstance(Base):
    __tablename__ = "vulnerability_instances"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerabilities.id", ondelete="CASCADE"), nullable=False, index=True)
    asset_id: Mapped[int] = mapped_column(Integer, ForeignKey("assets.id", ondelete="CASCADE"), nullable=False, index=True)
    risk_score: Mapped[Decimal] = mapped_column(Numeric(5, 2), nullable=False, index=True)
    discovery_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    fix_deadline: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    fix_status: Mapped[FixStatusEnum] = mapped_column(SAEnum(FixStatusEnum), default=FixStatusEnum.PENDING, nullable=False, index=True)
    verify_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    verify_fail_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    is_high_priority: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False, index=True)
    high_risk_reasons: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    port: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    protocol: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    location: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    vulnerability: Mapped["Vulnerability"] = relationship("Vulnerability", back_populates="vuln_instances")
    asset: Mapped["Asset"] = relationship("Asset", back_populates="vuln_instances")
    work_orders: Mapped[List["WorkOrder"]] = relationship(
        "WorkOrder", back_populates="vuln_instance", cascade="all, delete-orphan"
    )
    response_plans: Mapped[List["ResponsePlan"]] = relationship(
        "ResponsePlan", back_populates="vuln_instance", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_vuln_instances_vuln_asset", "vuln_id", "asset_id", unique=True),
        Index("idx_vuln_instances_risk_status", "risk_score", "fix_status"),
        Index("idx_vuln_instances_deadline", "fix_deadline"),
    )


class WorkOrder(Base):
    __tablename__ = "work_orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_instance_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerability_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    assignee: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    status: Mapped[WorkOrderStatusEnum] = mapped_column(SAEnum(WorkOrderStatusEnum), default=WorkOrderStatusEnum.PENDING, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    started_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    fixed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    verified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    current_stage_start: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    deadline: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    priority: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    remarks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    vuln_instance: Mapped["VulnerabilityInstance"] = relationship("VulnerabilityInstance", back_populates="work_orders")
    notifications: Mapped[List["Notification"]] = relationship(
        "Notification", back_populates="work_order", cascade="all, delete-orphan"
    )
    escalation_records: Mapped[List["EscalationRecord"]] = relationship(
        "EscalationRecord", back_populates="work_order", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_work_orders_assignee_status", "assignee", "status"),
        Index("idx_work_orders_status_deadline", "status", "deadline"),
        Index("idx_work_orders_escalation_level", "escalation_level"),
    )


class Notification(Base):
    __tablename__ = "notifications"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[NotificationTypeEnum] = mapped_column(SAEnum(NotificationTypeEnum), nullable=False, index=True)
    recipient: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    content: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[NotificationStatusEnum] = mapped_column(SAEnum(NotificationStatusEnum), default=NotificationStatusEnum.PENDING, nullable=False, index=True)
    sent_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True, index=True)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, nullable=False, index=True)
    work_order_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("work_orders.id", ondelete="SET NULL"), nullable=True, index=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    retry_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    work_order: Mapped[Optional["WorkOrder"]] = relationship("WorkOrder", back_populates="notifications")

    __table_args__ = (
        Index("idx_notifications_type_status", "type", "status"),
        Index("idx_notifications_sent_at", "sent_at"),
    )


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    title: Mapped[str] = mapped_column(String(500), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    type: Mapped[IncidentTypeEnum] = mapped_column(SAEnum(IncidentTypeEnum), nullable=False, index=True)
    severity: Mapped[SeverityEnum] = mapped_column(SAEnum(SeverityEnum), nullable=False, index=True)
    status: Mapped[IncidentStatusEnum] = mapped_column(SAEnum(IncidentStatusEnum), default=IncidentStatusEnum.OPEN, nullable=False, index=True)
    assets_affected: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    assigned_to: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)
    resolved_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)

    timelines: Mapped[List["IncidentTimeline"]] = relationship(
        "IncidentTimeline", back_populates="incident", cascade="all, delete-orphan"
    )

    __table_args__ = (
        Index("idx_incidents_type_severity", "type", "severity"),
        Index("idx_incidents_status_created", "status", "created_at"),
    )


class IncidentTimeline(Base):
    __tablename__ = "incident_timelines"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    incident_id: Mapped[int] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="CASCADE"), nullable=False, index=True)
    event_type: Mapped[IncidentEventTypeEnum] = mapped_column(SAEnum(IncidentEventTypeEnum), nullable=False, index=True)
    description: Mapped[str] = mapped_column(Text, nullable=False)
    operator: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

    incident: Mapped["Incident"] = relationship("Incident", back_populates="timelines")

    __table_args__ = (
        Index("idx_timeline_incident_event", "incident_id", "event_type"),
    )


class Report(Base):
    __tablename__ = "reports"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    type: Mapped[ReportTypeEnum] = mapped_column(SAEnum(ReportTypeEnum), nullable=False, index=True)
    period_start: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    period_end: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    generated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    generated_by: Mapped[str] = mapped_column(String(100), nullable=False)
    file_path_pdf: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    file_path_excel: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    summary_stats: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    __table_args__ = (
        Index("idx_reports_type_period", "type", "period_start", "period_end"),
    )


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    user: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_type: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    ip: Mapped[str] = mapped_column(String(45), nullable=False, index=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(500), nullable=True)
    request_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

    __table_args__ = (
        Index("idx_audit_user_action", "user", "action"),
        Index("idx_audit_resource", "resource_type", "resource_id"),
        Index("idx_audit_created_at", "created_at"),
    )


class EscalationRecord(Base):
    __tablename__ = "escalation_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    work_order_id: Mapped[int] = mapped_column(Integer, ForeignKey("work_orders.id", ondelete="CASCADE"), nullable=False, index=True)
    old_level: Mapped[int] = mapped_column(Integer, nullable=False)
    new_level: Mapped[int] = mapped_column(Integer, nullable=False, index=True)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    escalated_by: Mapped[str] = mapped_column(String(100), nullable=False)
    notified_recipients: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)

    work_order: Mapped["WorkOrder"] = relationship("WorkOrder", back_populates="escalation_records")

    __table_args__ = (
        Index("idx_escalation_work_order", "work_order_id", "new_level"),
    )


class ResponsePlan(Base):
    __tablename__ = "response_plans"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_instance_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerability_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    vuln_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("vulnerabilities.id", ondelete="SET NULL"), nullable=True, index=True)
    incident_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("incidents.id", ondelete="SET NULL"), nullable=True, index=True)
    status: Mapped[PlanStatus] = mapped_column(SAEnum(PlanStatus), default=PlanStatus.CREATED, nullable=False, index=True)
    vuln_type: Mapped[VulnType] = mapped_column(SAEnum(VulnType), nullable=False, index=True)
    trigger_reason: Mapped[str] = mapped_column(Text, nullable=False)
    trigger_condition: Mapped[str] = mapped_column(String(200), nullable=False)
    affected_assets: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    isolation_measures: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitigation_measures: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_fix_plan: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    contacts: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    knowledge_references: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    isolation_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    mitigation_status: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    confirmed_by: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    sla_confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_mitigation_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    sla_isolation_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    notified_teams: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    legal_notified: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    legal_notify_reason: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    legal_notified_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    executed_by: Mapped[str] = mapped_column(String(100), nullable=False)
    execution_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)
    effectiveness: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    remarks: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    closed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    vuln_instance: Mapped["VulnerabilityInstance"] = relationship("VulnerabilityInstance", back_populates="response_plans")
    vulnerability: Mapped[Optional["Vulnerability"]] = relationship("Vulnerability", back_populates="response_plans")
    incident: Mapped[Optional["Incident"]] = relationship("Incident")

    __table_args__ = (
        Index("idx_response_plan_vuln_instance", "vuln_instance_id"),
        Index("idx_response_plan_status", "status"),
        Index("idx_response_plan_vuln_type", "vuln_type"),
        Index("idx_response_plan_created_at", "created_at"),
    )


class ReviewTaskStatusEnum(str, enum.Enum):
    PENDING_ANALYSIS = "pending_analysis"
    IN_ANALYSIS = "in_analysis"
    COMPLETED = "completed"
    CONFIRMED = "confirmed"


class ReviewTaskReasonEnum(str, enum.Enum):
    VERIFY_FAILED_TWICE = "verify_failed_twice"
    HIGH_RISK_OVERDUE = "high_risk_overdue"
    WIDESPREAD_VULN = "widespread_vuln"


class ReviewTask(Base):
    __tablename__ = "review_tasks"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_instance_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerability_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    work_order_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("work_orders.id", ondelete="SET NULL"), nullable=True, index=True)
    reason: Mapped[ReviewTaskReasonEnum] = mapped_column(SAEnum(ReviewTaskReasonEnum), nullable=False, index=True)
    reason_detail: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    status: Mapped[ReviewTaskStatusEnum] = mapped_column(SAEnum(ReviewTaskStatusEnum), default=ReviewTaskStatusEnum.PENDING_ANALYSIS, nullable=False, index=True)
    assignees: Mapped[str] = mapped_column(String(500), nullable=False)
    root_cause: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    root_cause_category: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    improvement_measures: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    analysis_result: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    deadline: Mapped[datetime] = mapped_column(DateTime, nullable=False, index=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    confirmed_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_by: Mapped[str] = mapped_column(String(100), nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    vuln_instance: Mapped["VulnerabilityInstance"] = relationship("VulnerabilityInstance")
    work_order: Mapped[Optional["WorkOrder"]] = relationship("WorkOrder")

    __table_args__ = (
        Index("idx_review_tasks_status_deadline", "status", "deadline"),
        Index("idx_review_tasks_reason", "reason"),
    )


class VerificationRecord(Base):
    __tablename__ = "verification_records"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    vuln_instance_id: Mapped[int] = mapped_column(Integer, ForeignKey("vulnerability_instances.id", ondelete="CASCADE"), nullable=False, index=True)
    work_order_id: Mapped[Optional[int]] = mapped_column(Integer, ForeignKey("work_orders.id", ondelete="SET NULL"), nullable=True, index=True)
    scan_type: Mapped[str] = mapped_column(String(50), nullable=False, index=True)
    scan_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True, index=True)
    is_fixed: Mapped[bool] = mapped_column(Boolean, nullable=False, index=True)
    details: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    evidence: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    operator: Mapped[str] = mapped_column(String(100), nullable=False)
    verification_time: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False, index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, nullable=False)

    vuln_instance: Mapped["VulnerabilityInstance"] = relationship("VulnerabilityInstance")
    work_order: Mapped[Optional["WorkOrder"]] = relationship("WorkOrder")

    __table_args__ = (
        Index("idx_verification_records_vuln_time", "vuln_instance_id", "verification_time"),
    )
