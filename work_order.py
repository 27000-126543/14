from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from collections import defaultdict
import smtplib
import json
import time
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from email.utils import formataddr

import requests
from sqlalchemy import and_, or_, func
from sqlalchemy.orm import Session

from config import config
from models import (
    WorkOrder, WorkOrderStatusEnum, VulnerabilityInstance, Vulnerability,
    Asset, Notification, NotificationTypeEnum, NotificationStatusEnum,
    EscalationRecord, AuditLog, SeverityEnum
)
from database import db_manager, with_session, with_read_session
from logger import logger, audit_logger, log_audit, with_log_context


WORK_ORDER_STATUS_FLOW = {
    WorkOrderStatusEnum.PENDING: [WorkOrderStatusEnum.FIXING, WorkOrderStatusEnum.CLOSED],
    WorkOrderStatusEnum.FIXING: [WorkOrderStatusEnum.FIXED, WorkOrderStatusEnum.CLOSED],
    WorkOrderStatusEnum.FIXED: [WorkOrderStatusEnum.VERIFYING, WorkOrderStatusEnum.CLOSED],
    WorkOrderStatusEnum.VERIFYING: [WorkOrderStatusEnum.CLOSED, WorkOrderStatusEnum.FIXING],
    WorkOrderStatusEnum.CLOSED: []
}


ESCALATION_STAGES = [
    {"level": 1, "hours_range": (0, 24), "notify_roles": ["assignee", "department_security"]},
    {"level": 2, "hours_range": (24, 48), "notify_roles": ["assignee", "department_security", "security_supervisor"]},
    {"level": 3, "hours_range": (48, 72), "notify_roles": ["assignee", "department_security", "security_supervisor", "department_director"]},
    {"level": 4, "hours_range": (72, float('inf')), "notify_roles": ["assignee", "department_security", "security_supervisor", "department_director", "ciso_cio"]}
]


VULN_TYPE_TO_GROUP = {
    "web": "web_security_team",
    "xss": "web_security_team",
    "sql_injection": "web_security_team",
    "csrf": "web_security_team",
    "ssrf": "web_security_team",
    "rce": "infrastructure_team",
    "buffer_overflow": "infrastructure_team",
    "privilege_escalation": "infrastructure_team",
    "default": "general_security_team"
}


DEPARTMENT_TO_TEAM = {
    "研发部": "dev_security_team",
    "运维部": "ops_security_team",
    "测试部": "qa_security_team",
    "产品部": "product_security_team",
    "default": "general_security_team"
}


TEAM_MEMBERS = {
    "web_security_team": ["user1", "user2", "user3"],
    "infrastructure_team": ["user4", "user5", "user6"],
    "dev_security_team": ["user7", "user8"],
    "ops_security_team": ["user9", "user10"],
    "qa_security_team": ["user11", "user12"],
    "product_security_team": ["user13", "user14"],
    "general_security_team": ["user15", "user16"]
}


USER_SKILL_TAGS = {
    "user1": ["web", "xss", "sql_injection"],
    "user2": ["web", "csrf", "ssrf"],
    "user3": ["web", "rce"],
    "user4": ["infrastructure", "rce", "buffer_overflow"],
    "user5": ["infrastructure", "privilege_escalation"],
    "user6": ["infrastructure", "network"],
    "user7": ["dev", "code_review"],
    "user8": ["dev", "secure_coding"],
    "user9": ["ops", "cloud"],
    "user10": ["ops", "container"],
    "default": ["general"]
}


class AssignmentRecord:
    def __init__(self, work_order_id: int, assignee: str, assigned_by: str, 
                 assignment_strategy: str, reason: str = ""):
        self.work_order_id = work_order_id
        self.assignee = assignee
        self.assigned_by = assigned_by
        self.assignment_strategy = assignment_strategy
        self.reason = reason
        self.assigned_at = datetime.now(timezone.utc)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "work_order_id": self.work_order_id,
            "assignee": self.assignee,
            "assigned_by": self.assigned_by,
            "assignment_strategy": self.assignment_strategy,
            "reason": self.reason,
            "assigned_at": self.assigned_at.isoformat()
        }


class AutoAssigner:
    def __init__(self):
        self._round_robin_counters = defaultdict(int)
        self._assignment_history: List[AssignmentRecord] = []

    def _get_current_load(self, session: Session) -> Dict[str, int]:
        result = session.query(
            WorkOrder.assignee,
            func.count(WorkOrder.id).label('count')
        ).filter(
            WorkOrder.status.in_([
                WorkOrderStatusEnum.PENDING,
                WorkOrderStatusEnum.FIXING,
                WorkOrderStatusEnum.FIXED,
                WorkOrderStatusEnum.VERIFYING
            ])
        ).group_by(WorkOrder.assignee).all()
        return {row.assignee: row.count for row in result}

    def _get_candidates_by_asset_owner(self, vuln_instance: VulnerabilityInstance) -> Optional[List[str]]:
        if vuln_instance.asset and vuln_instance.asset.owner:
            return [vuln_instance.asset.owner]
        return None

    def _get_candidates_by_department(self, vuln_instance: VulnerabilityInstance) -> Optional[List[str]]:
        if vuln_instance.asset and vuln_instance.asset.department:
            dept = vuln_instance.asset.department
            team = DEPARTMENT_TO_TEAM.get(dept, DEPARTMENT_TO_TEAM["default"])
            return TEAM_MEMBERS.get(team, TEAM_MEMBERS["default"])
        return None

    def _get_candidates_by_vuln_type(self, vulnerability: Vulnerability) -> List[str]:
        vuln_type = self._extract_vuln_type(vulnerability)
        group = VULN_TYPE_TO_GROUP.get(vuln_type, VULN_TYPE_TO_GROUP["default"])
        return TEAM_MEMBERS.get(group, TEAM_MEMBERS["default"])

    def _extract_vuln_type(self, vulnerability: Vulnerability) -> str:
        title = vulnerability.title.lower() if vulnerability.title else ""
        description = vulnerability.description.lower() if vulnerability.description else ""
        combined = title + " " + description

        for vuln_type in VULN_TYPE_TO_GROUP.keys():
            if vuln_type in combined:
                return vuln_type
        return "default"

    def _filter_by_skill_tags(self, candidates: List[str], vulnerability: Vulnerability) -> List[str]:
        vuln_type = self._extract_vuln_type(vulnerability)
        matched = []
        for candidate in candidates:
            skills = USER_SKILL_TAGS.get(candidate, USER_SKILL_TAGS["default"])
            if vuln_type in skills:
                matched.append(candidate)
        return matched if matched else candidates

    def _balance_load(self, candidates: List[str], current_load: Dict[str, int]) -> List[str]:
        loads = [(c, current_load.get(c, 0)) for c in candidates]
        min_load = min(loads, key=lambda x: x[1])[1] if loads else 0
        return [c for c, load in loads if load == min_load]

    def _round_robin_select(self, candidates: List[str], group_key: str) -> str:
        if not candidates:
            raise ValueError("No candidates available for assignment")
        idx = self._round_robin_counters[group_key] % len(candidates)
        selected = candidates[idx]
        self._round_robin_counters[group_key] += 1
        return selected

    @with_session
    def assign(self, work_order: WorkOrder, vuln_instance: VulnerabilityInstance,
               vulnerability: Vulnerability, operator: str = "system",
               session: Session = None) -> Tuple[str, str]:
        strategy_used = ""
        reason = ""

        current_load = self._get_current_load(session)

        candidates = self._get_candidates_by_asset_owner(vuln_instance)
        if candidates:
            strategy_used = "asset_owner"
            reason = f"按资产负责人分配: {candidates[0]}"
        else:
            candidates = self._get_candidates_by_department(vuln_instance)
            if candidates:
                strategy_used = "department"
                reason = f"按部门分配: {vuln_instance.asset.department}"
            else:
                candidates = self._get_candidates_by_vuln_type(vulnerability)
                strategy_used = "vuln_type"
                reason = f"按漏洞类型分配: {self._extract_vuln_type(vulnerability)}"

        candidates = self._filter_by_skill_tags(candidates, vulnerability)
        if len(candidates) > 1:
            candidates = self._balance_load(candidates, current_load)
            if len(candidates) > 1:
                assignee = self._round_robin_select(candidates, strategy_used)
                strategy_used += "_round_robin"
                reason += " (轮询选择)"
            else:
                assignee = candidates[0]
                strategy_used += "_load_balanced"
                reason += " (负载均衡选择)"
        else:
            assignee = candidates[0] if candidates else "default_user"

        record = AssignmentRecord(
            work_order_id=work_order.id,
            assignee=assignee,
            assigned_by=operator,
            assignment_strategy=strategy_used,
            reason=reason
        )
        self._assignment_history.append(record)

        log_audit(
            action="work_order_assign",
            resource_type="work_order",
            resource_id=str(work_order.id),
            detail=f"自动分配工单给 {assignee}, 策略: {strategy_used}, 原因: {reason}",
            user=operator
        )

        logger.info(
            f"Work order {work_order.id} assigned to {assignee} "
            f"using strategy {strategy_used}: {reason}"
        )

        return assignee, strategy_used

    def get_assignment_history(self, work_order_id: Optional[int] = None) -> List[Dict[str, Any]]:
        if work_order_id:
            return [r.to_dict() for r in self._assignment_history 
                    if r.work_order_id == work_order_id]
        return [r.to_dict() for r in self._assignment_history]


class WorkOrderCreator:
    def __init__(self):
        self.deadline_config = config.work_order.DEADLINE_HOURS

    def _calculate_deadline(self, severity: SeverityEnum) -> datetime:
        hours = self.deadline_config.get(severity.value, self.deadline_config["medium"])
        return datetime.now(timezone.utc) + timedelta(hours=hours)

    def _generate_title(self, vulnerability: Vulnerability, asset: Asset) -> str:
        severity_display = {
            "critical": "严重",
            "high": "高危",
            "medium": "中危",
            "low": "低危"
        }.get(vulnerability.severity.value, vulnerability.severity.value)
        
        vuln_name = vulnerability.title[:50] if vulnerability.title else "未知漏洞"
        asset_name = asset.name[:30] if asset.name else "未知资产"
        
        return f"[{severity_display}]{vuln_name} - {asset_name}"

    def _generate_content(self, vuln_instance: VulnerabilityInstance, 
                          vulnerability: Vulnerability, asset: Asset) -> str:
        content_parts = []
        
        content_parts.append("=" * 60)
        content_parts.append("漏洞详情")
        content_parts.append("=" * 60)
        
        if vulnerability.cve_id:
            content_parts.append(f"CVE编号: {vulnerability.cve_id}")
        
        content_parts.append(f"漏洞名称: {vulnerability.title}")
        content_parts.append(f"风险等级: {vulnerability.severity.value}")
        
        if vulnerability.cvss_score:
            content_parts.append(f"CVSS评分: {vulnerability.cvss_score}")
        
        if vulnerability.cwe_id:
            content_parts.append(f"CWE编号: {vulnerability.cwe_id}")
        
        content_parts.append(f"漏洞来源: {vulnerability.source}")
        content_parts.append(f"发现时间: {vuln_instance.discovery_time.strftime('%Y-%m-%d %H:%M:%S')}")
        
        if vuln_instance.port:
            content_parts.append(f"端口: {vuln_instance.port}")
        
        if vuln_instance.protocol:
            content_parts.append(f"协议: {vuln_instance.protocol}")
        
        if vuln_instance.location:
            content_parts.append(f"漏洞位置: {vuln_instance.location}")
        
        if vuln_instance.evidence:
            content_parts.append(f"验证证据: {vuln_instance.evidence}")
        
        content_parts.append("")
        content_parts.append("漏洞描述:")
        content_parts.append(vulnerability.description or "暂无描述")
        
        content_parts.append("")
        content_parts.append("=" * 60)
        content_parts.append("资产信息")
        content_parts.append("=" * 60)
        content_parts.append(f"资产名称: {asset.name}")
        content_parts.append(f"IP地址: {asset.ip}")
        content_parts.append(f"资产类型: {asset.type}")
        content_parts.append(f"所属部门: {asset.department}")
        content_parts.append(f"资产负责人: {asset.owner}")
        content_parts.append(f"重要程度: {asset.importance}")
        
        if vulnerability.reference:
            content_parts.append("")
            content_parts.append("=" * 60)
            content_parts.append("修复建议参考链接")
            content_parts.append("=" * 60)
            
            refs = vulnerability.reference.split('\n')
            for i, ref in enumerate(refs, 1):
                if ref.strip():
                    content_parts.append(f"{i}. {ref.strip()}")
        
        return "\n".join(content_parts)

    def get_title(self, work_order: WorkOrder) -> str:
        vuln_instance = work_order.vuln_instance
        if not vuln_instance:
            return f"工单 #{work_order.id}"
        return self._generate_title(vuln_instance.vulnerability, vuln_instance.asset)

    def get_content(self, work_order: WorkOrder) -> str:
        vuln_instance = work_order.vuln_instance
        if not vuln_instance:
            return f"工单 #{work_order.id} 详情"
        return self._generate_content(vuln_instance, vuln_instance.vulnerability, vuln_instance.asset)

    @with_session
    def create(self, vuln_instance_id: int, operator: Optional[str] = None,
               session: Session = None) -> Optional[WorkOrder]:
        try:
            vuln_instance = session.query(VulnerabilityInstance).filter_by(
                id=vuln_instance_id
            ).first()
            
            if not vuln_instance:
                logger.error(f"Vulnerability instance {vuln_instance_id} not found")
                return None

            existing = session.query(WorkOrder).filter_by(
                vuln_instance_id=vuln_instance_id
            ).filter(
                WorkOrder.status != WorkOrderStatusEnum.CLOSED
            ).first()
            
            if existing:
                logger.warning(
                    f"Active work order already exists for vuln_instance {vuln_instance_id}: "
                    f"work_order {existing.id}"
                )
                return existing

            vulnerability = vuln_instance.vulnerability
            asset = vuln_instance.asset

            deadline = self._calculate_deadline(vulnerability.severity)
            title = self._generate_title(vulnerability, asset)
            content = self._generate_content(vuln_instance, vulnerability, asset)

            work_order = WorkOrder(
                vuln_instance_id=vuln_instance_id,
                assignee="pending",
                status=WorkOrderStatusEnum.PENDING,
                deadline=deadline,
                current_stage_start=datetime.now(timezone.utc),
                remarks=content[:500] if content else None
            )

            session.add(work_order)
            session.flush()

            log_audit(
                action="work_order_create",
                resource_type="work_order",
                resource_id=str(work_order.id),
                detail=f"创建工单: {title}, 截止日期: {deadline.strftime('%Y-%m-%d %H:%M:%S')}",
                user=operator or "system"
            )

            logger.info(
                f"Work order {work_order.id} created for vuln_instance {vuln_instance_id}"
            )

            return work_order

        except Exception as e:
            logger.exception(f"Failed to create work order for vuln_instance {vuln_instance_id}: {e}")
            raise

    @with_session
    def batch_create(self, vuln_instance_ids: List[int], operator: Optional[str] = None,
                     session: Session = None) -> List[WorkOrder]:
        work_orders = []
        for vuln_instance_id in vuln_instance_ids:
            try:
                wo = self.create(vuln_instance_id, operator, session=session)
                if wo:
                    work_orders.append(wo)
            except Exception as e:
                logger.error(f"Failed to create work order for vuln_instance {vuln_instance_id}: {e}")
                continue
        
        logger.info(f"Batch created {len(work_orders)} work orders from {len(vuln_instance_ids)} instances")
        return work_orders


class StatusManager:
    def __init__(self):
        self.status_flow = WORK_ORDER_STATUS_FLOW

    def _is_valid_transition(self, current_status: WorkOrderStatusEnum,
                             new_status: WorkOrderStatusEnum) -> bool:
        if new_status == WorkOrderStatusEnum.CLOSED:
            return current_status != WorkOrderStatusEnum.CLOSED
        return new_status in self.status_flow.get(current_status, [])

    def _update_status_timestamps(self, work_order: WorkOrder, new_status: WorkOrderStatusEnum):
        now = datetime.now(timezone.utc)
        
        status_timestamp_map = {
            WorkOrderStatusEnum.FIXING: "started_at",
            WorkOrderStatusEnum.FIXED: "fixed_at",
            WorkOrderStatusEnum.VERIFYING: "verified_at",
            WorkOrderStatusEnum.CLOSED: "closed_at"
        }
        
        timestamp_field = status_timestamp_map.get(new_status)
        if timestamp_field and not getattr(work_order, timestamp_field):
            setattr(work_order, timestamp_field, now)
        
        work_order.current_stage_start = now

    def _get_audit_detail(self, work_order: WorkOrder, old_status: WorkOrderStatusEnum,
                          new_status: WorkOrderStatusEnum, reason: Optional[str]) -> str:
        status_display = {
            WorkOrderStatusEnum.PENDING: "待处理",
            WorkOrderStatusEnum.FIXING: "修复中",
            WorkOrderStatusEnum.FIXED: "已修复",
            WorkOrderStatusEnum.VERIFYING: "验证中",
            WorkOrderStatusEnum.CLOSED: "已关闭"
        }
        
        detail = f"状态变更: {status_display.get(old_status, old_status.value)} -> {status_display.get(new_status, new_status.value)}"
        if reason:
            detail += f", 原因: {reason}"
        
        return detail

    @with_session
    def update_status(self, work_order_id: int, new_status: WorkOrderStatusEnum,
                      operator: str, reason: Optional[str] = None,
                      session: Session = None) -> Optional[WorkOrder]:
        try:
            work_order = session.query(WorkOrder).filter_by(id=work_order_id).first()
            
            if not work_order:
                logger.error(f"Work order {work_order_id} not found")
                return None

            old_status = work_order.status

            if not self._is_valid_transition(old_status, new_status):
                error_msg = (
                    f"Invalid status transition for work order {work_order_id}: "
                    f"{old_status.value} -> {new_status.value}"
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

            if new_status == WorkOrderStatusEnum.CLOSED and not reason:
                raise ValueError("Closing a work order requires a reason")

            self._update_status_timestamps(work_order, new_status)
            work_order.status = new_status
            work_order.updated_at = datetime.now(timezone.utc)

            audit_detail = self._get_audit_detail(work_order, old_status, new_status, reason)
            log_audit(
                action="work_order_status_update",
                resource_type="work_order",
                resource_id=str(work_order_id),
                detail=audit_detail,
                user=operator
            )

            logger.info(
                f"Work order {work_order_id} status updated: "
                f"{old_status.value} -> {new_status.value} by {operator}"
            )

            return work_order

        except ValueError:
            raise
        except Exception as e:
            logger.exception(f"Failed to update status for work order {work_order_id}: {e}")
            raise

    def get_valid_next_statuses(self, current_status: WorkOrderStatusEnum) -> List[WorkOrderStatusEnum]:
        valid_statuses = self.status_flow.get(current_status, []).copy()
        if current_status != WorkOrderStatusEnum.CLOSED:
            valid_statuses.append(WorkOrderStatusEnum.CLOSED)
        return valid_statuses


class EscalationManager:
    def __init__(self):
        self.stages = ESCALATION_STAGES
        self.notification_cooldown = 3600

    def _get_overdue_hours(self, work_order: WorkOrder) -> float:
        if work_order.status == WorkOrderStatusEnum.CLOSED:
            return 0
        
        now = datetime.now(timezone.utc)
        if work_order.deadline > now:
            return 0
        
        return (now - work_order.deadline).total_seconds() / 3600

    def _get_current_escalation_stage(self, overdue_hours: float) -> Optional[Dict[str, Any]]:
        for stage in self.stages:
            min_hours, max_hours = stage["hours_range"]
            if min_hours <= overdue_hours < max_hours:
                return stage
        return None

    def _should_escalate(self, work_order: WorkOrder, new_level: int, session: Session) -> bool:
        if work_order.escalation_level >= new_level:
            recent = session.query(EscalationRecord).filter(
                EscalationRecord.work_order_id == work_order.id,
                EscalationRecord.new_level == new_level,
                EscalationRecord.created_at >= datetime.now(timezone.utc) - timedelta(seconds=self.notification_cooldown)
            ).first()
            if recent:
                return False
        return True

    def _get_recipients(self, work_order: WorkOrder, roles: List[str], session: Session) -> List[str]:
        recipients = set()
        
        vuln_instance = work_order.vuln_instance
        asset = vuln_instance.asset if vuln_instance else None
        
        role_to_email = {
            "assignee": work_order.assignee,
            "department_security": f"security_{asset.department}@example.com" if asset else None,
            "security_supervisor": "security_supervisor@example.com",
            "department_director": f"director_{asset.department}@example.com" if asset else None,
            "ciso_cio": "ciso@example.com"
        }
        
        for role in roles:
            email = role_to_email.get(role)
            if email:
                recipients.add(email)
        
        return list(recipients)

    def _create_escalation_record(self, work_order: WorkOrder, old_level: int, new_level: int,
                                  reason: str, operator: str, recipients: List[str],
                                  session: Session) -> EscalationRecord:
        record = EscalationRecord(
            work_order_id=work_order.id,
            old_level=old_level,
            new_level=new_level,
            reason=reason,
            escalated_by=operator,
            notified_recipients=", ".join(recipients)
        )
        
        session.add(record)
        session.flush()
        
        log_audit(
            action="work_order_escalate",
            resource_type="work_order",
            resource_id=str(work_order.id),
            detail=f"升级等级: {old_level} -> {new_level}, 原因: {reason}, 通知: {', '.join(recipients)}",
            user=operator
        )
        
        return record

    @with_session
    def check_and_escalate(self, session: Session = None) -> List[WorkOrder]:
        escalated_work_orders = []
        
        now = datetime.now(timezone.utc)
        
        active_work_orders = session.query(WorkOrder).filter(
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline <= now
        ).all()
        
        logger.info(f"Checking escalation for {len(active_work_orders)} overdue work orders")
        
        for work_order in active_work_orders:
            try:
                overdue_hours = self._get_overdue_hours(work_order)
                stage = self._get_current_escalation_stage(overdue_hours)
                
                if not stage:
                    continue
                
                new_level = stage["level"]
                
                if not self._should_escalate(work_order, new_level, session):
                    continue
                
                recipients = self._get_recipients(work_order, stage["notify_roles"], session)
                
                old_level = work_order.escalation_level
                work_order.escalation_level = new_level
                work_order.updated_at = now
                
                reason = f"工单超时 {overdue_hours:.1f} 小时，触发 {stage['level']} 级升级"
                
                self._create_escalation_record(
                    work_order, old_level, new_level, reason, "system", recipients, session
                )
                
                escalated_work_orders.append(work_order)
                
                logger.info(
                    f"Work order {work_order.id} escalated from level {old_level} to {new_level}. "
                    f"Overdue: {overdue_hours:.1f}h. Recipients: {', '.join(recipients)}"
                )
                
            except Exception as e:
                logger.exception(f"Failed to escalate work order {work_order.id}: {e}")
                continue
        
        logger.info(f"Escalated {len(escalated_work_orders)} work orders")
        return escalated_work_orders

    @with_session
    def check_upcoming_deadlines(self, hours_before: int = 2, session: Session = None) -> List[WorkOrder]:
        now = datetime.now(timezone.utc)
        deadline_threshold = now + timedelta(hours=hours_before)
        
        upcoming = session.query(WorkOrder).filter(
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline > now,
            WorkOrder.deadline <= deadline_threshold
        ).all()
        
        logger.info(f"Found {len(upcoming)} work orders approaching deadline within {hours_before}h")
        return upcoming


class NotificationService:
    def __init__(self):
        self.notification_config = config.notification
        self.max_retries = 3
        self.retry_delay = 5

    def _send_email(self, recipient: str, subject: str, content: str) -> bool:
        try:
            msg = MIMEMultipart()
            msg['From'] = formataddr(('安全管理系统', self.notification_config.SMTP_FROM))
            msg['To'] = recipient
            msg['Subject'] = subject
            
            msg.attach(MIMEText(content, 'plain', 'utf-8'))
            
            with smtplib.SMTP(self.notification_config.SMTP_HOST, self.notification_config.SMTP_PORT, timeout=30) as server:
                if self.notification_config.SMTP_USE_TLS:
                    server.starttls()
                if self.notification_config.SMTP_USERNAME:
                    server.login(self.notification_config.SMTP_USERNAME, self.notification_config.SMTP_PASSWORD)
                server.send_message(msg)
            
            logger.info(f"Email sent to {recipient}: {subject}")
            return True
            
        except Exception as e:
            logger.error(f"Failed to send email to {recipient}: {e}")
            return False

    def _send_dingtalk(self, webhook: str, secret: str, content: str) -> bool:
        try:
            if not webhook:
                return False
            
            timestamp = str(round(time.time() * 1000))
            
            data = {
                "msgtype": "text",
                "text": {
                    "content": content
                },
                "at": {
                    "isAtAll": False
                }
            }
            
            headers = {"Content-Type": "application/json"}
            response = requests.post(webhook, json=data, headers=headers, timeout=10)
            
            result = response.json()
            if result.get('errcode') == 0:
                logger.info(f"DingTalk message sent successfully")
                return True
            else:
                logger.error(f"DingTalk API error: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send DingTalk message: {e}")
            return False

    def _send_wechat(self, webhook: str, content: str) -> bool:
        try:
            if not webhook:
                return False
            
            data = {
                "msgtype": "text",
                "text": {
                    "content": content
                }
            }
            
            headers = {"Content-Type": "application/json"}
            response = requests.post(webhook, json=data, headers=headers, timeout=10)
            
            result = response.json()
            if result.get('errcode') == 0:
                logger.info(f"WeChat message sent successfully")
                return True
            else:
                logger.error(f"WeChat API error: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send WeChat message: {e}")
            return False

    def _send_feishu(self, webhook: str, content: str) -> bool:
        try:
            if not webhook:
                return False
            
            data = {
                "msg_type": "text",
                "content": {
                    "text": content
                }
            }
            
            headers = {"Content-Type": "application/json"}
            response = requests.post(webhook, json=data, headers=headers, timeout=10)
            
            result = response.json()
            if result.get('code') == 0:
                logger.info(f"Feishu message sent successfully")
                return True
            else:
                logger.error(f"Feishu API error: {result}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to send Feishu message: {e}")
            return False

    def _send_with_retry(self, send_func, *args, **kwargs) -> Tuple[bool, Optional[str]]:
        last_error = None
        
        for attempt in range(self.max_retries):
            try:
                success = send_func(*args, **kwargs)
                if success:
                    return True, None
                last_error = "Send function returned False"
            except Exception as e:
                last_error = str(e)
                logger.warning(f"Notification attempt {attempt + 1} failed: {e}")
            
            if attempt < self.max_retries - 1:
                time.sleep(self.retry_delay * (attempt + 1))
        
        return False, last_error

    @with_session
    def _create_notification_record(self, work_order_id: int, notification_type: NotificationTypeEnum,
                                    recipient: str, content: str, escalation_level: int,
                                    session: Session) -> Notification:
        notification = Notification(
            type=notification_type,
            recipient=recipient,
            content=content,
            status=NotificationStatusEnum.PENDING,
            escalation_level=escalation_level,
            work_order_id=work_order_id
        )
        session.add(notification)
        session.flush()
        return notification

    def _update_notification_status(self, notification: Notification, success: bool,
                                    error_message: Optional[str] = None, session: Session = None):
        if success:
            notification.status = NotificationStatusEnum.SENT
            notification.sent_at = datetime.now(timezone.utc)
        else:
            notification.status = NotificationStatusEnum.FAILED
            notification.error_message = error_message
        
        notification.retry_count += 1
        notification.updated_at = datetime.now(timezone.utc)

    def _get_template_new_order(self, work_order: WorkOrder) -> Tuple[str, str]:
        creator = WorkOrderCreator()
        title = creator.get_title(work_order)
        severity = work_order.vuln_instance.vulnerability.severity.value if work_order.vuln_instance else "unknown"
        
        subject = f"【新工单通知】{title}"
        
        content = f"""
您好，您有新的安全漏洞工单需要处理：

工单编号: {work_order.id}
工单标题: {title}
分配给: {work_order.assignee}
风险等级: {severity}
截止日期: {work_order.deadline.strftime('%Y-%m-%d %H:%M:%S')}
创建时间: {work_order.created_at.strftime('%Y-%m-%d %H:%M:%S')}

请及时登录系统处理。
        """
        
        return subject, content.strip()

    def _get_template_upcoming_deadline(self, work_order: WorkOrder, hours_left: float) -> Tuple[str, str]:
        creator = WorkOrderCreator()
        title = creator.get_title(work_order)
        
        subject = f"【即将超时提醒】工单 {work_order.id} 将在 {hours_left:.0f} 小时后超时"
        
        content = f"""
您好，您负责的工单即将超时：

工单编号: {work_order.id}
工单标题: {title}
当前状态: {work_order.status.value}
剩余时间: {hours_left:.0f} 小时
截止日期: {work_order.deadline.strftime('%Y-%m-%d %H:%M:%S')}

请尽快处理，避免工单升级。
        """
        
        return subject, content.strip()

    def _get_template_escalation(self, work_order: WorkOrder, level: int, overdue_hours: float) -> Tuple[str, str]:
        level_desc = {1: "一级", 2: "二级", 3: "三级", 4: "四级"}.get(level, f"{level}级")
        creator = WorkOrderCreator()
        title = creator.get_title(work_order)
        severity = work_order.vuln_instance.vulnerability.severity.value if work_order.vuln_instance else "unknown"
        
        subject = f"【超时升级通知】{level_desc}升级 - 工单 {work_order.id} 已超时 {overdue_hours:.0f} 小时"
        
        content = f"""
【安全工单超时升级通知】

工单编号: {work_order.id}
工单标题: {title}
当前状态: {work_order.status.value}
负责人: {work_order.assignee}
风险等级: {severity}
截止日期: {work_order.deadline.strftime('%Y-%m-%d %H:%M:%S')}
已超时: {overdue_hours:.0f} 小时
升级等级: {level_desc}

请相关负责人关注并督促处理。
        """
        
        return subject, content.strip()

    def _get_template_status_change(self, work_order: WorkOrder, old_status: str, new_status: str,
                                    operator: str, reason: Optional[str]) -> Tuple[str, str]:
        creator = WorkOrderCreator()
        title = creator.get_title(work_order)
        
        subject = f"【状态变更通知】工单 {work_order.id} 状态变更"
        
        content = f"""
您好，工单状态已变更：

工单编号: {work_order.id}
工单标题: {title}
原状态: {old_status}
新状态: {new_status}
操作人: {operator}
变更时间: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}
{('变更原因: ' + reason) if reason else ''}

请知悉。
        """
        
        return subject, content.strip()

    @with_session
    def send_new_order_notification(self, work_order: WorkOrder, session: Session = None) -> bool:
        if not work_order:
            return False
        
        subject, content = self._get_template_new_order(work_order)
        channels = self.notification_config.NOTIFICATION_CHANNELS
        success_count = 0
        
        recipients = [work_order.assignee]
        
        for recipient in recipients:
            for channel in channels:
                try:
                    notification_type = NotificationTypeEnum(channel)
                    notification = self._create_notification_record(
                        work_order.id, notification_type, recipient, content,
                        work_order.escalation_level, session=session
                    )
                    
                    if channel == "email":
                        email_addr = f"{recipient}@example.com" if "@" not in recipient else recipient
                        success, error = self._send_with_retry(
                            self._send_email, email_addr, subject, content
                        )
                    elif channel == "dingtalk":
                        success, error = self._send_with_retry(
                            self._send_dingtalk,
                            self.notification_config.DINGTALK_WEBHOOK,
                            self.notification_config.DINGTALK_SECRET,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "wechat":
                        success, error = self._send_with_retry(
                            self._send_wechat,
                            self.notification_config.WECHAT_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "feishu":
                        success, error = self._send_with_retry(
                            self._send_feishu,
                            self.notification_config.FEISHU_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    else:
                        success, error = False, f"Unknown channel: {channel}"
                    
                    self._update_notification_status(notification, success, error, session=session)
                    
                    if success:
                        success_count += 1
                        
                except Exception as e:
                    logger.exception(f"Failed to send {channel} notification for work order {work_order.id}: {e}")
        
        logger.info(f"New order notifications sent: {success_count} channels succeeded for work order {work_order.id}")
        return success_count > 0

    @with_session
    def send_upcoming_deadline_notification(self, work_order: WorkOrder, 
                                             hours_left: float, session: Session = None) -> bool:
        subject, content = self._get_template_upcoming_deadline(work_order, hours_left)
        channels = self.notification_config.NOTIFICATION_CHANNELS
        success_count = 0
        
        recipients = [work_order.assignee]
        
        for recipient in recipients:
            for channel in channels:
                try:
                    notification_type = NotificationTypeEnum(channel)
                    notification = self._create_notification_record(
                        work_order.id, notification_type, recipient, content,
                        work_order.escalation_level, session=session
                    )
                    
                    if channel == "email":
                        email_addr = f"{recipient}@example.com" if "@" not in recipient else recipient
                        success, error = self._send_with_retry(
                            self._send_email, email_addr, subject, content
                        )
                    elif channel == "dingtalk":
                        success, error = self._send_with_retry(
                            self._send_dingtalk,
                            self.notification_config.DINGTALK_WEBHOOK,
                            self.notification_config.DINGTALK_SECRET,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "wechat":
                        success, error = self._send_with_retry(
                            self._send_wechat,
                            self.notification_config.WECHAT_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "feishu":
                        success, error = self._send_with_retry(
                            self._send_feishu,
                            self.notification_config.FEISHU_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    else:
                        success, error = False, f"Unknown channel: {channel}"
                    
                    self._update_notification_status(notification, success, error, session=session)
                    
                    if success:
                        success_count += 1
                        
                except Exception as e:
                    logger.exception(f"Failed to send upcoming deadline notification for work order {work_order.id}: {e}")
        
        return success_count > 0

    @with_session
    def send_escalation_notification(self, work_order: WorkOrder, level: int,
                                     overdue_hours: float, recipients: List[str],
                                     session: Session = None) -> bool:
        subject, content = self._get_template_escalation(work_order, level, overdue_hours)
        channels = self.notification_config.NOTIFICATION_CHANNELS
        success_count = 0
        
        for recipient in recipients:
            for channel in channels:
                try:
                    notification_type = NotificationTypeEnum(channel)
                    notification = self._create_notification_record(
                        work_order.id, notification_type, recipient, content,
                        level, session=session
                    )
                    
                    if channel == "email":
                        success, error = self._send_with_retry(
                            self._send_email, recipient, subject, content
                        )
                    elif channel == "dingtalk":
                        success, error = self._send_with_retry(
                            self._send_dingtalk,
                            self.notification_config.DINGTALK_WEBHOOK,
                            self.notification_config.DINGTALK_SECRET,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "wechat":
                        success, error = self._send_with_retry(
                            self._send_wechat,
                            self.notification_config.WECHAT_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "feishu":
                        success, error = self._send_with_retry(
                            self._send_feishu,
                            self.notification_config.FEISHU_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    else:
                        success, error = False, f"Unknown channel: {channel}"
                    
                    self._update_notification_status(notification, success, error, session=session)
                    
                    if success:
                        success_count += 1
                        
                except Exception as e:
                    logger.exception(f"Failed to send escalation notification to {recipient}: {e}")
        
        return success_count > 0

    @with_session
    def send_status_change_notification(self, work_order: WorkOrder, old_status: str,
                                         new_status: str, operator: str,
                                         reason: Optional[str] = None, session: Session = None) -> bool:
        subject, content = self._get_template_status_change(work_order, old_status, new_status, operator, reason)
        channels = self.notification_config.NOTIFICATION_CHANNELS
        success_count = 0
        
        recipients = [work_order.assignee, operator]
        
        for recipient in recipients:
            for channel in channels:
                try:
                    notification_type = NotificationTypeEnum(channel)
                    notification = self._create_notification_record(
                        work_order.id, notification_type, recipient, content,
                        work_order.escalation_level, session=session
                    )
                    
                    if channel == "email":
                        email_addr = f"{recipient}@example.com" if "@" not in recipient else recipient
                        success, error = self._send_with_retry(
                            self._send_email, email_addr, subject, content
                        )
                    elif channel == "dingtalk":
                        success, error = self._send_with_retry(
                            self._send_dingtalk,
                            self.notification_config.DINGTALK_WEBHOOK,
                            self.notification_config.DINGTALK_SECRET,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "wechat":
                        success, error = self._send_with_retry(
                            self._send_wechat,
                            self.notification_config.WECHAT_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    elif channel == "feishu":
                        success, error = self._send_with_retry(
                            self._send_feishu,
                            self.notification_config.FEISHU_WEBHOOK,
                            f"{subject}\n\n{content}"
                        )
                    else:
                        success, error = False, f"Unknown channel: {channel}"
                    
                    self._update_notification_status(notification, success, error, session=session)
                    
                    if success:
                        success_count += 1
                        
                except Exception as e:
                    logger.exception(f"Failed to send status change notification for work order {work_order.id}: {e}")
        
        return success_count > 0

    @with_session
    def retry_failed_notifications(self, session: Session = None) -> int:
        failed_notifications = session.query(Notification).filter(
            Notification.status == NotificationStatusEnum.FAILED,
            Notification.retry_count < self.max_retries * 2
        ).all()
        
        retried_count = 0
        
        for notification in failed_notifications:
            try:
                success = False
                error = None
                
                if notification.type == NotificationTypeEnum.EMAIL:
                    success, error = self._send_with_retry(
                        self._send_email, notification.recipient,
                        f"【重试】通知", notification.content
                    )
                elif notification.type == NotificationTypeEnum.DINGTALK:
                    success, error = self._send_with_retry(
                        self._send_dingtalk,
                        self.notification_config.DINGTALK_WEBHOOK,
                        self.notification_config.DINGTALK_SECRET,
                        notification.content
                    )
                elif notification.type == NotificationTypeEnum.WECHAT:
                    success, error = self._send_with_retry(
                        self._send_wechat,
                        self.notification_config.WECHAT_WEBHOOK,
                        notification.content
                    )
                elif notification.type == NotificationTypeEnum.FEISHU:
                    success, error = self._send_with_retry(
                        self._send_feishu,
                        self.notification_config.FEISHU_WEBHOOK,
                        notification.content
                    )
                
                self._update_notification_status(notification, success, error, session=session)
                
                if success:
                    retried_count += 1
                    
            except Exception as e:
                logger.exception(f"Failed to retry notification {notification.id}: {e}")
                continue
        
        logger.info(f"Retried {retried_count} failed notifications")
        return retried_count


class WorkOrderQuery:
    def __init__(self):
        pass

    def _build_filters(self, filters: Dict[str, Any]) -> List:
        conditions = []
        
        if "status" in filters:
            if isinstance(filters["status"], list):
                conditions.append(WorkOrder.status.in_(filters["status"]))
            else:
                conditions.append(WorkOrder.status == filters["status"])
        
        if "assignee" in filters:
            conditions.append(WorkOrder.assignee == filters["assignee"])
        
        if "department" in filters:
            conditions.append(Asset.department == filters["department"])
        
        if "severity" in filters:
            if isinstance(filters["severity"], list):
                conditions.append(Vulnerability.severity.in_(filters["severity"]))
            else:
                conditions.append(Vulnerability.severity == filters["severity"])
        
        if "start_time" in filters:
            conditions.append(WorkOrder.created_at >= filters["start_time"])
        
        if "end_time" in filters:
            conditions.append(WorkOrder.created_at <= filters["end_time"])
        
        if "escalation_level" in filters:
            conditions.append(WorkOrder.escalation_level >= filters["escalation_level"])
        
        if "overdue" in filters and filters["overdue"]:
            conditions.append(WorkOrder.deadline < datetime.now(timezone.utc))
        
        return conditions

    @with_read_session
    def query(self, filters: Dict[str, Any], page: int = 1, page_size: int = 20,
              session: Session = None) -> Dict[str, Any]:
        conditions = self._build_filters(filters)
        
        query = session.query(WorkOrder).join(
            VulnerabilityInstance, WorkOrder.vuln_instance_id == VulnerabilityInstance.id
        ).join(
            Vulnerability, VulnerabilityInstance.vuln_id == Vulnerability.id
        ).join(
            Asset, VulnerabilityInstance.asset_id == Asset.id
        )
        
        if conditions:
            query = query.filter(and_(*conditions))
        
        total = query.count()
        
        offset = (page - 1) * page_size
        work_orders = query.order_by(
            WorkOrder.deadline.asc(),
            WorkOrder.created_at.desc()
        ).offset(offset).limit(page_size).all()
        
        total_pages = (total + page_size - 1) // page_size
        
        return {
            "items": work_orders,
            "total": total,
            "page": page,
            "page_size": page_size,
            "total_pages": total_pages,
            "has_next": page < total_pages,
            "has_prev": page > 1
        }

    @with_read_session
    def get_personal_stats(self, assignee: str, session: Session = None) -> Dict[str, Any]:
        stats = session.query(
            WorkOrder.status,
            func.count(WorkOrder.id).label('count')
        ).filter(
            WorkOrder.assignee == assignee
        ).group_by(WorkOrder.status).all()
        
        result = defaultdict(int)
        for row in stats:
            result[row.status.value] = row.count
        
        overdue = session.query(func.count(WorkOrder.id)).filter(
            WorkOrder.assignee == assignee,
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline < datetime.now(timezone.utc)
        ).scalar() or 0
        
        return {
            "assignee": assignee,
            "pending": result.get("pending", 0),
            "fixing": result.get("fixing", 0),
            "fixed": result.get("fixed", 0),
            "verifying": result.get("verifying", 0),
            "closed": result.get("closed", 0),
            "overdue": overdue,
            "total_active": result.get("pending", 0) + result.get("fixing", 0) + result.get("fixed", 0) + result.get("verifying", 0)
        }

    @with_read_session
    def get_department_stats(self, department: str, session: Session = None) -> Dict[str, Any]:
        stats = session.query(
            WorkOrder.status,
            func.count(WorkOrder.id).label('count')
        ).join(
            VulnerabilityInstance, WorkOrder.vuln_instance_id == VulnerabilityInstance.id
        ).join(
            Asset, VulnerabilityInstance.asset_id == Asset.id
        ).filter(
            Asset.department == department
        ).group_by(WorkOrder.status).all()
        
        result = defaultdict(int)
        for row in stats:
            result[row.status.value] = row.count
        
        overdue = session.query(func.count(WorkOrder.id)).join(
            VulnerabilityInstance, WorkOrder.vuln_instance_id == VulnerabilityInstance.id
        ).join(
            Asset, VulnerabilityInstance.asset_id == Asset.id
        ).filter(
            Asset.department == department,
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline < datetime.now(timezone.utc)
        ).scalar() or 0
        
        return {
            "department": department,
            "pending": result.get("pending", 0),
            "fixing": result.get("fixing", 0),
            "fixed": result.get("fixed", 0),
            "verifying": result.get("verifying", 0),
            "closed": result.get("closed", 0),
            "overdue": overdue,
            "total_active": result.get("pending", 0) + result.get("fixing", 0) + result.get("fixed", 0) + result.get("verifying", 0)
        }

    @with_read_session
    def get_overdue_stats(self, session: Session = None) -> Dict[str, Any]:
        now = datetime.now(timezone.utc)
        
        by_severity = session.query(
            Vulnerability.severity,
            func.count(WorkOrder.id).label('count')
        ).join(
            VulnerabilityInstance, WorkOrder.vuln_instance_id == VulnerabilityInstance.id
        ).join(
            Vulnerability, VulnerabilityInstance.vuln_id == Vulnerability.id
        ).filter(
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline < now
        ).group_by(Vulnerability.severity).all()
        
        by_department = session.query(
            Asset.department,
            func.count(WorkOrder.id).label('count')
        ).join(
            VulnerabilityInstance, WorkOrder.vuln_instance_id == VulnerabilityInstance.id
        ).join(
            Asset, VulnerabilityInstance.asset_id == Asset.id
        ).filter(
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline < now
        ).group_by(Asset.department).all()
        
        by_escalation = session.query(
            WorkOrder.escalation_level,
            func.count(WorkOrder.id).label('count')
        ).filter(
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline < now
        ).group_by(WorkOrder.escalation_level).all()
        
        total_overdue = session.query(func.count(WorkOrder.id)).filter(
            WorkOrder.status != WorkOrderStatusEnum.CLOSED,
            WorkOrder.deadline < now
        ).scalar() or 0
        
        return {
            "total_overdue": total_overdue,
            "by_severity": {row.severity.value: row.count for row in by_severity},
            "by_department": {row.department: row.count for row in by_department},
            "by_escalation_level": {row.escalation_level: row.count for row in by_escalation}
        }

    @with_read_session
    def get_by_id(self, work_order_id: int, session: Session = None) -> Optional[WorkOrder]:
        return session.query(WorkOrder).filter_by(id=work_order_id).first()

    @with_read_session
    def get_by_vuln_instance(self, vuln_instance_id: int, session: Session = None) -> List[WorkOrder]:
        return session.query(WorkOrder).filter_by(
            vuln_instance_id=vuln_instance_id
        ).order_by(WorkOrder.created_at.desc()).all()

    @with_read_session
    def get_active_by_assignee(self, assignee: str, session: Session = None) -> List[WorkOrder]:
        return session.query(WorkOrder).filter(
            WorkOrder.assignee == assignee,
            WorkOrder.status.in_([
                WorkOrderStatusEnum.PENDING,
                WorkOrderStatusEnum.FIXING,
                WorkOrderStatusEnum.FIXED,
                WorkOrderStatusEnum.VERIFYING
            ])
        ).order_by(WorkOrder.deadline.asc()).all()


class WorkOrderService:
    def __init__(self):
        self.auto_assigner = AutoAssigner()
        self.work_order_creator = WorkOrderCreator()
        self.status_manager = StatusManager()
        self.escalation_manager = EscalationManager()
        self.notification_service = NotificationService()
        self.work_order_query = WorkOrderQuery()

    @with_session
    @with_log_context(operation_type="auto_create_work_orders")
    def auto_create_work_orders(self, session: Session = None) -> Dict[str, int]:
        from models import VulnerabilityInstance, FixStatusEnum

        existing_inst_ids = {
            wo[0] for wo in session.query(WorkOrder.vuln_instance_id).all()
        }

        pending_instances = (
            session.query(VulnerabilityInstance)
            .filter(VulnerabilityInstance.fix_status == FixStatusEnum.PENDING)
            .filter(~VulnerabilityInstance.id.in_(existing_inst_ids))
            .all()
        )

        if not pending_instances:
            logger.info("No pending vulnerability instances need work orders")
            return {"total": 0, "created": 0, "failed": 0}

        instance_ids = [inst.id for inst in pending_instances]
        created_count = 0
        failed_count = 0

        batch_size = 50
        for i in range(0, len(instance_ids), batch_size):
            batch = instance_ids[i:i + batch_size]
            try:
                work_orders = self.work_order_creator.batch_create(batch, operator="system", session=session)
                for work_order in work_orders:
                    try:
                        vuln_instance = work_order.vuln_instance
                        vulnerability = vuln_instance.vulnerability
                        assignee, strategy = self.auto_assigner.assign(
                            work_order, vuln_instance, vulnerability, "system", session=session
                        )
                        work_order.assignee = assignee
                        work_order.updated_at = datetime.now(timezone.utc)
                        session.flush()
                        self.notification_service.send_new_order_notification(work_order, session=session)
                        created_count += 1
                    except Exception as e:
                        logger.exception(f"Failed to process work order {work_order.id}: {e}")
                        failed_count += 1
            except Exception as e:
                logger.exception(f"Failed to create batch work orders: {e}")
                failed_count += len(batch)

        logger.info(f"Auto create work orders completed: total={len(instance_ids)}, created={created_count}, failed={failed_count}")
        return {"total": len(instance_ids), "created": created_count, "failed": failed_count}

    @with_session
    def notify_new_work_orders(self, session: Session = None) -> Dict[str, int]:
        pending_notifs = (
            session.query(Notification)
            .filter(Notification.status == NotificationStatusEnum.PENDING)
            .limit(100)
            .all()
        )
        sent = 0
        for n in pending_notifs:
            try:
                self.notification_service._send_notification(n, session=session)
                sent += 1
            except Exception as e:
                logger.exception(f"Failed to send notification {n.id}: {e}")
        return {"total": len(pending_notifs), "sent": sent}

    @with_session
    @with_log_context(operation_type="create_work_orders")
    def create_work_orders(self, vuln_instance_ids: List[int], operator: Optional[str] = None,
                           session: Session = None) -> List[WorkOrder]:
        work_orders = self.work_order_creator.batch_create(vuln_instance_ids, operator, session=session)
        
        for work_order in work_orders:
            try:
                vuln_instance = work_order.vuln_instance
                vulnerability = vuln_instance.vulnerability
                
                assignee, strategy = self.auto_assigner.assign(
                    work_order, vuln_instance, vulnerability, operator or "system", session=session
                )
                
                work_order.assignee = assignee
                work_order.updated_at = datetime.now(timezone.utc)
                session.flush()
                
                self.notification_service.send_new_order_notification(work_order, session=session)
                
            except Exception as e:
                logger.exception(f"Failed to process work order {work_order.id}: {e}")
                continue
        
        logger.info(f"Successfully created and processed {len(work_orders)} work orders")
        return work_orders

    @with_session
    @with_log_context(operation_type="update_status")
    def update_status(self, work_order_id: int, new_status: WorkOrderStatusEnum,
                      operator: str, reason: Optional[str] = None,
                      session: Session = None) -> Optional[WorkOrder]:
        work_order = self.work_order_query.get_by_id(work_order_id, session=session)
        if not work_order:
            logger.error(f"Work order {work_order_id} not found")
            return None
        
        old_status = work_order.status.value
        
        updated_order = self.status_manager.update_status(
            work_order_id, new_status, operator, reason, session=session
        )
        
        if updated_order:
            self.notification_service.send_status_change_notification(
                updated_order, old_status, new_status.value, operator, reason, session=session
            )
        
        return updated_order

    @with_session
    @with_log_context(operation_type="check_and_escalate")
    def check_and_escalate(self, session: Session = None) -> List[WorkOrder]:
        escalated = self.escalation_manager.check_and_escalate(session=session)
        
        for work_order in escalated:
            try:
                overdue_hours = (datetime.now(timezone.utc) - work_order.deadline).total_seconds() / 3600
                stage = self.escalation_manager._get_current_escalation_stage(overdue_hours)
                
                if stage:
                    recipients = self.escalation_manager._get_recipients(
                        work_order, stage["notify_roles"], session
                    )
                    
                    self.notification_service.send_escalation_notification(
                        work_order, stage["level"], overdue_hours, recipients, session=session
                    )
            except Exception as e:
                logger.exception(f"Failed to send escalation notification for work order {work_order.id}: {e}")
        
        return escalated

    @with_session
    @with_log_context(operation_type="check_upcoming_deadlines")
    def check_upcoming_deadlines(self, hours_before: int = 2, session: Session = None) -> List[WorkOrder]:
        upcoming = self.escalation_manager.check_upcoming_deadlines(hours_before, session=session)
        
        for work_order in upcoming:
            try:
                hours_left = (work_order.deadline - datetime.now(timezone.utc)).total_seconds() / 3600
                self.notification_service.send_upcoming_deadline_notification(work_order, hours_left, session=session)
            except Exception as e:
                logger.exception(f"Failed to send upcoming deadline notification for work order {work_order.id}: {e}")
        
        return upcoming

    @with_session
    @with_log_context(operation_type="assign_work_order")
    def assign_work_order(self, work_order_id: int, assignee: str, operator: str,
                          reason: str = "", session: Session = None) -> Optional[WorkOrder]:
        work_order = self.work_order_query.get_by_id(work_order_id, session=session)
        if not work_order:
            logger.error(f"Work order {work_order_id} not found")
            return None
        
        old_assignee = work_order.assignee
        work_order.assignee = assignee
        work_order.updated_at = datetime.now(timezone.utc)
        session.flush()
        
        record = AssignmentRecord(
            work_order_id=work_order_id,
            assignee=assignee,
            assigned_by=operator,
            assignment_strategy="manual",
            reason=reason or f"手动重新分配: {old_assignee} -> {assignee}"
        )
        self.auto_assigner._assignment_history.append(record)
        
        log_audit(
            action="work_order_reassign",
            resource_type="work_order",
            resource_id=str(work_order_id),
            detail=f"手动重新分配: {old_assignee} -> {assignee}, 原因: {reason}",
            user=operator
        )
        
        logger.info(f"Work order {work_order_id} reassigned from {old_assignee} to {assignee} by {operator}")
        
        self.notification_service.send_new_order_notification(work_order, session=session)
        
        return work_order

    def query_work_orders(self, filters: Dict[str, Any], page: int = 1, page_size: int = 20) -> Dict[str, Any]:
        return self.work_order_query.query(filters, page, page_size)

    def get_personal_stats(self, assignee: str) -> Dict[str, Any]:
        return self.work_order_query.get_personal_stats(assignee)

    def get_department_stats(self, department: str) -> Dict[str, Any]:
        return self.work_order_query.get_department_stats(department)

    def get_overdue_stats(self) -> Dict[str, Any]:
        return self.work_order_query.get_overdue_stats()

    def get_work_order(self, work_order_id: int) -> Optional[WorkOrder]:
        return self.work_order_query.get_by_id(work_order_id)

    def get_valid_next_statuses(self, current_status: WorkOrderStatusEnum) -> List[WorkOrderStatusEnum]:
        return self.status_manager.get_valid_next_statuses(current_status)

    def retry_failed_notifications(self) -> int:
        return self.notification_service.retry_failed_notifications()

    def get_assignment_history(self, work_order_id: Optional[int] = None) -> List[Dict[str, Any]]:
        return self.auto_assigner.get_assignment_history(work_order_id)
