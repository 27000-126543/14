from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field
from collections import defaultdict
import random
import time
import json

import requests
from sqlalchemy import and_, or_, func
from sqlalchemy.orm import Session

from config import config
from models import (
    WorkOrder, WorkOrderStatusEnum, VulnerabilityInstance, Vulnerability,
    Asset, FixStatusEnum, SeverityEnum, ReviewTask, ReviewTaskStatusEnum,
    ReviewTaskReasonEnum, VerificationRecord
)
from database import db_manager, with_session, with_read_session
from logger import logger, log_audit, with_log_context
from work_order import StatusManager, NotificationService


SCAN_TYPE_QUICK = "quick"
SCAN_TYPE_FULL = "full"
SCAN_TYPE_MANUAL = "manual"

VERIFICATION_TIMEOUT_MINUTES = 30
SCAN_POLL_INTERVAL_SECONDS = 30
REVIEW_TASK_DEADLINE_DAYS = 7
HIGH_RISK_OVERDUE_HOURS = 72
WIDESPREAD_VULN_THRESHOLD = 10

REVIEW_TASK_STATUS_FLOW = {
    ReviewTaskStatusEnum.PENDING_ANALYSIS: [ReviewTaskStatusEnum.IN_ANALYSIS, ReviewTaskStatusEnum.COMPLETED],
    ReviewTaskStatusEnum.IN_ANALYSIS: [ReviewTaskStatusEnum.COMPLETED, ReviewTaskStatusEnum.PENDING_ANALYSIS],
    ReviewTaskStatusEnum.COMPLETED: [ReviewTaskStatusEnum.CONFIRMED],
    ReviewTaskStatusEnum.CONFIRMED: []
}

ROOT_CAUSE_CATEGORIES = [
    "fix_solution_issue",
    "environment_issue",
    "personnel_issue",
    "process_issue",
    "tool_issue",
    "other"
]


@dataclass
class VerificationResult:
    vuln_instance_id: int
    is_fixed: bool
    scan_type: str
    scan_id: Optional[str] = None
    details: Optional[str] = None
    evidence: Optional[str] = None
    operator: str = "system"
    verification_time: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "vuln_instance_id": self.vuln_instance_id,
            "is_fixed": self.is_fixed,
            "scan_type": self.scan_type,
            "scan_id": self.scan_id,
            "details": self.details,
            "evidence": self.evidence,
            "operator": self.operator,
            "verification_time": self.verification_time.isoformat()
        }


class VerificationScanner:
    def __init__(self):
        self.scanner_config = config.scanner
        self.timeout = VERIFICATION_TIMEOUT_MINUTES * 60
        self.poll_interval = SCAN_POLL_INTERVAL_SECONDS
        self.status_manager = StatusManager()
        self.notification_service = NotificationService()

    def _call_scanner_api(self, vuln_instance: VulnerabilityInstance,
                          scan_type: str) -> Optional[str]:
        try:
            asset = vuln_instance.asset
            vulnerability = vuln_instance.vulnerability

            if scan_type == SCAN_TYPE_QUICK:
                payload = {
                    "type": "poc_verify",
                    "target": asset.ip,
                    "port": vuln_instance.port,
                    "vuln_id": vulnerability.cve_id or vulnerability.id,
                    "vuln_type": vulnerability.title,
                    "location": vuln_instance.location
                }
            else:
                payload = {
                    "type": "full_scan",
                    "target": asset.ip,
                    "scan_policy": "vulnerability",
                    "targeted_checks": [vulnerability.cve_id] if vulnerability.cve_id else []
                }

            headers = {
                "X-API-Key": self.scanner_config.INTERNAL_SCANNER_API_KEY,
                "Content-Type": "application/json"
            }

            response = requests.post(
                f"{self.scanner_config.INTERNAL_SCANNER_API_URL}/scans",
                json=payload,
                headers=headers,
                timeout=self.scanner_config.INTERNAL_SCANNER_TIMEOUT
            )

            if response.status_code == 200:
                result = response.json()
                return result.get("scan_id")
            else:
                logger.error(
                    f"Scanner API call failed: {response.status_code} - {response.text}"
                )
                return None

        except Exception as e:
            logger.exception(f"Failed to call scanner API: {e}")
            return None

    def _poll_scan_status(self, scan_id: str) -> Optional[Dict[str, Any]]:
        start_time = time.time()
        headers = {
            "X-API-Key": self.scanner_config.INTERNAL_SCANNER_API_KEY
        }

        while time.time() - start_time < self.timeout:
            try:
                response = requests.get(
                    f"{self.scanner_config.INTERNAL_SCANNER_API_URL}/scans/{scan_id}/status",
                    headers=headers,
                    timeout=self.scanner_config.INTERNAL_SCANNER_TIMEOUT
                )

                if response.status_code == 200:
                    result = response.json()
                    status = result.get("status")

                    if status == "completed":
                        return result
                    elif status == "failed":
                        logger.error(f"Scan {scan_id} failed: {result.get('error')}")
                        return None

                time.sleep(self.poll_interval)

            except Exception as e:
                logger.exception(f"Error polling scan status: {e}")
                time.sleep(self.poll_interval)

        logger.error(f"Scan {scan_id} timed out after {self.timeout} seconds")
        return None

    def _parse_scan_result(self, scan_result: Dict[str, Any],
                           vuln_instance: VulnerabilityInstance) -> Tuple[bool, str, Optional[str]]:
        try:
            findings = scan_result.get("findings", [])
            vulnerability = vuln_instance.vulnerability

            vuln_found = False
            evidence = None

            for finding in findings:
                if (finding.get("cve_id") == vulnerability.cve_id or
                    finding.get("vuln_id") == str(vulnerability.id) or
                    vulnerability.title.lower() in finding.get("title", "").lower()):
                    vuln_found = True
                    evidence = finding.get("evidence") or finding.get("description")
                    break

            if vuln_found:
                return False, f"漏洞仍然存在，扫描检测到相关漏洞特征", evidence
            else:
                return True, f"扫描完成，未检测到该漏洞特征", None

        except Exception as e:
            logger.exception(f"Failed to parse scan result: {e}")
            return False, f"扫描结果解析失败: {str(e)}", None

    @with_session
    @with_log_context(operation_type="trigger_verification")
    def trigger_verification(self, work_order_id: int, operator: str = "system",
                             scan_type: str = SCAN_TYPE_QUICK,
                             manual_result: Optional[bool] = None,
                             manual_details: Optional[str] = None,
                             session: Session = None) -> Optional[VerificationResult]:
        try:
            work_order = session.query(WorkOrder).filter_by(id=work_order_id).first()
            if not work_order:
                logger.error(f"Work order {work_order_id} not found")
                return None

            if work_order.status != WorkOrderStatusEnum.FIXED:
                logger.error(
                    f"Cannot trigger verification for work order {work_order_id}: "
                    f"invalid status {work_order.status.value}"
                )
                return None

            vuln_instance = work_order.vuln_instance
            if not vuln_instance:
                logger.error(f"Vulnerability instance not found for work order {work_order_id}")
                return None

            self.status_manager.update_status(
                work_order_id, WorkOrderStatusEnum.VERIFYING, operator,
                reason=f"触发{scan_type}验证扫描", session=session
            )

            log_audit(
                action="verification_trigger",
                resource_type="work_order",
                resource_id=str(work_order_id),
                detail=f"触发{scan_type}验证扫描，漏洞实例: {vuln_instance.id}",
                user=operator
            )

            logger.info(
                f"Verification triggered for work order {work_order_id}, "
                f"vuln_instance {vuln_instance.id}, scan_type: {scan_type}"
            )

            if scan_type == SCAN_TYPE_MANUAL:
                if manual_result is None:
                    raise ValueError("Manual verification requires manual_result")

                result = VerificationResult(
                    vuln_instance_id=vuln_instance.id,
                    is_fixed=manual_result,
                    scan_type=SCAN_TYPE_MANUAL,
                    details=manual_details or "手动验证",
                    operator=operator
                )

                self.notification_service.send_status_change_notification(
                    work_order,
                    WorkOrderStatusEnum.FIXED.value,
                    WorkOrderStatusEnum.VERIFYING.value,
                    operator,
                    f"手动验证已提交，结果: {'通过' if manual_result else '未通过'}"
                )

                return result

            scan_id = self._call_scanner_api(vuln_instance, scan_type)
            if not scan_id:
                logger.error(f"Failed to start scan for work order {work_order_id}")
                self.status_manager.update_status(
                    work_order_id, WorkOrderStatusEnum.FIXED, operator,
                    reason="扫描启动失败，回退至已修复状态", session=session
                )
                return None

            logger.info(f"Scan started for work order {work_order_id}, scan_id: {scan_id}")

            scan_result = self._poll_scan_status(scan_id)
            if not scan_result:
                logger.error(f"Scan failed or timed out for work order {work_order_id}")
                self.status_manager.update_status(
                    work_order_id, WorkOrderStatusEnum.FIXED, operator,
                    reason="扫描失败或超时，回退至已修复状态", session=session
                )
                return None

            is_fixed, details, evidence = self._parse_scan_result(scan_result, vuln_instance)

            result = VerificationResult(
                vuln_instance_id=vuln_instance.id,
                is_fixed=is_fixed,
                scan_type=scan_type,
                scan_id=scan_id,
                details=details,
                evidence=evidence,
                operator=operator
            )

            return result

        except Exception as e:
            logger.exception(f"Failed to trigger verification for work order {work_order_id}: {e}")
            raise

    def mock_scan_result(self, vuln_instance_id: int,
                         success_rate: float = 0.7) -> VerificationResult:
        is_fixed = random.random() < success_rate
        scan_type = random.choice([SCAN_TYPE_QUICK, SCAN_TYPE_FULL])

        if is_fixed:
            details = "Mock验证通过：漏洞已修复，未检测到相关特征"
            evidence = None
        else:
            details = "Mock验证失败：漏洞仍然存在，检测到相关特征"
            evidence = "GET /vulnerable/path HTTP/1.1\nHost: target\n\nHTTP/1.1 200 OK\nVulnerable Code: yes"

        return VerificationResult(
            vuln_instance_id=vuln_instance_id,
            is_fixed=is_fixed,
            scan_type=scan_type,
            scan_id=f"mock_scan_{int(time.time())}",
            details=details,
            evidence=evidence,
            operator="mock_system"
        )


class VerificationProcessor:
    def __init__(self):
        self.status_manager = StatusManager()
        self.notification_service = NotificationService()
        self.review_manager = ReviewTaskManager()

    def _create_verification_record(self, result: VerificationResult,
                                    work_order_id: Optional[int],
                                    session: Session) -> VerificationRecord:
        record = VerificationRecord(
            vuln_instance_id=result.vuln_instance_id,
            work_order_id=work_order_id,
            scan_type=result.scan_type,
            scan_id=result.scan_id,
            is_fixed=result.is_fixed,
            details=result.details,
            evidence=result.evidence,
            operator=result.operator,
            verification_time=result.verification_time
        )
        session.add(record)
        session.flush()
        return record

    def _get_notification_recipients(self, work_order: WorkOrder,
                                     fail_count: int) -> List[str]:
        recipients = [work_order.assignee]

        if fail_count >= 1:
            recipients.append("security_supervisor@example.com")

        if fail_count >= 2:
            recipients.append("security_team@example.com")
            recipients.append("department_director@example.com")

        return list(set(recipients))

    def _send_verification_success_notification(self, work_order: WorkOrder,
                                                result: VerificationResult,
                                                session: Session):
        vuln_instance = work_order.vuln_instance
        vulnerability = vuln_instance.vulnerability if vuln_instance else None

        subject = f"【验证通过通知】工单 {work_order.id} 漏洞验证通过"

        content = f"""
您好，漏洞验证已通过：

工单编号: {work_order.id}
漏洞名称: {vulnerability.title if vulnerability else '未知漏洞'}
漏洞实例: {result.vuln_instance_id}
验证方式: {result.scan_type}
验证时间: {result.verification_time.strftime('%Y-%m-%d %H:%M:%S')}
验证结果: 漏洞已修复
验证详情: {result.details or '无'}

工单状态已更新为已关闭。
        """

        recipients = [work_order.assignee, result.operator]

        for recipient in recipients:
            for channel in config.notification.NOTIFICATION_CHANNELS:
                try:
                    if channel == "email":
                        email_addr = f"{recipient}@example.com" if "@" not in recipient else recipient
                        self.notification_service._send_with_retry(
                            self.notification_service._send_email,
                            email_addr, subject, content.strip()
                        )
                    elif channel == "dingtalk":
                        self.notification_service._send_with_retry(
                            self.notification_service._send_dingtalk,
                            config.notification.DINGTALK_WEBHOOK,
                            config.notification.DINGTALK_SECRET,
                            f"{subject}\n\n{content.strip()}"
                        )
                except Exception as e:
                    logger.error(f"Failed to send verification success notification: {e}")

    def _send_verification_failed_notification(self, work_order: WorkOrder,
                                               result: VerificationResult,
                                               fail_count: int,
                                               session: Session):
        vuln_instance = work_order.vuln_instance
        vulnerability = vuln_instance.vulnerability if vuln_instance else None

        subject = f"【验证失败通知】工单 {work_order.id} 第{fail_count}次验证失败"

        content = f"""
【重要】漏洞验证失败，请重新修复：

工单编号: {work_order.id}
漏洞名称: {vulnerability.title if vulnerability else '未知漏洞'}
漏洞实例: {result.vuln_instance_id}
验证方式: {result.scan_type}
验证时间: {result.verification_time.strftime('%Y-%m-%d %H:%M:%S')}
验证结果: 漏洞仍然存在
失败次数: {fail_count}
失败详情: {result.details or '无'}
{('验证证据: ' + result.evidence) if result.evidence else ''}

工单状态已回退至修复中，请尽快重新修复。
        """

        if fail_count == 1:
            content += "\n\n⚠️ 这是第1次验证失败，已通知负责人和安全主管。"
        elif fail_count >= 2:
            content += "\n\n⚠️⚠️ 这是第2次验证失败，将自动生成复盘任务，请安全团队分析原因。"

        recipients = self._get_notification_recipients(work_order, fail_count)

        for recipient in recipients:
            for channel in config.notification.NOTIFICATION_CHANNELS:
                try:
                    if channel == "email":
                        email_addr = f"{recipient}@example.com" if "@" not in recipient else recipient
                        self.notification_service._send_with_retry(
                            self.notification_service._send_email,
                            email_addr, subject, content.strip()
                        )
                    elif channel == "dingtalk":
                        self.notification_service._send_with_retry(
                            self.notification_service._send_dingtalk,
                            config.notification.DINGTALK_WEBHOOK,
                            config.notification.DINGTALK_SECRET,
                            f"{subject}\n\n{content.strip()}"
                        )
                except Exception as e:
                    logger.error(f"Failed to send verification failed notification: {e}")

    @with_session
    @with_log_context(operation_type="process_verification_result")
    def process_verification_result(self, vuln_instance_id: int, is_fixed: bool,
                                    details: Optional[str] = None,
                                    operator: str = "system",
                                    scan_type: str = SCAN_TYPE_QUICK,
                                    scan_id: Optional[str] = None,
                                    evidence: Optional[str] = None,
                                    session: Session = None) -> Optional[WorkOrder]:
        try:
            vuln_instance = session.query(VulnerabilityInstance).filter_by(
                id=vuln_instance_id
            ).first()

            if not vuln_instance:
                logger.error(f"Vulnerability instance {vuln_instance_id} not found")
                return None

            work_order = session.query(WorkOrder).filter(
                WorkOrder.vuln_instance_id == vuln_instance_id,
                WorkOrder.status.in_([
                    WorkOrderStatusEnum.VERIFYING,
                    WorkOrderStatusEnum.FIXED
                ])
            ).first()

            if not work_order:
                logger.error(
                    f"No active verifying/fixed work order found for "
                    f"vuln_instance {vuln_instance_id}"
                )
                return None

            result = VerificationResult(
                vuln_instance_id=vuln_instance_id,
                is_fixed=is_fixed,
                scan_type=scan_type,
                scan_id=scan_id,
                details=details,
                evidence=evidence,
                operator=operator
            )

            self._create_verification_record(result, work_order.id, session)

            vuln_instance.verify_count += 1
            vuln_instance.updated_at = datetime.now(timezone.utc)

            log_audit(
                action="verification_process",
                resource_type="vulnerability_instance",
                resource_id=str(vuln_instance_id),
                detail=f"验证结果: {'通过' if is_fixed else '失败'}, "
                       f"验证次数: {vuln_instance.verify_count}, "
                       f"详情: {details or '无'}",
                user=operator
            )

            if is_fixed:
                work_order.status = WorkOrderStatusEnum.CLOSED
                work_order.closed_at = datetime.now(timezone.utc)
                work_order.verified_at = result.verification_time
                work_order.current_stage_start = datetime.now(timezone.utc)

                vuln_instance.fix_status = FixStatusEnum.VERIFIED
                vuln_instance.verify_fail_count = 0

                log_audit(
                    action="work_order_close",
                    resource_type="work_order",
                    resource_id=str(work_order.id),
                    detail=f"验证通过，工单关闭，漏洞已修复",
                    user=operator
                )

                logger.info(
                    f"Verification passed for vuln_instance {vuln_instance_id}, "
                    f"work order {work_order.id} closed"
                )

                self._send_verification_success_notification(work_order, result, session)

            else:
                vuln_instance.verify_fail_count += 1
                fail_count = vuln_instance.verify_fail_count

                work_order.status = WorkOrderStatusEnum.FIXING
                work_order.current_stage_start = datetime.now(timezone.utc)

                if work_order.remarks:
                    work_order.remarks = (
                        f"{work_order.remarks}\n\n"
                        f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}] "
                        f"第{fail_count}次验证失败: {details or '无'}"
                    )
                else:
                    work_order.remarks = (
                        f"[{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')}] "
                        f"第{fail_count}次验证失败: {details or '无'}"
                    )

                log_audit(
                    action="verification_failed",
                    resource_type="work_order",
                    resource_id=str(work_order.id),
                    detail=f"第{fail_count}次验证失败，回退至修复中，原因: {details or '无'}",
                    user=operator
                )

                logger.warning(
                    f"Verification failed for vuln_instance {vuln_instance_id}, "
                    f"fail_count: {fail_count}, work order {work_order.id} "
                    f"reverted to fixing"
                )

                self._send_verification_failed_notification(
                    work_order, result, fail_count, session
                )

                if fail_count >= 2:
                    logger.info(
                        f"Verification failed {fail_count} times for "
                        f"vuln_instance {vuln_instance_id}, creating review task"
                    )
                    self.review_manager.create_review_task(
                        vuln_instance_id=vuln_instance_id,
                        reason=ReviewTaskReasonEnum.VERIFY_FAILED_TWICE,
                        assignees=["security_team"],
                        reason_detail=f"连续{fail_count}次验证失败: {details or '无'}",
                        operator=operator,
                        work_order_id=work_order.id,
                        session=session
                    )

            session.flush()
            return work_order

        except Exception as e:
            logger.exception(
                f"Failed to process verification result for "
                f"vuln_instance {vuln_instance_id}: {e}"
            )
            raise


class ReviewTaskManager:
    def __init__(self):
        self.status_flow = REVIEW_TASK_STATUS_FLOW
        self.notification_service = NotificationService()

    def _is_valid_transition(self, current_status: ReviewTaskStatusEnum,
                             new_status: ReviewTaskStatusEnum) -> bool:
        return new_status in self.status_flow.get(current_status, [])

    def _send_review_task_notification(self, review_task: ReviewTask,
                                       action: str, session: Session):
        vuln_instance = review_task.vuln_instance
        vulnerability = vuln_instance.vulnerability if vuln_instance else None
        work_order = review_task.work_order

        if action == "create":
            subject = f"【复盘任务通知】新复盘任务 #{review_task.id}"
            content = f"""
您好，有新的复盘任务需要处理：

复盘任务编号: {review_task.id}
触发原因: {review_task.reason.value}
原因详情: {review_task.reason_detail or '无'}
关联漏洞: {vulnerability.title if vulnerability else '未知漏洞'}
关联工单: {work_order.id if work_order else '无'}
指派人: {review_task.assignees}
截止日期: {review_task.deadline.strftime('%Y-%m-%d %H:%M:%S')}
创建人: {review_task.created_by}
创建时间: {review_task.created_at.strftime('%Y-%m-%d %H:%M:%S')}

请及时登录系统处理。
            """
        elif action == "timeout":
            subject = f"【复盘任务超时提醒】复盘任务 #{review_task.id} 已超时"
            content = f"""
【重要提醒】复盘任务已超时：

复盘任务编号: {review_task.id}
当前状态: {review_task.status.value}
触发原因: {review_task.reason.value}
截止日期: {review_task.deadline.strftime('%Y-%m-%d %H:%M:%S')}
指派人: {review_task.assignees}

请尽快完成复盘任务，超时将升级通知。
            """
        else:
            subject = f"【复盘任务状态更新】复盘任务 #{review_task.id}"
            content = f"""
复盘任务状态已更新：

复盘任务编号: {review_task.id}
新状态: {review_task.status.value}
触发原因: {review_task.reason.value}
指派人: {review_task.assignees}

请知悉。
            """

        assignees = review_task.assignees.split(",") if "," in review_task.assignees else [review_task.assignees]
        for assignee in assignees:
            assignee = assignee.strip()
            for channel in config.notification.NOTIFICATION_CHANNELS:
                try:
                    if channel == "email":
                        email_addr = f"{assignee}@example.com" if "@" not in assignee else assignee
                        self.notification_service._send_with_retry(
                            self.notification_service._send_email,
                            email_addr, subject, content.strip()
                        )
                    elif channel == "dingtalk":
                        self.notification_service._send_with_retry(
                            self.notification_service._send_dingtalk,
                            config.notification.DINGTALK_WEBHOOK,
                            config.notification.DINGTALK_SECRET,
                            f"{subject}\n\n{content.strip()}"
                        )
                except Exception as e:
                    logger.error(f"Failed to send review task notification: {e}")

    @with_session
    @with_log_context(operation_type="create_review_task")
    def create_review_task(self, vuln_instance_id: int,
                           reason: ReviewTaskReasonEnum,
                           assignees: List[str],
                           reason_detail: Optional[str] = None,
                           operator: str = "system",
                           work_order_id: Optional[int] = None,
                           session: Session = None) -> Optional[ReviewTask]:
        try:
            existing = session.query(ReviewTask).filter(
                ReviewTask.vuln_instance_id == vuln_instance_id,
                ReviewTask.status.in_([
                    ReviewTaskStatusEnum.PENDING_ANALYSIS,
                    ReviewTaskStatusEnum.IN_ANALYSIS
                ])
            ).first()

            if existing:
                logger.warning(
                    f"Active review task already exists for vuln_instance "
                    f"{vuln_instance_id}: task {existing.id}"
                )
                return existing

            deadline = datetime.now(timezone.utc) + timedelta(days=REVIEW_TASK_DEADLINE_DAYS)
            assignees_str = ",".join(assignees)

            review_task = ReviewTask(
                vuln_instance_id=vuln_instance_id,
                work_order_id=work_order_id,
                reason=reason,
                reason_detail=reason_detail,
                status=ReviewTaskStatusEnum.PENDING_ANALYSIS,
                assignees=assignees_str,
                deadline=deadline,
                created_by=operator
            )

            session.add(review_task)
            session.flush()

            log_audit(
                action="review_task_create",
                resource_type="review_task",
                resource_id=str(review_task.id),
                detail=f"创建复盘任务，原因: {reason.value}, "
                       f"指派人: {assignees_str}, 截止: {deadline}",
                user=operator
            )

            logger.info(
                f"Review task {review_task.id} created for "
                f"vuln_instance {vuln_instance_id}, reason: {reason.value}"
            )

            self._send_review_task_notification(review_task, "create", session)

            return review_task

        except Exception as e:
            logger.exception(
                f"Failed to create review task for vuln_instance "
                f"{vuln_instance_id}: {e}"
            )
            raise

    @with_session
    @with_log_context(operation_type="update_review_task_status")
    def update_review_task_status(self, task_id: int,
                                  new_status: ReviewTaskStatusEnum,
                                  analysis: Optional[Dict[str, Any]] = None,
                                  operator: str = "system",
                                  session: Session = None) -> Optional[ReviewTask]:
        try:
            review_task = session.query(ReviewTask).filter_by(id=task_id).first()
            if not review_task:
                logger.error(f"Review task {task_id} not found")
                return None

            old_status = review_task.status

            if not self._is_valid_transition(old_status, new_status):
                error_msg = (
                    f"Invalid status transition for review task {task_id}: "
                    f"{old_status.value} -> {new_status.value}"
                )
                logger.error(error_msg)
                raise ValueError(error_msg)

            if analysis:
                if "root_cause" in analysis:
                    review_task.root_cause = analysis["root_cause"]
                if "root_cause_category" in analysis:
                    review_task.root_cause_category = analysis["root_cause_category"]
                if "improvement_measures" in analysis:
                    review_task.improvement_measures = analysis["improvement_measures"]
                if "analysis_result" in analysis:
                    review_task.analysis_result = analysis["analysis_result"]

            now = datetime.now(timezone.utc)
            if new_status == ReviewTaskStatusEnum.COMPLETED:
                review_task.completed_at = now
            elif new_status == ReviewTaskStatusEnum.CONFIRMED:
                review_task.confirmed_at = now

            review_task.status = new_status
            review_task.updated_at = now

            log_audit(
                action="review_task_status_update",
                resource_type="review_task",
                resource_id=str(task_id),
                detail=f"状态变更: {old_status.value} -> {new_status.value}, "
                       f"分析内容: {json.dumps(analysis, ensure_ascii=False) if analysis else '无'}",
                user=operator
            )

            logger.info(
                f"Review task {task_id} status updated: "
                f"{old_status.value} -> {new_status.value} by {operator}"
            )

            self._send_review_task_notification(review_task, "update", session)

            return review_task

        except ValueError:
            raise
        except Exception as e:
            logger.exception(f"Failed to update review task {task_id}: {e}")
            raise

    @with_session
    @with_log_context(operation_type="check_and_create_review_tasks")
    def check_and_create_review_tasks(self, session: Session = None) -> List[ReviewTask]:
        created_tasks = []
        now = datetime.now(timezone.utc)

        logger.info("Checking conditions for automatic review task creation")

        try:
            high_risk_overdue = session.query(VulnerabilityInstance).join(
                Vulnerability, VulnerabilityInstance.vuln_id == Vulnerability.id
            ).filter(
                Vulnerability.severity.in_([SeverityEnum.CRITICAL, SeverityEnum.HIGH]),
                VulnerabilityInstance.fix_status.in_([
                    FixStatusEnum.PENDING,
                    FixStatusEnum.IN_PROGRESS
                ]),
                VulnerabilityInstance.fix_deadline < now - timedelta(hours=HIGH_RISK_OVERDUE_HOURS)
            ).all()

            logger.info(
                f"Found {len(high_risk_overdue)} high risk vuln instances "
                f"overdue > {HIGH_RISK_OVERDUE_HOURS}h"
            )

            for vuln_instance in high_risk_overdue:
                existing = session.query(ReviewTask).filter(
                    ReviewTask.vuln_instance_id == vuln_instance.id,
                    ReviewTask.reason == ReviewTaskReasonEnum.HIGH_RISK_OVERDUE,
                    ReviewTask.status.in_([
                        ReviewTaskStatusEnum.PENDING_ANALYSIS,
                        ReviewTaskStatusEnum.IN_ANALYSIS
                    ])
                ).first()

                if not existing:
                    work_order = session.query(WorkOrder).filter(
                        WorkOrder.vuln_instance_id == vuln_instance.id,
                        WorkOrder.status != WorkOrderStatusEnum.CLOSED
                    ).first()

                    task = self.create_review_task(
                        vuln_instance_id=vuln_instance.id,
                        reason=ReviewTaskReasonEnum.HIGH_RISK_OVERDUE,
                        assignees=["security_team", "risk_management"],
                        reason_detail=(
                            f"高危漏洞修复超时超过{HIGH_RISK_OVERDUE_HOURS}小时，"
                            f"截止日期: {vuln_instance.fix_deadline.strftime('%Y-%m-%d %H:%M:%S')}"
                        ),
                        operator="system",
                        work_order_id=work_order.id if work_order else None,
                        session=session
                    )
                    if task:
                        created_tasks.append(task)

            vuln_asset_counts = session.query(
                VulnerabilityInstance.vuln_id,
                func.count(VulnerabilityInstance.asset_id).label('asset_count')
            ).filter(
                VulnerabilityInstance.fix_status.in_([
                    FixStatusEnum.PENDING,
                    FixStatusEnum.IN_PROGRESS,
                    FixStatusEnum.FIXED
                ])
            ).group_by(
                VulnerabilityInstance.vuln_id
            ).having(
                func.count(VulnerabilityInstance.asset_id) >= WIDESPREAD_VULN_THRESHOLD
            ).all()

            logger.info(
                f"Found {len(vuln_asset_counts)} widespread vulnerabilities "
                f"affecting >= {WIDESPREAD_VULN_THRESHOLD} assets"
            )

            for vuln_id, asset_count in vuln_asset_counts:
                vuln_instances = session.query(VulnerabilityInstance).filter(
                    VulnerabilityInstance.vuln_id == vuln_id,
                    VulnerabilityInstance.fix_status.in_([
                        FixStatusEnum.PENDING,
                        FixStatusEnum.IN_PROGRESS,
                        FixStatusEnum.FIXED
                    ])
                ).all()

                for vuln_instance in vuln_instances:
                    existing = session.query(ReviewTask).filter(
                        ReviewTask.vuln_instance_id == vuln_instance.id,
                        ReviewTask.reason == ReviewTaskReasonEnum.WIDESPREAD_VULN,
                        ReviewTask.status.in_([
                            ReviewTaskStatusEnum.PENDING_ANALYSIS,
                            ReviewTaskStatusEnum.IN_ANALYSIS
                        ])
                    ).first()

                    if not existing:
                        work_order = session.query(WorkOrder).filter(
                            WorkOrder.vuln_instance_id == vuln_instance.id,
                            WorkOrder.status != WorkOrderStatusEnum.CLOSED
                        ).first()

                        task = self.create_review_task(
                            vuln_instance_id=vuln_instance.id,
                            reason=ReviewTaskReasonEnum.WIDESPREAD_VULN,
                            assignees=["security_architecture", "incident_response"],
                            reason_detail=(
                                f"该类漏洞在{asset_count}台资产上重复出现，"
                                f"需要分析根源并制定系统性解决方案"
                            ),
                            operator="system",
                            work_order_id=work_order.id if work_order else None,
                            session=session
                        )
                        if task:
                            created_tasks.append(task)

            logger.info(
                f"Auto-created {len(created_tasks)} review tasks from checks"
            )
            return created_tasks

        except Exception as e:
            logger.exception(f"Failed to check and create review tasks: {e}")
            raise

    @with_session
    @with_log_context(operation_type="check_review_task_timeout")
    def check_review_task_timeout(self, session: Session = None) -> List[ReviewTask]:
        now = datetime.now(timezone.utc)
        overdue_tasks = []

        try:
            tasks = session.query(ReviewTask).filter(
                ReviewTask.status.in_([
                    ReviewTaskStatusEnum.PENDING_ANALYSIS,
                    ReviewTaskStatusEnum.IN_ANALYSIS
                ]),
                ReviewTask.deadline < now
            ).all()

            for task in tasks:
                logger.warning(
                    f"Review task {task.id} is overdue, deadline: {task.deadline}, "
                    f"assignees: {task.assignees}"
                )
                self._send_review_task_notification(task, "timeout", session)
                overdue_tasks.append(task)

            logger.info(f"Found {len(overdue_tasks)} overdue review tasks")
            return overdue_tasks

        except Exception as e:
            logger.exception(f"Failed to check review task timeout: {e}")
            raise

    @with_session
    def mock_create_review_tasks(self, count: int = 5,
                                 session: Session = None) -> List[ReviewTask]:
        mock_tasks = []

        vuln_instances = session.query(VulnerabilityInstance).limit(count * 2).all()
        if not vuln_instances:
            logger.warning("No vulnerability instances found for mock review tasks")
            return mock_tasks

        reasons = list(ReviewTaskReasonEnum)
        assignee_options = [
            ["security_team"],
            ["security_supervisor"],
            ["security_architecture"],
            ["incident_response"],
            ["security_team", "risk_management"]
        ]

        for i in range(min(count, len(vuln_instances))):
            vuln_instance = vuln_instances[i]
            work_order = session.query(WorkOrder).filter(
                WorkOrder.vuln_instance_id == vuln_instance.id
            ).first()

            task = self.create_review_task(
                vuln_instance_id=vuln_instance.id,
                reason=random.choice(reasons),
                assignees=random.choice(assignee_options),
                reason_detail=f"Mock复盘任务 - 测试数据 #{i + 1}",
                operator="mock_system",
                work_order_id=work_order.id if work_order else None,
                session=session
            )
            if task:
                mock_tasks.append(task)

        logger.info(f"Created {len(mock_tasks)} mock review tasks")
        return mock_tasks


verification_scanner = VerificationScanner()
verification_processor = VerificationProcessor()
review_task_manager = ReviewTaskManager()
