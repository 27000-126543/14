#!/usr/bin/env python3
import os
import sys
import json
import time
import enum
import random
import argparse
import threading
import shutil
from datetime import datetime, timedelta, timezone
from typing import List, Dict, Any, Optional, Tuple
from dataclasses import dataclass, field

import psutil
import requests
from colorama import init, Fore, Style
from tqdm import tqdm
from apscheduler.schedulers.blocking import BlockingScheduler
from apscheduler.triggers.cron import CronTrigger
from apscheduler.triggers.interval import IntervalTrigger
from apscheduler.events import EVENT_JOB_EXECUTED, EVENT_JOB_ERROR
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from sqlalchemy.orm import Session
from sqlalchemy import func, and_, or_, text

from config import config
from database import db_manager, Base, engine
from logger import logger, log_audit, log_with_context, set_log_context
from models import (
    Asset, Vulnerability, VulnerabilityInstance, WorkOrder,
    SeverityEnum, VulnStatusEnum, FixStatusEnum, WorkOrderStatusEnum,
    Notification, NotificationTypeEnum, NotificationStatusEnum,
    Incident, IncidentStatusEnum, Report, ReportTypeEnum,
    ReviewTask, ReviewTaskStatusEnum, VerificationRecord,
    EscalationRecord
)

init(autoreset=True)


class CommandType(str, enum.Enum):
    INIT = "init"
    START = "start"
    STOP = "stop"
    STATUS = "status"
    RUN = "run"
    LIST_TASKS = "list-tasks"
    MOCK = "mock"
    TEST_NOTIFICATION = "test-notification"
    QUERY = "query"
    EXPORT = "export"


class TaskName(str, enum.Enum):
    VULNERABILITY_SCAN = "vulnerability_scan"
    RISK_ASSESSMENT = "risk_assessment"
    CREATE_WORK_ORDERS = "create_work_orders"
    CHECK_ESCALATION = "check_escalation"
    CHECK_UPCOMING_DEADLINES = "check_upcoming_deadlines"
    CHECK_REVIEW_TASKS = "check_review_tasks"
    CHECK_EMERGENCY_RESPONSE = "check_emergency_response"
    TRIGGER_VERIFICATION = "trigger_verification"
    DAILY_REPORT = "daily_report"
    WEEKLY_REPORT = "weekly_report"
    DATABASE_MAINTENANCE = "database_maintenance"


TASK_DESCRIPTIONS = {
    TaskName.VULNERABILITY_SCAN: "漏洞数据采集（全量扫描）",
    TaskName.RISK_ASSESSMENT: "风险评估和漏洞入库",
    TaskName.CREATE_WORK_ORDERS: "工单自动创建和分配",
    TaskName.CHECK_ESCALATION: "超时检测和升级通知",
    TaskName.CHECK_UPCOMING_DEADLINES: "即将到期提醒（提前2小时）",
    TaskName.CHECK_REVIEW_TASKS: "复盘任务检查",
    TaskName.CHECK_EMERGENCY_RESPONSE: "应急响应检查",
    TaskName.TRIGGER_VERIFICATION: "验证扫描触发",
    TaskName.DAILY_REPORT: "日报生成和推送",
    TaskName.WEEKLY_REPORT: "周报生成和推送",
    TaskName.DATABASE_MAINTENANCE: "数据库优化",
}


@dataclass
class HealthCheckResult:
    name: str
    status: bool
    message: str
    details: Dict[str, Any] = field(default_factory=dict)


@dataclass
class SystemStatus:
    database_status: bool
    scanner_api_status: bool
    threat_intel_status: bool
    email_status: bool
    webhook_status: bool
    disk_usage_percent: float
    memory_usage_percent: float
    cpu_usage_percent: float
    active_tasks: int
    pending_work_orders: int
    total_vulnerabilities: int
    scheduler_running: bool


class SystemInitializer:
    def __init__(self):
        self.required_dirs = ["logs", "reports", "data", "exports"]

    def create_directories(self) -> None:
        for dir_name in self.required_dirs:
            dir_path = os.path.join(os.getcwd(), dir_name)
            if not os.path.exists(dir_path):
                os.makedirs(dir_path, exist_ok=True)
                logger.info(f"创建目录: {dir_path}")
            else:
                logger.info(f"目录已存在: {dir_path}")

    def init_database(self) -> None:
        logger.info("开始初始化数据库连接...")
        try:
            Base.metadata.create_all(bind=engine)
            logger.info("数据库连接和表创建成功")
        except Exception as e:
            logger.error(f"数据库初始化失败: {e}")
            raise

    def create_tables(self) -> None:
        logger.info("数据表已在 init_database 中创建，跳过重复创建")

    def init_default_assets(self, session: Session) -> None:
        existing_count = session.query(func.count(Asset.id)).scalar()
        if existing_count > 0:
            logger.info(f"资产数据已存在，跳过初始化（现有 {existing_count} 条）")
            return

        default_assets = [
            {"name": "Web服务器-01", "ip": "192.168.1.10", "type": "web_server", "importance": 10,
             "owner": "user1", "department": "运维部", "description": "生产环境Web服务器"},
            {"name": "Web服务器-02", "ip": "192.168.1.11", "type": "web_server", "importance": 10,
             "owner": "user2", "department": "运维部", "description": "生产环境Web服务器"},
            {"name": "数据库服务器-01", "ip": "192.168.1.20", "type": "database", "importance": 10,
             "owner": "user4", "department": "运维部", "description": "主数据库服务器"},
            {"name": "应用服务器-01", "ip": "192.168.1.30", "type": "application", "importance": 8,
             "owner": "user7", "department": "研发部", "description": "业务应用服务器"},
            {"name": "应用服务器-02", "ip": "192.168.1.31", "type": "application", "importance": 8,
             "owner": "user8", "department": "研发部", "description": "业务应用服务器"},
            {"name": "测试服务器-01", "ip": "192.168.2.10", "type": "web_server", "importance": 5,
             "owner": "user11", "department": "测试部", "description": "测试环境服务器"},
            {"name": "开发服务器-01", "ip": "192.168.3.10", "type": "application", "importance": 3,
             "owner": "user13", "department": "产品部", "description": "开发环境服务器"},
        ]

        for asset_data in default_assets:
            asset = Asset(**asset_data)
            session.add(asset)

        logger.info(f"初始化默认资产数据 {len(default_assets)} 条")

    def init_default_users(self, session: Session) -> None:
        logger.info("用户数据初始化完成（用户数据在工单模块中配置）")

    def init_notification_config(self, session: Session) -> None:
        logger.info("通知配置初始化完成（配置在config模块中）")

    def init_default_data(self) -> None:
        logger.info("开始初始化默认数据...")
        try:
            with db_manager.get_session() as session:
                self.init_default_assets(session)
                self.init_default_users(session)
                self.init_notification_config(session)
            logger.info("默认数据初始化完成")
        except Exception as e:
            logger.warning(f"默认数据初始化失败（不影响系统启动）: {e}")

    def init_system(self) -> None:
        logger.info(f"{'='*60}")
        logger.info(f"{Fore.CYAN}开始系统初始化{Style.RESET_ALL}")
        logger.info(f"{'='*60}")

        self.create_directories()
        self.init_database()
        self.create_tables()
        self.init_default_data()

        logger.info(f"{'='*60}")
        logger.info(f"{Fore.GREEN}系统初始化完成{Style.RESET_ALL}")
        logger.info(f"{'='*60}")


class TaskScheduler:
    def __init__(self, facade: 'SystemFacade'):
        self.facade = facade
        self.scheduler = BlockingScheduler(timezone="Asia/Shanghai")
        self._task_locks: Dict[str, threading.Lock] = {}
        self._init_task_locks()
        self._register_event_listeners()

    def _init_task_locks(self) -> None:
        for task_name in TaskName:
            self._task_locks[task_name.value] = threading.Lock()

    def _register_event_listeners(self) -> None:
        self.scheduler.add_listener(self._on_job_executed, EVENT_JOB_EXECUTED)
        self.scheduler.add_listener(self._on_job_error, EVENT_JOB_ERROR)

    def _on_job_executed(self, event) -> None:
        job_id = event.job_id
        logger.info(f"任务执行完成: {job_id}")

    def _on_job_error(self, event) -> None:
        job_id = event.job_id
        exception = event.exception
        traceback = event.traceback
        logger.error(f"任务执行失败: {job_id}, 错误: {exception}\n{traceback}")

    def _execute_with_lock(self, task_name: str, func, *args, **kwargs) -> Any:
        lock = self._task_locks.get(task_name)
        if not lock:
            logger.error(f"未找到任务锁: {task_name}")
            return None

        acquired = False
        try:
            if not lock.acquire(blocking=False):
                logger.warning(f"任务 {task_name} 正在执行中，跳过本次执行")
                return None
            acquired = True

            logger.info(f"开始执行任务: {task_name} - {TASK_DESCRIPTIONS.get(TaskName(task_name), '未知任务')}")
            result = func(*args, **kwargs)
            logger.info(f"任务执行成功: {task_name}")
            return result
        except Exception as e:
            logger.error(f"任务执行异常: {task_name}, 错误: {e}")
            raise
        finally:
            if acquired:
                try:
                    lock.release()
                except Exception as e:
                    logger.warning(f"释放任务锁失败: {task_name}, 错误: {e}")

    @retry(stop=stop_after_attempt(3), wait=wait_exponential(multiplier=1, min=5, max=30),
           retry=retry_if_exception_type((Exception,)))
    def _execute_task_with_retry(self, task_name: str, func, *args, **kwargs) -> Any:
        return self._execute_with_lock(task_name, func, *args, **kwargs)

    def task_vulnerability_scan(self) -> None:
        self._execute_task_with_retry(
            TaskName.VULNERABILITY_SCAN.value,
            self.facade.run_full_scan
        )

    def task_risk_assessment(self) -> None:
        self._execute_task_with_retry(
            TaskName.RISK_ASSESSMENT.value,
            self.facade.process_new_vulns
        )

    def task_create_work_orders(self) -> None:
        from work_order import WorkOrderService
        self._execute_task_with_retry(
            TaskName.CREATE_WORK_ORDERS.value,
            WorkOrderService().auto_create_work_orders
        )

    def task_check_escalation(self) -> None:
        from work_order import WorkOrderService
        self._execute_task_with_retry(
            TaskName.CHECK_ESCALATION.value,
            WorkOrderService().check_and_escalate
        )

    def task_check_upcoming_deadlines(self) -> None:
        from work_order import WorkOrderService
        self._execute_task_with_retry(
            TaskName.CHECK_UPCOMING_DEADLINES.value,
            WorkOrderService().check_upcoming_deadlines,
            hours_before=2
        )

    def task_check_review_tasks(self) -> None:
        from verify import review_task_manager
        self._execute_task_with_retry(
            TaskName.CHECK_REVIEW_TASKS.value,
            review_task_manager.check_and_create_review_tasks
        )

    def task_check_emergency_response(self) -> None:
        from response import response_trigger
        self._execute_task_with_retry(
            TaskName.CHECK_EMERGENCY_RESPONSE.value,
            self._run_emergency_response_check
        )

    def _run_emergency_response_check(self) -> int:
        from database import db_manager
        from models import VulnerabilityInstance, FixStatusEnum
        from response import response_trigger
        with db_manager.get_session() as session:
            pending_instances = session.query(VulnerabilityInstance.id).filter(
                VulnerabilityInstance.fix_status == FixStatusEnum.PENDING
            ).all()
            ids = [r[0] for r in pending_instances]
        if ids:
            plans = response_trigger.check_and_trigger_response(ids, operator="system")
            return len(plans)
        return 0

    def task_trigger_verification(self) -> None:
        from verify import verification_scanner
        self._execute_task_with_retry(
            TaskName.TRIGGER_VERIFICATION.value,
            self._auto_trigger_verifications
        )

    def _auto_trigger_verifications(self) -> int:
        from database import db_manager
        from models import WorkOrder, WorkOrderStatusEnum
        from verify import verification_scanner
        with db_manager.get_session() as session:
            fixed_orders = session.query(WorkOrder).filter(
                WorkOrder.status == WorkOrderStatusEnum.FIXED
            ).limit(50).all()
            count = 0
            for wo in fixed_orders:
                try:
                    verification_scanner.trigger_verification(wo.id, operator="system", scan_type="quick")
                    count += 1
                except Exception as e:
                    logger.exception(f"Failed to trigger verification for WO {wo.id}: {e}")
        return count

    def task_daily_report(self) -> None:
        from reports import ReportManager
        self._execute_task_with_retry(
            TaskName.DAILY_REPORT.value,
            ReportManager().run_daily_report
        )

    def task_weekly_report(self) -> None:
        from reports import ReportManager
        self._execute_task_with_retry(
            TaskName.WEEKLY_REPORT.value,
            ReportManager().run_weekly_report
        )

    def task_database_maintenance(self) -> None:
        self._execute_task_with_retry(
            TaskName.DATABASE_MAINTENANCE.value,
            self._perform_database_maintenance
        )

    def _perform_database_maintenance(self) -> None:
        logger.info("开始数据库维护...")
        try:
            with db_manager.get_session() as session:
                db_manager.vacuum_analyze(session)
            logger.info("数据库维护完成")
        except Exception as e:
            logger.error(f"数据库维护失败: {e}")
            raise

    def _setup_jobs(self) -> None:
        self.scheduler.add_job(
            self.task_vulnerability_scan,
            trigger=CronTrigger(hour=2, minute=0),
            id=TaskName.VULNERABILITY_SCAN.value,
            name=TASK_DESCRIPTIONS[TaskName.VULNERABILITY_SCAN],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_risk_assessment,
            trigger=CronTrigger(hour=3, minute=0),
            id=TaskName.RISK_ASSESSMENT.value,
            name=TASK_DESCRIPTIONS[TaskName.RISK_ASSESSMENT],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_create_work_orders,
            trigger=CronTrigger(hour=3, minute=30),
            id=TaskName.CREATE_WORK_ORDERS.value,
            name=TASK_DESCRIPTIONS[TaskName.CREATE_WORK_ORDERS],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_check_escalation,
            trigger=IntervalTrigger(hours=1),
            id=TaskName.CHECK_ESCALATION.value,
            name=TASK_DESCRIPTIONS[TaskName.CHECK_ESCALATION],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_check_upcoming_deadlines,
            trigger=IntervalTrigger(hours=1),
            id=TaskName.CHECK_UPCOMING_DEADLINES.value,
            name=TASK_DESCRIPTIONS[TaskName.CHECK_UPCOMING_DEADLINES],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_check_review_tasks,
            trigger=IntervalTrigger(hours=2),
            id=TaskName.CHECK_REVIEW_TASKS.value,
            name=TASK_DESCRIPTIONS[TaskName.CHECK_REVIEW_TASKS],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_check_emergency_response,
            trigger=CronTrigger(hour=4, minute=0),
            id=TaskName.CHECK_EMERGENCY_RESPONSE.value,
            name=TASK_DESCRIPTIONS[TaskName.CHECK_EMERGENCY_RESPONSE],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_trigger_verification,
            trigger=CronTrigger(hour=5, minute=0),
            id=TaskName.TRIGGER_VERIFICATION.value,
            name=TASK_DESCRIPTIONS[TaskName.TRIGGER_VERIFICATION],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_daily_report,
            trigger=CronTrigger(hour=8, minute=0),
            id=TaskName.DAILY_REPORT.value,
            name=TASK_DESCRIPTIONS[TaskName.DAILY_REPORT],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_weekly_report,
            trigger=CronTrigger(day_of_week='mon', hour=9, minute=0),
            id=TaskName.WEEKLY_REPORT.value,
            name=TASK_DESCRIPTIONS[TaskName.WEEKLY_REPORT],
            replace_existing=True
        )

        self.scheduler.add_job(
            self.task_database_maintenance,
            trigger=CronTrigger(hour=1, minute=0),
            id=TaskName.DATABASE_MAINTENANCE.value,
            name=TASK_DESCRIPTIONS[TaskName.DATABASE_MAINTENANCE],
            replace_existing=True
        )

        logger.info("定时任务配置完成")

    def start(self) -> None:
        logger.info(f"{'='*60}")
        logger.info(f"{Fore.CYAN}启动定时任务调度器{Style.RESET_ALL}")
        logger.info(f"{'='*60}")

        self._setup_jobs()
        self.print_jobs()

        try:
            self.scheduler.start()
        except (KeyboardInterrupt, SystemExit):
            logger.info("调度器被用户中断")
            self.stop()

    def stop(self) -> None:
        logger.info(f"{Fore.YELLOW}正在停止调度器...{Style.RESET_ALL}")
        if self.scheduler.running:
            self.scheduler.shutdown(wait=True)
            logger.info(f"{Fore.GREEN}调度器已停止{Style.RESET_ALL}")
        else:
            logger.info("调度器未在运行")

    def print_jobs(self) -> None:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}已配置的定时任务:{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

        for job in self.scheduler.get_jobs():
            next_run = job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else 'N/A'
            print(f"  {Fore.GREEN}[{job.id}]{Style.RESET_ALL} {job.name}")
            print(f"    触发器: {job.trigger}")
            print(f"    下次执行: {next_run}")
            print()

    def run_task(self, task_name: str) -> Any:
        task_methods = {
            TaskName.VULNERABILITY_SCAN.value: self.task_vulnerability_scan,
            TaskName.RISK_ASSESSMENT.value: self.task_risk_assessment,
            TaskName.CREATE_WORK_ORDERS.value: self.task_create_work_orders,
            TaskName.CHECK_ESCALATION.value: self.task_check_escalation,
            TaskName.CHECK_UPCOMING_DEADLINES.value: self.task_check_upcoming_deadlines,
            TaskName.CHECK_REVIEW_TASKS.value: self.task_check_review_tasks,
            TaskName.CHECK_EMERGENCY_RESPONSE.value: self.task_check_emergency_response,
            TaskName.TRIGGER_VERIFICATION.value: self.task_trigger_verification,
            TaskName.DAILY_REPORT.value: self.task_daily_report,
            TaskName.WEEKLY_REPORT.value: self.task_weekly_report,
            TaskName.DATABASE_MAINTENANCE.value: self.task_database_maintenance,
        }

        method = task_methods.get(task_name)
        if not method:
            raise ValueError(f"未知任务: {task_name}")

        return method()

    def get_status(self) -> Dict[str, Any]:
        jobs = self.scheduler.get_jobs()
        job_status = []
        for job in jobs:
            job_status.append({
                "id": job.id,
                "name": job.name,
                "trigger": str(job.trigger),
                "next_run_time": job.next_run_time.strftime('%Y-%m-%d %H:%M:%S') if job.next_run_time else None,
                "pending": job.pending
            })

        return {
            "running": self.scheduler.running,
            "job_count": len(jobs),
            "jobs": job_status
        }


class SystemFacade:
    def __init__(self):
        self.initializer = SystemInitializer()

    def init_system(self) -> None:
        self.initializer.init_system()

    def run_full_scan(self) -> Dict[str, Any]:
        logger.info("执行完整扫描流程...")

        from collector import CollectorManager
        from risk_engine import VulnerabilityProcessor
        from work_order import WorkOrderService
        from work_order import NotificationService

        results = {}

        logger.info("步骤1: 漏洞数据采集")
        collector_manager = CollectorManager()
        scan_result = collector_manager.collect_all()
        results["scan"] = scan_result.to_dict()

        logger.info("步骤2: 风险评估和漏洞入库")
        processor = VulnerabilityProcessor()
        with db_manager.get_session() as session:
            raw_data = []
            if hasattr(scan_result, 'raw_data'):
                raw_data = scan_result.raw_data
            process_result = processor.process_vulnerabilities(raw_data, session=session)
        results["assessment"] = process_result.to_dict()

        logger.info("步骤3: 工单创建和分配")
        wo_service = WorkOrderService()
        wo_result = wo_service.auto_create_work_orders()
        results["work_orders"] = wo_result

        logger.info("步骤4: 发送通知")
        notification_service = NotificationService()
        notif_result = notification_service.notify_new_work_orders()
        results["notifications"] = notif_result

        logger.info("完整扫描流程完成")
        return results

    def process_new_vulns(self) -> Dict[str, Any]:
        logger.info("处理新采集的漏洞...")

        from risk_engine import VulnerabilityProcessor

        processor = VulnerabilityProcessor()

        results = {}

        raw_data = []
        try:
            process_result = processor.process_vulnerabilities(raw_data)
        except Exception as e:
            logger.warning(f"处理漏洞数据时发生错误（不影响系统运行）: {e}")
            from risk_engine import ProcessingResult
            process_result = ProcessingResult()
        results["processed"] = process_result.to_dict()

        logger.info(f"漏洞处理完成: 共 {process_result.total} 条，新增 {process_result.new} 条，更新 {process_result.updated} 条")
        return results

    def get_system_status(self) -> SystemStatus:
        disk_usage = psutil.disk_usage(os.getcwd())
        memory_usage = psutil.virtual_memory()
        cpu_usage = psutil.cpu_percent(interval=1)

        health_checks = self.health_check()
        db_status = next((h.status for h in health_checks if h.name == "database"), False)
        scanner_status = next((h.status for h in health_checks if h.name == "internal_scanner"), False)
        threat_intel_status = next((h.status for h in health_checks if h.name == "threat_intel"), False)
        email_status = next((h.status for h in health_checks if h.name == "email"), False)
        webhook_status = next((h.status for h in health_checks if h.name == "webhook"), False)

        with db_manager.get_session_no_commit() as session:
            pending_wo = session.query(func.count(WorkOrder.id)).filter(
                WorkOrder.status.in_([WorkOrderStatusEnum.PENDING, WorkOrderStatusEnum.FIXING])
            ).scalar()

            total_vulns = session.query(func.count(Vulnerability.id)).filter(
                Vulnerability.status == VulnStatusEnum.ACTIVE
            ).scalar()

        return SystemStatus(
            database_status=db_status,
            scanner_api_status=scanner_status,
            threat_intel_status=threat_intel_status,
            email_status=email_status,
            webhook_status=webhook_status,
            disk_usage_percent=disk_usage.percent,
            memory_usage_percent=memory_usage.percent,
            cpu_usage_percent=cpu_usage,
            active_tasks=0,
            pending_work_orders=pending_wo,
            total_vulnerabilities=total_vulns,
            scheduler_running=False
        )

    def get_dashboard_data(self) -> Dict[str, Any]:
        logger.info("获取仪表盘数据...")

        from reports import StatsEngine

        stats_engine = StatsEngine()
        with db_manager.get_session_no_commit() as session:
            daily_stats = stats_engine.get_daily_stats(session=session)
            severity_stats = stats_engine.get_severity_distribution(session=session)
            status_stats = stats_engine.get_status_distribution(session=session)
            trend_stats = stats_engine.get_trend_data(days=7, session=session)

        return {
            "daily_stats": daily_stats.to_dict() if daily_stats else None,
            "severity_distribution": severity_stats,
            "status_distribution": status_stats,
            "trend_data": [t.to_dict() for t in trend_stats] if trend_stats else [],
            "system_status": self.get_system_status().__dict__
        }

    def health_check(self) -> List[HealthCheckResult]:
        results = []

        results.append(self._check_database())
        results.append(self._check_internal_scanner())
        results.append(self._check_threat_intel())
        results.append(self._check_email())
        results.append(self._check_webhook())
        results.append(self._check_disk_space())

        return results

    def _check_database(self) -> HealthCheckResult:
        try:
            with db_manager.get_session() as session:
                session.execute(text("SELECT 1"))
            return HealthCheckResult(
                name="database",
                status=True,
                message="数据库连接正常",
                details={"type": config.database.DB_TYPE}
            )
        except Exception as e:
            return HealthCheckResult(
                name="database",
                status=False,
                message=f"数据库连接失败: {e}",
                details={"error": str(e)}
            )

    def _check_internal_scanner(self) -> HealthCheckResult:
        url = config.scanner.INTERNAL_SCANNER_API_URL

        if config.TEST_MODE or not url:
            return HealthCheckResult(
                name="internal_scanner",
                status=True,
                message="内部扫描器API（测试模式/未配置，跳过检测）",
                details={"test_mode": config.TEST_MODE, "configured": bool(url)}
            )

        try:
            api_key = config.scanner.INTERNAL_SCANNER_API_KEY
            timeout = config.scanner.INTERNAL_SCANNER_TIMEOUT

            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            response = requests.get(f"{url}/health", headers=headers, timeout=timeout)
            response.raise_for_status()

            return HealthCheckResult(
                name="internal_scanner",
                status=True,
                message="内部扫描器API连接正常",
                details={"url": url}
            )
        except Exception as e:
            return HealthCheckResult(
                name="internal_scanner",
                status=False,
                message=f"内部扫描器API连接失败: {e}",
                details={"error": str(e)}
            )

    def _check_threat_intel(self) -> HealthCheckResult:
        url = config.scanner.EXTERNAL_THREAT_INTEL_API_URL

        if config.TEST_MODE or not url:
            return HealthCheckResult(
                name="threat_intel",
                status=True,
                message="外部威胁情报API（测试模式/未配置，跳过检测）",
                details={"test_mode": config.TEST_MODE, "configured": bool(url)}
            )

        try:
            api_key = config.scanner.EXTERNAL_THREAT_INTEL_API_KEY
            timeout = config.scanner.EXTERNAL_THREAT_INTEL_TIMEOUT

            headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
            response = requests.get(f"{url}/health", headers=headers, timeout=timeout)
            response.raise_for_status()

            return HealthCheckResult(
                name="threat_intel",
                status=True,
                message="外部威胁情报API连接正常",
                details={"url": url}
            )
        except Exception as e:
            return HealthCheckResult(
                name="threat_intel",
                status=False,
                message=f"外部威胁情报API连接失败: {e}",
                details={"error": str(e)}
            )

    def _check_email(self) -> HealthCheckResult:
        host = config.notification.SMTP_HOST
        username = config.notification.SMTP_USERNAME
        password = config.notification.SMTP_PASSWORD

        if config.TEST_MODE or not host or not username or not password:
            return HealthCheckResult(
                name="email",
                status=True,
                message="邮件服务（测试模式/未配置，跳过检测）",
                details={"test_mode": config.TEST_MODE, "configured": bool(host and username and password)}
            )

        try:
            import smtplib
            from email.mime.text import MIMEText

            port = config.notification.SMTP_PORT
            use_tls = config.notification.SMTP_USE_TLS

            if use_tls:
                server = smtplib.SMTP(host, port, timeout=10)
                server.starttls()
            else:
                server = smtplib.SMTP_SSL(host, port, timeout=10)

            server.login(username, password)
            server.quit()

            return HealthCheckResult(
                name="email",
                status=True,
                message="邮件服务连接正常",
                details={"host": host, "port": port}
            )
        except Exception as e:
            return HealthCheckResult(
                name="email",
                status=False,
                message=f"邮件服务连接失败: {e}",
                details={"error": str(e)}
            )

    def _check_webhook(self) -> HealthCheckResult:
        webhooks = [
            ("dingtalk", config.notification.DINGTALK_WEBHOOK),
            ("wechat", config.notification.WECHAT_WEBHOOK),
            ("feishu", config.notification.FEISHU_WEBHOOK),
        ]

        any_configured = any(url for _, url in webhooks)

        if config.TEST_MODE or not any_configured:
            results = {}
            for name, url in webhooks:
                results[name] = {
                    "status": True,
                    "message": "测试模式/未配置，跳过检测" if not url else "测试模式，跳过检测"
                }
            return HealthCheckResult(
                name="webhook",
                status=True,
                message="Webhook服务（测试模式/未配置，跳过检测）",
                details={"test_mode": config.TEST_MODE, "configured": any_configured, "channels": results}
            )

        results = {}
        all_ok = False

        for name, url in webhooks:
            if not url:
                results[name] = {"status": False, "message": "未配置"}
                continue

            try:
                response = requests.post(
                    url,
                    json={"msgtype": "text", "text": {"content": "健康检查测试"}},
                    timeout=5
                )
                if response.status_code == 200:
                    results[name] = {"status": True, "message": "连接正常"}
                    all_ok = True
                else:
                    results[name] = {"status": False, "message": f"HTTP {response.status_code}"}
            except Exception as e:
                results[name] = {"status": False, "message": str(e)}

        return HealthCheckResult(
            name="webhook",
            status=all_ok,
            message="Webhook服务检查完成",
            details=results
        )

    def _check_disk_space(self) -> HealthCheckResult:
        try:
            disk_usage = psutil.disk_usage(os.getcwd())
            threshold = 90.0
            status = disk_usage.percent < threshold

            return HealthCheckResult(
                name="disk_space",
                status=status,
                message=f"磁盘使用率: {disk_usage.percent:.1f}%" if status else f"磁盘使用率过高: {disk_usage.percent:.1f}%",
                details={
                    "total_gb": round(disk_usage.total / (1024**3), 2),
                    "used_gb": round(disk_usage.used / (1024**3), 2),
                    "free_gb": round(disk_usage.free / (1024**3), 2),
                    "percent": disk_usage.percent,
                    "threshold": threshold
                }
            )
        except Exception as e:
            return HealthCheckResult(
                name="disk_space",
                status=False,
                message=f"磁盘检查失败: {e}",
                details={"error": str(e)}
            )


class MockDataGenerator:
    def __init__(self):
        self.severities = list(SeverityEnum)
        self.vuln_titles = [
            "SQL注入漏洞", "XSS跨站脚本漏洞", "远程代码执行漏洞",
            "目录遍历漏洞", "弱密码策略", "未授权访问漏洞",
            "CSRF跨站请求伪造", "SSRF服务端请求伪造",
            "信息泄露漏洞", "缓冲区溢出漏洞", "命令注入漏洞",
            "权限提升漏洞", "文件上传漏洞", "XXE外部实体注入",
            "反序列化漏洞"
        ]
        self.cwe_ids = ["CWE-78", "CWE-79", "CWE-89", "CWE-94", "CWE-200",
                        "CWE-264", "CWE-352", "CWE-434", "CWE-502", "CWE-611",
                        "CWE-732", "CWE-770"]

    def generate_mock_vulnerabilities(self, count: int) -> List[Dict[str, Any]]:
        mock_data = []

        with db_manager.get_session_no_commit() as session:
            assets = session.query(Asset).all()
            if not assets:
                raise ValueError("没有可用的资产数据，请先初始化系统")

        for i in tqdm(range(count), desc=f"{Fore.CYAN}生成Mock数据{Style.RESET_ALL}"):
            asset = random.choice(assets)
            severity = random.choices(
                self.severities,
                weights=[0.1, 0.25, 0.4, 0.25],
                k=1
            )[0]
            cvss_score = random.uniform(
                {"critical": 9.0, "high": 7.0, "medium": 4.0, "low": 0.1}[severity.value],
                {"critical": 10.0, "high": 8.9, "medium": 6.9, "low": 3.9}[severity.value]
            )

            days_ago = random.randint(0, 30)
            discovery_time = datetime.now(timezone.utc) - timedelta(days=days_ago, hours=random.randint(0, 23))

            vuln = {
                "cve_id": f"CVE-2024-{random.randint(1000, 99999)}" if random.random() > 0.3 else None,
                "title": random.choice(self.vuln_titles),
                "description": f"这是一个{severity.value}级别的漏洞，存在于{asset.name}服务器上。",
                "severity": severity.value,
                "cvss_score": round(cvss_score, 1),
                "cwe_id": random.choice(self.cwe_ids),
                "reference": f"https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2024-{random.randint(1000, 99999)}",
                "source": random.choice(["internal_scanner", "threat_intel", "manual_import"]),
                "affected_assets": [{
                    "ip": asset.ip,
                    "port": random.randint(1, 65535),
                    "protocol": random.choice(["tcp", "udp"]),
                    "location": f"/api/v{random.randint(1, 5)}/endpoint",
                }],
                "extra_data": {
                    "mock_data": True,
                    "generated_at": datetime.now(timezone.utc).isoformat()
                },
                "fetch_time": discovery_time
            }
            mock_data.append(vuln)
            time.sleep(0.01)

        return mock_data

    def insert_mock_data(self, count: int) -> Dict[str, Any]:
        from collector import VulnRawData
        from risk_engine import VulnerabilityProcessor

        logger.info(f"开始生成 {count} 条Mock漏洞数据...")

        mock_data = self.generate_mock_vulnerabilities(count)
        raw_data_list = [VulnRawData(**data) for data in mock_data]

        processor = VulnerabilityProcessor()
        result = processor.process_vulnerabilities(raw_data_list)

        logger.info(f"Mock数据生成完成: 新增 {result.new} 条，更新 {result.updated} 条")

        return result.to_dict()


class CLI:
    def __init__(self):
        self.facade = SystemFacade()
        self.scheduler = TaskScheduler(self.facade)
        self.mock_generator = MockDataGenerator()
        self.parser = self._create_parser()

    def _create_parser(self) -> argparse.ArgumentParser:
        parser = argparse.ArgumentParser(
            prog="vuln-management",
            description="企业级漏洞管理系统",
            formatter_class=argparse.RawDescriptionHelpFormatter,
            epilog="""
示例:
  python main.py init              # 初始化系统
  python main.py start             # 启动定时任务
  python main.py status            # 查看系统状态
  python main.py run vulnerability_scan  # 手动执行漏洞扫描
  python main.py mock 100          # 生成100条Mock数据
  python main.py query             # 交互式查询
  python main.py export            # 交互式导出
            """
        )

        subparsers = parser.add_subparsers(dest="command", help="可用命令")

        subparsers.add_parser("init", help="初始化系统")

        subparsers.add_parser("start", help="启动定时任务调度器")

        subparsers.add_parser("stop", help="停止调度器")

        subparsers.add_parser("status", help="查看调度器状态和任务列表")

        run_parser = subparsers.add_parser("run", help="手动执行指定任务")
        run_parser.add_argument("task_name", help="任务名称",
                               choices=[t.value for t in TaskName])

        subparsers.add_parser("list-tasks", help="列出所有可用任务")

        mock_parser = subparsers.add_parser("mock", help="生成Mock漏洞数据")
        mock_parser.add_argument("count", type=int, help="生成数量")

        subparsers.add_parser("test-notification", help="测试通知渠道")

        subparsers.add_parser("query", help="查询漏洞/工单/事件（交互式）")

        subparsers.add_parser("export", help="导出数据（交互式）")

        return parser

    def _print_header(self, title: str) -> None:
        print(f"\n{Fore.CYAN}{'='*60}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{title}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}{'='*60}{Style.RESET_ALL}")

    def cmd_init(self) -> None:
        self.facade.init_system()
        print(f"\n{Fore.GREEN}✓ 系统初始化完成{Style.RESET_ALL}")

    def cmd_start(self) -> None:
        self.scheduler.start()

    def cmd_stop(self) -> None:
        self.scheduler.stop()

    def cmd_status(self) -> None:
        self._print_header("系统状态")

        status = self.facade.get_system_status()
        scheduler_status = self.scheduler.get_status()

        print(f"\n{Fore.YELLOW}系统资源:{Style.RESET_ALL}")
        print(f"  CPU使用率: {Fore.GREEN if status.cpu_usage_percent < 70 else Fore.RED}{status.cpu_usage_percent:.1f}%{Style.RESET_ALL}")
        print(f"  内存使用率: {Fore.GREEN if status.memory_usage_percent < 70 else Fore.RED}{status.memory_usage_percent:.1f}%{Style.RESET_ALL}")
        print(f"  磁盘使用率: {Fore.GREEN if status.disk_usage_percent < 80 else Fore.RED}{status.disk_usage_percent:.1f}%{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}服务状态:{Style.RESET_ALL}")
        status_map = {True: f"{Fore.GREEN}✓ 正常{Style.RESET_ALL}", False: f"{Fore.RED}✗ 异常{Style.RESET_ALL}"}
        print(f"  数据库: {status_map[status.database_status]}")
        print(f"  内部扫描器API: {status_map[status.scanner_api_status]}")
        print(f"  威胁情报API: {status_map[status.threat_intel_status]}")
        print(f"  邮件服务: {status_map[status.email_status]}")
        print(f"  Webhook服务: {status_map[status.webhook_status]}")

        print(f"\n{Fore.YELLOW}业务数据:{Style.RESET_ALL}")
        print(f"  活跃漏洞: {status.total_vulnerabilities}")
        print(f"  待处理工单: {status.pending_work_orders}")

        print(f"\n{Fore.YELLOW}调度器状态:{Style.RESET_ALL}")
        print(f"  运行状态: {status_map[scheduler_status['running']]}")
        print(f"  任务数量: {scheduler_status['job_count']}")

        if scheduler_status['jobs']:
            print(f"\n{Fore.YELLOW}任务列表:{Style.RESET_ALL}")
            for job in scheduler_status['jobs']:
                next_run = job['next_run_time'] or 'N/A'
                print(f"  {Fore.CYAN}[{job['id']}]{Style.RESET_ALL} {job['name']}")
                print(f"    下次执行: {next_run}")

    def cmd_run(self, task_name: str) -> None:
        self._print_header(f"手动执行任务: {task_name}")
        try:
            result = self.scheduler.run_task(task_name)
            print(f"\n{Fore.GREEN}✓ 任务执行完成{Style.RESET_ALL}")
            if result:
                print(f"  结果: {json.dumps(result, ensure_ascii=False, indent=2)[:500]}")
        except Exception as e:
            print(f"\n{Fore.RED}✗ 任务执行失败: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def cmd_list_tasks(self) -> None:
        self._print_header("可用任务列表")
        for task in TaskName:
            desc = TASK_DESCRIPTIONS.get(task, "未知任务")
            print(f"  {Fore.CYAN}{task.value:<30}{Style.RESET_ALL} {desc}")

    def cmd_mock(self, count: int) -> None:
        self._print_header(f"生成 {count} 条Mock数据")
        try:
            result = self.mock_generator.insert_mock_data(count)
            print(f"\n{Fore.GREEN}✓ Mock数据生成完成{Style.RESET_ALL}")
            print(f"  总计处理: {result['total']}")
            print(f"  新增: {Fore.CYAN}{result['new']}{Style.RESET_ALL}")
            print(f"  更新: {Fore.YELLOW}{result['updated']}{Style.RESET_ALL}")
            print(f"  重复: {result['duplicate']}")
            print(f"  高风险: {Fore.RED}{result['high_risk']}{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}✗ 生成失败: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def cmd_test_notification(self) -> None:
        self._print_header("测试通知渠道")
        from work_order import NotificationService

        notification_service = NotificationService()

        print(f"\n{Fore.YELLOW}测试邮箱通知...{Style.RESET_ALL}")
        email_result = notification_service.send_test_email()
        print(f"  邮箱: {Fore.GREEN if email_result else Fore.RED}{'成功' if email_result else '失败'}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}测试钉钉通知...{Style.RESET_ALL}")
        dingtalk_result = notification_service.send_test_dingtalk()
        print(f"  钉钉: {Fore.GREEN if dingtalk_result else Fore.RED}{'成功' if dingtalk_result else '失败'}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}测试企业微信通知...{Style.RESET_ALL}")
        wechat_result = notification_service.send_test_wechat()
        print(f"  企业微信: {Fore.GREEN if wechat_result else Fore.RED}{'成功' if wechat_result else '失败'}{Style.RESET_ALL}")

        print(f"\n{Fore.YELLOW}测试飞书通知...{Style.RESET_ALL}")
        feishu_result = notification_service.send_test_feishu()
        print(f"  飞书: {Fore.GREEN if feishu_result else Fore.RED}{'成功' if feishu_result else '失败'}{Style.RESET_ALL}")

    def cmd_query(self) -> None:
        self._print_header("交互式查询")

        print(f"\n{Fore.YELLOW}请选择查询类型:{Style.RESET_ALL}")
        print("  1. 漏洞查询")
        print("  2. 工单查询")
        print("  3. 事件查询")
        print("  4. 全生命周期查询")

        choice = input(f"\n{Fore.CYAN}请输入选项 [1-4]: {Style.RESET_ALL}").strip()

        from incident import QueryEngine
        query_engine = QueryEngine()

        try:
            if choice == "1":
                results = self._query_vulnerabilities_interactive(query_engine)
            elif choice == "2":
                results = self._query_work_orders_interactive(query_engine)
            elif choice == "3":
                results = self._query_incidents_interactive(query_engine)
            elif choice == "4":
                results = self._query_lifecycle_interactive(query_engine)
            else:
                print(f"{Fore.RED}无效选项{Style.RESET_ALL}")
                return

            self._display_query_results(results)
        except Exception as e:
            print(f"\n{Fore.RED}查询失败: {e}{Style.RESET_ALL}")

    def _query_vulnerabilities_interactive(self, query_engine) -> List[Dict[str, Any]]:
        print(f"\n{Fore.YELLOW}漏洞查询条件（留空跳过）:{Style.RESET_ALL}")

        filters = {}
        filters["cve_id"] = input("  CVE ID: ").strip() or None
        filters["asset_ip"] = input("  资产IP: ").strip() or None
        filters["asset_name"] = input("  资产名称: ").strip() or None

        severity = input("  严重级别 (critical/high/medium/low): ").strip()
        filters["severity"] = severity if severity else None

        status = input("  状态 (active/mitigated/fixed/closed): ").strip()
        filters["status"] = status if status else None

        date_from = input("  开始日期 (YYYY-MM-DD): ").strip()
        date_to = input("  结束日期 (YYYY-MM-DD): ").strip()

        if date_from:
            filters["discovery_time_start"] = datetime.strptime(date_from, "%Y-%m-%d")
        if date_to:
            filters["discovery_time_end"] = datetime.strptime(date_to, "%Y-%m-%d") + timedelta(days=1)

        limit = input("  返回数量 (默认50): ").strip()
        limit = int(limit) if limit else 50

        from incident import QueryFilter
        query_filter = QueryFilter(**{k: v for k, v in filters.items() if v is not None})

        print(f"\n{Fore.CYAN}正在查询...{Style.RESET_ALL}")
        with db_manager.get_session_no_commit() as session:
            return query_engine.query_vulnerabilities(query_filter, limit=limit, session=session)

    def _query_work_orders_interactive(self, query_engine) -> List[Dict[str, Any]]:
        print(f"\n{Fore.YELLOW}工单查询条件（留空跳过）:{Style.RESET_ALL}")

        filters = {}
        filters["assignee"] = input("  处理人: ").strip() or None
        filters["department"] = input("  部门: ").strip() or None

        status = input("  状态 (pending/fixing/fixed/verifying/closed): ").strip()
        filters["status"] = status if status else None

        severity = input("  严重级别 (critical/high/medium/low): ").strip()
        filters["severity"] = severity if severity else None

        limit = input("  返回数量 (默认50): ").strip()
        limit = int(limit) if limit else 50

        from incident import QueryFilter
        query_filter = QueryFilter(**{k: v for k, v in filters.items() if v is not None})

        print(f"\n{Fore.CYAN}正在查询...{Style.RESET_ALL}")
        with db_manager.get_session_no_commit() as session:
            return query_engine.query_work_orders(query_filter, limit=limit, session=session)

    def _query_incidents_interactive(self, query_engine) -> List[Dict[str, Any]]:
        print(f"\n{Fore.YELLOW}事件查询条件（留空跳过）:{Style.RESET_ALL}")

        filters = {}
        filters["title"] = input("  事件标题: ").strip() or None

        type_choice = input("  事件类型 (data_breach/malware/unauthorized_access/dos_attack/phishing/other): ").strip()
        filters["incident_type"] = type_choice if type_choice else None

        status = input("  状态 (open/investigating/contained/eradicated/recovered/closed): ").strip()
        filters["status"] = status if status else None

        limit = input("  返回数量 (默认50): ").strip()
        limit = int(limit) if limit else 50

        from incident import QueryFilter
        query_filter = QueryFilter(**{k: v for k, v in filters.items() if v is not None})

        print(f"\n{Fore.CYAN}正在查询...{Style.RESET_ALL}")
        with db_manager.get_session_no_commit() as session:
            return query_engine.query_incidents(query_filter, limit=limit, session=session)

    def _query_lifecycle_interactive(self, query_engine) -> List[Dict[str, Any]]:
        print(f"\n{Fore.YELLOW}全生命周期查询:{Style.RESET_ALL}")
        vuln_instance_id = input("  漏洞实例ID: ").strip()

        if not vuln_instance_id:
            print(f"{Fore.RED}漏洞实例ID不能为空{Style.RESET_ALL}")
            return []

        print(f"\n{Fore.CYAN}正在查询...{Style.RESET_ALL}")
        with db_manager.get_session_no_commit() as session:
            return [query_engine.get_vulnerability_lifecycle(int(vuln_instance_id), session=session)]

    def _display_query_results(self, results: List[Dict[str, Any]]) -> None:
        if not results:
            print(f"\n{Fore.YELLOW}未查询到数据{Style.RESET_ALL}")
            return

        print(f"\n{Fore.GREEN}查询完成，共 {len(results)} 条记录{Style.RESET_ALL}")

        display_count = min(len(results), 20)
        for i, result in enumerate(results[:display_count], 1):
            print(f"\n{Fore.CYAN}[{i}]{Style.RESET_ALL} {json.dumps(result, ensure_ascii=False, indent=2)[:300]}...")

        if len(results) > 20:
            print(f"\n{Fore.YELLOW}... 还有 {len(results) - 20} 条记录{Style.RESET_ALL}")

        save = input(f"\n{Fore.CYAN}是否保存结果到JSON文件? (y/N): {Style.RESET_ALL}").strip().lower()
        if save == 'y':
            filename = f"query_result_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(results, f, ensure_ascii=False, indent=2, default=str)
            print(f"{Fore.GREEN}结果已保存到: {filename}{Style.RESET_ALL}")

    def cmd_export(self) -> None:
        self._print_header("交互式数据导出")

        print(f"\n{Fore.YELLOW}请选择导出类型:{Style.RESET_ALL}")
        print("  1. 漏洞数据")
        print("  2. 工单数据")
        print("  3. 事件数据")
        print("  4. 全量数据")

        choice = input(f"\n{Fore.CYAN}请输入选项 [1-4]: {Style.RESET_ALL}").strip()

        print(f"\n{Fore.YELLOW}请选择导出格式:{Style.RESET_ALL}")
        print("  1. Excel")
        print("  2. CSV")
        print("  3. JSON")

        fmt_choice = input(f"\n{Fore.CYAN}请输入格式 [1-3]: {Style.RESET_ALL}").strip()
        fmt_map = {"1": "excel", "2": "csv", "3": "json"}
        export_format = fmt_map.get(fmt_choice, "excel")

        from incident import ExportManager, ExportFormat, QueryType
        export_manager = ExportManager()

        query_type_map = {
            "1": QueryType.VULNERABILITIES,
            "2": QueryType.WORK_ORDERS,
            "3": QueryType.INCIDENTS,
            "4": QueryType.LIFECYCLE
        }

        try:
            query_type = query_type_map.get(choice)
            if not query_type:
                print(f"{Fore.RED}无效选项{Style.RESET_ALL}")
                return

            output_dir = os.path.join(os.getcwd(), "exports")
            os.makedirs(output_dir, exist_ok=True)

            from incident import QueryFilter
            query_filter = QueryFilter()

            print(f"\n{Fore.CYAN}正在导出{export_format.upper()}格式数据...{Style.RESET_ALL}")

            with db_manager.get_session() as session:
                if export_format == "excel":
                    result = export_manager.export_to_excel(query_type, query_filter, output_dir, session=session)
                elif export_format == "csv":
                    result = export_manager.export_to_csv(query_type, query_filter, output_dir, session=session)
                else:
                    result = export_manager.export_to_json(query_type, query_filter, output_dir, session=session)

            print(f"\n{Fore.GREEN}✓ 导出完成{Style.RESET_ALL}")
            print(f"  文件: {result.file_path}")
            print(f"  记录数: {result.record_count}")
            print(f"  文件大小: {result.file_size / 1024:.2f} KB")

        except Exception as e:
            print(f"\n{Fore.RED}✗ 导出失败: {e}{Style.RESET_ALL}")

    def run(self) -> None:
        args = self.parser.parse_args()

        if not args.command:
            self.parser.print_help()
            sys.exit(1)

        set_log_context(user="cli", operation_type=args.command, ip="127.0.0.1")

        try:
            if args.command == CommandType.INIT.value:
                self.cmd_init()
            elif args.command == CommandType.START.value:
                self.cmd_start()
            elif args.command == CommandType.STOP.value:
                self.cmd_stop()
            elif args.command == CommandType.STATUS.value:
                self.cmd_status()
            elif args.command == CommandType.RUN.value:
                self.cmd_run(args.task_name)
            elif args.command == CommandType.LIST_TASKS.value:
                self.cmd_list_tasks()
            elif args.command == CommandType.MOCK.value:
                self.cmd_mock(args.count)
            elif args.command == CommandType.TEST_NOTIFICATION.value:
                self.cmd_test_notification()
            elif args.command == CommandType.QUERY.value:
                self.cmd_query()
            elif args.command == CommandType.EXPORT.value:
                self.cmd_export()
            else:
                print(f"{Fore.RED}未知命令: {args.command}{Style.RESET_ALL}")
                self.parser.print_help()
                sys.exit(1)
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}操作被用户中断{Style.RESET_ALL}")
            sys.exit(0)
        except Exception as e:
            logger.error(f"命令执行失败: {e}", exc_info=True)
            print(f"\n{Fore.RED}错误: {e}{Style.RESET_ALL}")
            sys.exit(1)


def init_system() -> None:
    facade = SystemFacade()
    facade.init_system()


def start_scheduler() -> None:
    facade = SystemFacade()
    scheduler = TaskScheduler(facade)
    scheduler.start()


def stop_scheduler() -> None:
    facade = SystemFacade()
    scheduler = TaskScheduler(facade)
    scheduler.stop()


def run_task(task_name: str) -> Any:
    facade = SystemFacade()
    scheduler = TaskScheduler(facade)
    return scheduler.run_task(task_name)


def main() -> None:
    cli = CLI()
    cli.run()


if __name__ == "__main__":
    main()
