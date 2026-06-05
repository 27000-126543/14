import os
from typing import Dict, List, Optional
from dataclasses import dataclass, field


@dataclass
class DatabaseConfig:
    DB_TYPE: str = os.getenv("DB_TYPE", "sqlite")
    DB_HOST: str = os.getenv("DB_HOST", "localhost")
    DB_PORT: int = int(os.getenv("DB_PORT", 5432))
    DB_USER: str = os.getenv("DB_USER", "admin")
    DB_PASSWORD: str = os.getenv("DB_PASSWORD", "password")
    DB_NAME: str = os.getenv("DB_NAME", "vuln_management")
    SQLITE_PATH: str = os.getenv("SQLITE_PATH", "./vuln_management.db")

    POOL_SIZE: int = int(os.getenv("DB_POOL_SIZE", 20))
    MAX_OVERFLOW: int = int(os.getenv("DB_MAX_OVERFLOW", 10))
    POOL_RECYCLE: int = int(os.getenv("DB_POOL_RECYCLE", 3600))
    POOL_PRE_PING: bool = os.getenv("DB_POOL_PRE_PING", "True") == "True"
    ECHO: bool = os.getenv("DB_ECHO", "False") == "True"

    def get_database_url(self) -> str:
        if self.DB_TYPE == "postgresql":
            return f"postgresql+psycopg2://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        elif self.DB_TYPE == "mysql":
            return f"mysql+pymysql://{self.DB_USER}:{self.DB_PASSWORD}@{self.DB_HOST}:{self.DB_PORT}/{self.DB_NAME}"
        else:
            return f"sqlite:///{self.SQLITE_PATH}"


@dataclass
class ScannerConfig:
    INTERNAL_SCANNER_API_URL: str = os.getenv("INTERNAL_SCANNER_API_URL", "")
    INTERNAL_SCANNER_API_KEY: str = os.getenv("INTERNAL_SCANNER_API_KEY", "")
    INTERNAL_SCANNER_TIMEOUT: int = int(os.getenv("INTERNAL_SCANNER_TIMEOUT", 30))

    EXTERNAL_THREAT_INTEL_API_URL: str = os.getenv("EXTERNAL_THREAT_INTEL_API_URL", "")
    EXTERNAL_THREAT_INTEL_API_KEY: str = os.getenv("EXTERNAL_THREAT_INTEL_API_KEY", "")
    EXTERNAL_THREAT_INTEL_TIMEOUT: int = int(os.getenv("EXTERNAL_THREAT_INTEL_TIMEOUT", 30))

    NESSUS_API_URL: str = os.getenv("NESSUS_API_URL", "")
    NESSUS_ACCESS_KEY: str = os.getenv("NESSUS_ACCESS_KEY", "")
    NESSUS_SECRET_KEY: str = os.getenv("NESSUS_SECRET_KEY", "")

    OPENVAS_API_URL: str = os.getenv("OPENVAS_API_URL", "")
    OPENVAS_USERNAME: str = os.getenv("OPENVAS_USERNAME", "")
    OPENVAS_PASSWORD: str = os.getenv("OPENVAS_PASSWORD", "")

    def use_mock_scanner(self) -> bool:
        return not self.INTERNAL_SCANNER_API_KEY or config.TEST_MODE

    def use_mock_threat_intel(self) -> bool:
        return not self.EXTERNAL_THREAT_INTEL_API_KEY or config.TEST_MODE


@dataclass
class NotificationConfig:
    SMTP_HOST: str = os.getenv("SMTP_HOST", "smtp.example.com")
    SMTP_PORT: int = int(os.getenv("SMTP_PORT", 587))
    SMTP_USERNAME: str = os.getenv("SMTP_USERNAME", "")
    SMTP_PASSWORD: str = os.getenv("SMTP_PASSWORD", "")
    SMTP_USE_TLS: bool = os.getenv("SMTP_USE_TLS", "True") == "True"
    SMTP_FROM: str = os.getenv("SMTP_FROM", "security@example.com")

    DINGTALK_WEBHOOK: str = os.getenv("DINGTALK_WEBHOOK", "")
    DINGTALK_SECRET: str = os.getenv("DINGTALK_SECRET", "")

    WECHAT_WEBHOOK: str = os.getenv("WECHAT_WEBHOOK", "")

    FEISHU_WEBHOOK: str = os.getenv("FEISHU_WEBHOOK", "")

    NOTIFICATION_CHANNELS: List[str] = field(default_factory=lambda: ["email", "dingtalk", "wechat"])

    def use_mock_notification(self) -> bool:
        all_empty = (not self.SMTP_USERNAME and not self.DINGTALK_WEBHOOK
                     and not self.WECHAT_WEBHOOK and not self.FEISHU_WEBHOOK)
        return all_empty or config.TEST_MODE

    def get_enabled_channels(self) -> List[str]:
        if config.TEST_MODE:
            return []
        channels = []
        if self.SMTP_USERNAME:
            channels.append("email")
        if self.DINGTALK_WEBHOOK:
            channels.append("dingtalk")
        if self.WECHAT_WEBHOOK:
            channels.append("wechat")
        if self.FEISHU_WEBHOOK:
            channels.append("feishu")
        return channels


@dataclass
class RiskAssessmentConfig:
    ASSET_IMPORTANCE_WEIGHT: float = float(os.getenv("ASSET_IMPORTANCE_WEIGHT", 0.4))
    VULN_SEVERITY_WEIGHT: float = float(os.getenv("VULN_SEVERITY_WEIGHT", 0.6))

    SEVERITY_SCORES: Dict[str, int] = field(default_factory=lambda: {
        "critical": 10,
        "high": 7,
        "medium": 4,
        "low": 1
    })

    RISK_LEVEL_THRESHOLDS: Dict[str, int] = field(default_factory=lambda: {
        "critical": 9,
        "high": 7,
        "medium": 4,
        "low": 0
    })


@dataclass
class WorkOrderConfig:
    DEADLINE_HOURS: Dict[str, int] = field(default_factory=lambda: {
        "critical": 24,
        "high": 24,
        "medium": 72,
        "low": 168
    })

    VERIFY_MAX_RETRY: int = int(os.getenv("VERIFY_MAX_RETRY", 2))

    ESCALATION_LEVELS: List[str] = field(default_factory=lambda: [
        "assignee",
        "supervisor",
        "director",
        "ciso"
    ])

    ESCALATION_HOURS: Dict[str, Dict[str, int]] = field(default_factory=lambda: {
        "critical": {"supervisor": 4, "director": 8, "ciso": 12},
        "high": {"supervisor": 8, "director": 16, "ciso": 24},
        "medium": {"supervisor": 24, "director": 48, "ciso": 72},
        "low": {"supervisor": 72, "director": 120, "ciso": 168}
    })


@dataclass
class SchedulerConfig:
    DAILY_SCAN_TIME: str = os.getenv("DAILY_SCAN_TIME", "02:00")
    WEEKLY_SCAN_DAY: str = os.getenv("WEEKLY_SCAN_DAY", "sunday")
    WEEKLY_SCAN_TIME: str = os.getenv("WEEKLY_SCAN_TIME", "01:00")

    DAILY_REPORT_TIME: str = os.getenv("DAILY_REPORT_TIME", "08:00")
    WEEKLY_REPORT_DAY: str = os.getenv("WEEKLY_REPORT_DAY", "monday")
    WEEKLY_REPORT_TIME: str = os.getenv("WEEKLY_REPORT_TIME", "09:00")

    VULN_SYNC_INTERVAL_MINUTES: int = int(os.getenv("VULN_SYNC_INTERVAL_MINUTES", 60))
    DEADLINE_CHECK_INTERVAL_MINUTES: int = int(os.getenv("DEADLINE_CHECK_INTERVAL_MINUTES", 30))


@dataclass
class ConcurrencyConfig:
    BATCH_INSERT_SIZE: int = int(os.getenv("BATCH_INSERT_SIZE", 1000))
    BATCH_UPDATE_SIZE: int = int(os.getenv("BATCH_UPDATE_SIZE", 500))

    THREAD_POOL_SIZE: int = int(os.getenv("THREAD_POOL_SIZE", 10))
    MAX_WORKERS: int = int(os.getenv("MAX_WORKERS", 20))

    SCAN_CONCURRENCY: int = int(os.getenv("SCAN_CONCURRENCY", 5))
    NOTIFICATION_CONCURRENCY: int = int(os.getenv("NOTIFICATION_CONCURRENCY", 3))


@dataclass
class LogConfig:
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_DIR: str = os.getenv("LOG_DIR", "./logs")
    LOG_FILE: str = os.getenv("LOG_FILE", "vuln_management.log")
    AUDIT_LOG_FILE: str = os.getenv("AUDIT_LOG_FILE", "audit.log")

    LOG_MAX_BYTES: int = int(os.getenv("LOG_MAX_BYTES", 10485760))
    LOG_BACKUP_COUNT: int = int(os.getenv("LOG_BACKUP_COUNT", 30))

    CONSOLE_OUTPUT: bool = os.getenv("CONSOLE_OUTPUT", "True") == "True"
    FILE_OUTPUT: bool = os.getenv("FILE_OUTPUT", "True") == "True"


@dataclass
class SecurityConfig:
    SECRET_KEY: str = os.getenv("SECRET_KEY", "your-secret-key-here-change-in-production")
    TOKEN_EXPIRE_HOURS: int = int(os.getenv("TOKEN_EXPIRE_HOURS", 24))
    PASSWORD_HASH_ITERATIONS: int = int(os.getenv("PASSWORD_HASH_ITERATIONS", 100000))

    SESSION_TIMEOUT_MINUTES: int = int(os.getenv("SESSION_TIMEOUT_MINUTES", 30))
    MAX_LOGIN_ATTEMPTS: int = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
    LOCKOUT_MINUTES: int = int(os.getenv("LOCKOUT_MINUTES", 30))


@dataclass
class AppConfig:
    TEST_MODE: bool = os.getenv("TEST_MODE", "True") == "True"

    database: DatabaseConfig = field(default_factory=DatabaseConfig)
    scanner: ScannerConfig = field(default_factory=ScannerConfig)
    notification: NotificationConfig = field(default_factory=NotificationConfig)
    risk_assessment: RiskAssessmentConfig = field(default_factory=RiskAssessmentConfig)
    work_order: WorkOrderConfig = field(default_factory=WorkOrderConfig)
    scheduler: SchedulerConfig = field(default_factory=SchedulerConfig)
    concurrency: ConcurrencyConfig = field(default_factory=ConcurrencyConfig)
    log: LogConfig = field(default_factory=LogConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)

    APP_NAME: str = "Enterprise Vulnerability Management System"
    APP_VERSION: str = "1.0.0"
    DEBUG: bool = os.getenv("DEBUG", "False") == "True"

    WEB_HOST: str = os.getenv("WEB_HOST", "0.0.0.0")
    WEB_PORT: int = int(os.getenv("WEB_PORT", 5000))
    WEB_CORS_ORIGINS: List[str] = field(default_factory=lambda: ["*"])

    REPORT_OUTPUT_DIR: str = os.getenv("REPORT_OUTPUT_DIR", "./reports")
    EXPORT_TEMP_DIR: str = os.getenv("EXPORT_TEMP_DIR", "./temp")

    def is_test_mode(self) -> bool:
        return self.TEST_MODE


config = AppConfig()
