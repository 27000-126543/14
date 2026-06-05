import os
import sys
import logging
import json
import threading
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from logging.handlers import TimedRotatingFileHandler, RotatingFileHandler
from functools import wraps

from config import config


class ContextFilter(logging.Filter):
    def __init__(self):
        super().__init__()
        self._local = threading.local()

    def set_context(self, **kwargs):
        for key, value in kwargs.items():
            setattr(self._local, key, value)

    def clear_context(self):
        self._local.__dict__.clear()

    def get_context(self) -> Dict[str, Any]:
        return self._local.__dict__.copy()

    def filter(self, record):
        context = self.get_context()
        record.user = context.get("user", "system")
        record.operation_type = context.get("operation_type", "unknown")
        record.ip = context.get("ip", "unknown")
        record.request_id = context.get("request_id", "-")
        record.resource_type = context.get("resource_type", "-")
        record.resource_id = context.get("resource_id", "-")
        record.action = context.get("action", "unknown")
        record.detail = context.get("detail", "")
        return True


context_filter = ContextFilter()


class JsonFormatter(logging.Formatter):
    def format(self, record):
        log_entry = {
            "timestamp": datetime.fromtimestamp(record.created).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "message": record.getMessage(),
            "user": getattr(record, "user", "system"),
            "operation_type": getattr(record, "operation_type", "unknown"),
            "ip": getattr(record, "ip", "unknown"),
            "request_id": getattr(record, "request_id", "-"),
            "resource_type": getattr(record, "resource_type", "-"),
            "resource_id": getattr(record, "resource_id", "-"),
        }

        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        if hasattr(record, "extra_data"):
            log_entry["extra_data"] = record.extra_data

        return json.dumps(log_entry, ensure_ascii=False)


class ColoredFormatter(logging.Formatter):
    COLORS = {
        "DEBUG": "\033[36m",
        "INFO": "\033[32m",
        "WARNING": "\033[33m",
        "ERROR": "\033[31m",
        "CRITICAL": "\033[35m",
        "RESET": "\033[0m",
    }

    def format(self, record):
        levelname = record.levelname
        color = self.COLORS.get(levelname, self.COLORS["RESET"])
        reset = self.COLORS["RESET"]

        record.levelname = f"{color}{levelname}{reset}"
        record.msg = f"{color}{record.msg}{reset}"

        return super().format(record)


def _ensure_log_dir():
    log_dir = config.log.LOG_DIR
    if not os.path.exists(log_dir):
        os.makedirs(log_dir, exist_ok=True)


def _get_log_level() -> int:
    level_str = config.log.LOG_LEVEL.upper()
    return getattr(logging, level_str, logging.INFO)


def create_logger(name: str = "vuln_management") -> logging.Logger:
    _ensure_log_dir()

    logger = logging.getLogger(name)
    logger.setLevel(_get_log_level())
    logger.propagate = False

    if not logger.handlers:
        log_format = "%(asctime)s | %(levelname)-8s | %(user)s@%(ip)s | %(operation_type)s | %(request_id)s | %(name)s | %(message)s"
        date_format = "%Y-%m-%d %H:%M:%S"

        if config.log.FILE_OUTPUT:
            log_file = os.path.join(config.log.LOG_DIR, config.log.LOG_FILE)
            file_handler = TimedRotatingFileHandler(
                log_file,
                when="midnight",
                interval=1,
                backupCount=config.log.LOG_BACKUP_COUNT,
                encoding="utf-8"
            )
            file_handler.setLevel(_get_log_level())
            file_handler.setFormatter(JsonFormatter())
            file_handler.addFilter(context_filter)
            logger.addHandler(file_handler)

        if config.log.CONSOLE_OUTPUT:
            console_handler = logging.StreamHandler(sys.stdout)
            console_handler.setLevel(_get_log_level())
            console_formatter = ColoredFormatter(log_format, datefmt=date_format)
            console_handler.setFormatter(console_formatter)
            console_handler.addFilter(context_filter)
            logger.addHandler(console_handler)

    return logger


def create_audit_logger() -> logging.Logger:
    _ensure_log_dir()

    logger = logging.getLogger("audit")
    logger.setLevel(logging.INFO)
    logger.propagate = False

    if not logger.handlers:
        audit_file = os.path.join(config.log.LOG_DIR, config.log.AUDIT_LOG_FILE)
        file_handler = TimedRotatingFileHandler(
            audit_file,
            when="midnight",
            interval=1,
            backupCount=config.log.LOG_BACKUP_COUNT,
            encoding="utf-8"
        )
        file_handler.setLevel(logging.INFO)

        audit_format = "%(asctime)s | %(user)s | %(action)s | %(resource_type)s | %(resource_id)s | %(ip)s | %(detail)s"
        formatter = logging.Formatter(audit_format, datefmt="%Y-%m-%d %H:%M:%S")
        file_handler.setFormatter(formatter)
        file_handler.addFilter(context_filter)
        logger.addHandler(file_handler)

    return logger


def set_log_context(**kwargs):
    context_filter.set_context(**kwargs)


def clear_log_context():
    context_filter.clear_context()


def get_log_context() -> Dict[str, Any]:
    return context_filter.get_context()


def with_log_context(user: Optional[str] = None, operation_type: Optional[str] = None,
                     ip: Optional[str] = None, request_id: Optional[str] = None,
                     resource_type: Optional[str] = None, resource_id: Optional[str] = None):
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            context_kwargs = {}
            if user:
                context_kwargs["user"] = user
            if operation_type:
                context_kwargs["operation_type"] = operation_type
            if ip:
                context_kwargs["ip"] = ip
            if request_id:
                context_kwargs["request_id"] = request_id
            if resource_type:
                context_kwargs["resource_type"] = resource_type
            if resource_id:
                context_kwargs["resource_id"] = resource_id

            old_context = get_log_context()
            set_log_context(**context_kwargs)

            try:
                return func(*args, **kwargs)
            finally:
                context_filter.clear_context()
                if old_context:
                    set_log_context(**old_context)

        return wrapper
    return decorator


def log_audit(action: str, resource_type: str, resource_id: str, detail: str = "",
              user: Optional[str] = None, ip: Optional[str] = None):
    audit_logger = create_audit_logger()

    extra = {
        "action": action,
        "resource_type": resource_type,
        "resource_id": resource_id,
        "detail": detail,
    }
    if user:
        extra["user"] = user
    if ip:
        extra["ip"] = ip

    for key, value in extra.items():
        setattr(context_filter._local, key, value)

    audit_logger.info(detail)


def log_with_context(logger: logging.Logger, level: str, message: str, **kwargs):
    level = level.upper()
    log_func = getattr(logger, level.lower(), logger.info)

    if kwargs:
        extra = {"extra_data": kwargs}
        log_func(message, extra=extra)
    else:
        log_func(message)


logger = create_logger()
audit_logger = create_audit_logger()


class LoggerAdapter:
    def __init__(self, **context):
        self._context = context

    def _get_effective_context(self, extra_kwargs):
        context = self._context.copy()
        context.update(extra_kwargs)
        return context

    def debug(self, message: str, **kwargs):
        ctx = self._get_effective_context(kwargs)
        set_log_context(**ctx)
        logger.debug(message)

    def info(self, message: str, **kwargs):
        ctx = self._get_effective_context(kwargs)
        set_log_context(**ctx)
        logger.info(message)

    def warning(self, message: str, **kwargs):
        ctx = self._get_effective_context(kwargs)
        set_log_context(**ctx)
        logger.warning(message)

    def error(self, message: str, **kwargs):
        ctx = self._get_effective_context(kwargs)
        set_log_context(**ctx)
        logger.error(message)

    def critical(self, message: str, **kwargs):
        ctx = self._get_effective_context(kwargs)
        set_log_context(**ctx)
        logger.critical(message)

    def exception(self, message: str, **kwargs):
        ctx = self._get_effective_context(kwargs)
        set_log_context(**ctx)
        logger.exception(message)

    def audit(self, action: str, resource_type: str, resource_id: str, detail: str = "", **kwargs):
        ctx = self._get_effective_context(kwargs)
        log_audit(action, resource_type, resource_id, detail, **ctx)
