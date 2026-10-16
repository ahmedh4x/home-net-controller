"""
Structured Logging, Sensitive Data Redaction, and Diagnostic Support Bundling.
Provides thread-safe in-memory ring buffer for the GUI log viewer and bounded rotating log files.
"""
from __future__ import annotations

import collections
import io
import json
import logging
import os
import platform
import re
import sys
import threading
import zipfile
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from logging.handlers import RotatingFileHandler
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional
from netcutter.common.paths import get_app_data_dir


# Regex patterns to detect and scrub sensitive data from logs and diagnostics
SENSITIVE_PATTERNS = [
    (re.compile(r"(password['\"]?\s*[:=]\s*['\"]?)([^'\"\s,\}]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(secret['\"]?\s*[:=]\s*['\"]?)([^'\"\s,\}]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(token['\"]?\s*[:=]\s*['\"]?)([^'\"\s,\}]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(Bearer\s+)([a-zA-Z0-9_\-\.]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(auth_secret_id['\"]?\s*[:=]\s*['\"]?)([^'\"\s,\}]+)", re.IGNORECASE), r"\1[REDACTED]"),
    (re.compile(r"(private_key|privkey|id_rsa)['\"]?\s*[:=]\s*['\"]?([^'\"\s,\}]+)", re.IGNORECASE), r"\1:[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]+PRIVATE KEY-----[\s\S]+?-----END [A-Z ]+PRIVATE KEY-----"), r"[REDACTED PRIVATE KEY]"),
]


def redact_sensitive_text(text: str) -> str:
    """Scrub passwords, keys, and tokens from any string."""
    if not isinstance(text, str):
        text = str(text)
    scrubbed = text
    for pattern, replacement in SENSITIVE_PATTERNS:
        scrubbed = pattern.sub(replacement, scrubbed)
    return scrubbed


class SensitiveDataFilter(logging.Filter):
    """Logging filter that scrubs sensitive information from all log records."""

    def filter(self, record: logging.LogRecord) -> bool:
        if record.msg and isinstance(record.msg, str):
            record.msg = redact_sensitive_text(record.msg)
        if record.args:
            if isinstance(record.args, dict):
                record.args = {k: redact_sensitive_text(str(v)) for k, v in record.args.items()}
            elif isinstance(record.args, (tuple, list)):
                record.args = tuple(redact_sensitive_text(str(a)) for a in record.args)
        return True


@dataclass
class LogEntry:
    """Structured log item stored in the in-memory buffer."""
    timestamp: str
    level: str
    logger_name: str
    message: str
    correlation_id: Optional[str] = None
    exception: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


class RingBufferLogHandler(logging.Handler):
    """
    Thread-safe in-memory ring buffer that retains the most recent log records
    for high-speed GUI display, querying, and live streaming.
    """

    def __init__(self, capacity: int = 2000):
        super().__init__()
        self.capacity = capacity
        self.buffer = collections.deque(maxlen=capacity)
        self._buf_lock = threading.RLock()
        self.listeners: List[Callable[[LogEntry], None]] = []

    def emit(self, record: logging.LogRecord):
        try:
            msg = self.format(record)
            correlation_id = getattr(record, "correlation_id", None)
            exc = None
            if record.exc_info:
                exc = self.formatter.formatException(record.exc_info) if self.formatter else str(record.exc_info)

            entry = LogEntry(
                timestamp=datetime.fromtimestamp(record.created, tz=timezone.utc).isoformat(),
                level=record.levelname,
                logger_name=record.name,
                message=msg,
                correlation_id=correlation_id,
                exception=exc,
            )

            with self._buf_lock:
                self.buffer.append(entry)

            for cb in list(self.listeners):
                try:
                    cb(entry)
                except Exception:
                    pass
        except Exception:
            self.handleError(record)

    def get_entries(
        self,
        level_filter: Optional[str] = None,
        search_query: Optional[str] = None,
        logger_filter: Optional[str] = None,
        limit: int = 500,
    ) -> List[LogEntry]:
        with self._buf_lock:
            items = list(self.buffer)

        results = []
        q = search_query.lower() if search_query else None
        lvl = level_filter.upper() if level_filter and level_filter.upper() != "ALL" else None
        lg = logger_filter.lower() if logger_filter and logger_filter.lower() != "all" else None

        for item in reversed(items):
            if lvl and item.level != lvl:
                continue
            if lg and lg not in item.logger_name.lower():
                continue
            if q and (q not in item.message.lower() and (not item.exception or q not in item.exception.lower())):
                continue
            results.append(item)
            if len(results) >= limit:
                break

        return results

    def clear(self):
        with self._buf_lock:
            self.buffer.clear()

    def add_listener(self, callback: Callable[[LogEntry], None]):
        self.listeners.append(callback)

    def remove_listener(self, callback: Callable[[LogEntry], None]):
        if callback in self.listeners:
            self.listeners.remove(callback)


# Global singleton handler for application logging
_ring_buffer_handler: Optional[RingBufferLogHandler] = None
_file_handler: Optional[RotatingFileHandler] = None


def get_ring_buffer() -> RingBufferLogHandler:
    global _ring_buffer_handler
    if _ring_buffer_handler is None:
        _ring_buffer_handler = RingBufferLogHandler(capacity=3000)
    return _ring_buffer_handler


def setup_application_logging(log_dir: Optional[Path] = None, log_level: int = logging.INFO) -> None:
    """Configures centralized logging with rotation, redaction filter, and GUI ring buffer."""
    global _ring_buffer_handler, _file_handler

    if log_dir is None:
        log_dir = get_app_data_dir() / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    log_file = log_dir / "netcutter.log"

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    formatter = logging.Formatter(
        fmt="%(asctime)s [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    redact_filter = SensitiveDataFilter()

    # 1. Rotating File Handler (Max 5MB x 5 backups)
    _file_handler = RotatingFileHandler(
        log_file, maxBytes=5 * 1024 * 1024, backupCount=5, encoding="utf-8"
    )
    _file_handler.setFormatter(formatter)
    _file_handler.addFilter(redact_filter)
    _file_handler.setLevel(log_level)

    # 2. In-Memory Ring Buffer Handler
    ring_handler = get_ring_buffer()
    ring_handler.setFormatter(formatter)
    ring_handler.addFilter(redact_filter)
    ring_handler.setLevel(log_level)

    # 3. Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    console_handler.addFilter(redact_filter)
    console_handler.setLevel(log_level)

    # Avoid duplicate handlers on re-initialization
    for h in list(root_logger.handlers):
        if isinstance(h, (RotatingFileHandler, RingBufferLogHandler, logging.StreamHandler)):
            root_logger.removeHandler(h)

    root_logger.addHandler(_file_handler)
    root_logger.addHandler(ring_handler)
    root_logger.addHandler(console_handler)

    # Suppress overly chatty third-party loggers
    logging.getLogger("paramiko.transport").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)


def generate_support_bundle(
    output_zip_path: Path,
    system_health_report: Optional[Dict[str, Any]] = None,
    include_recent_logs_count: int = 1500,
) -> Path:
    """
    Creates a sanitized diagnostic support bundle (.zip) with all secrets scrubbed.
    Contains:
    - sanitized_logs.txt
    - system_environment.json
    - health_diagnostics.json
    - manifest.json
    """
    output_zip_path.parent.mkdir(parents=True, exist_ok=True)
    ring = get_ring_buffer()
    recent_entries = ring.get_entries(limit=include_recent_logs_count)

    env_info = {
        "platform": platform.platform(),
        "python_version": platform.python_version(),
        "architecture": platform.machine(),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processor": platform.processor(),
    }

    manifest = {
        "generator": "NetCutter Diagnostic Engine",
        "version": "1.0.0-rc1",
        "redaction_applied": True,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "entries_included": len(recent_entries),
    }

    with zipfile.ZipFile(output_zip_path, "w", zipfile.ZIP_DEFLATED) as zf:
        # 1. Environment
        zf.writestr(
            "system_environment.json",
            json.dumps(env_info, indent=2),
        )

        # 2. Health Report
        if system_health_report:
            zf.writestr(
                "health_diagnostics.json",
                json.dumps(system_health_report, indent=2),
            )

        # 3. Sanitized Logs
        log_stream = io.StringIO()
        for item in reversed(recent_entries):
            line = f"{item.timestamp} [{item.level}] [{item.logger_name}] {item.message}\n"
            if item.exception:
                line += f"{item.exception}\n"
            log_stream.write(redact_sensitive_text(line))
        zf.writestr("sanitized_logs.txt", log_stream.getvalue())

        # 4. Manifest
        zf.writestr("manifest.json", json.dumps(manifest, indent=2))

    return output_zip_path
