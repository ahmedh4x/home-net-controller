"""
Production-grade Crash Reporting, Unhandled Exception Protection, and Redaction.
Prevents unexplained silent crashes, logs full sanitized diagnostics, and presents safe recovery.
"""
from __future__ import annotations

import logging
import sys
import threading
import traceback
from datetime import datetime, timezone
from pathlib import Path

from netcutter.common.logging import redact_sensitive_text
from netcutter.common.paths import get_app_data_dir

logger = logging.getLogger("netcutter.crash")

_INSTALLED = False
_LOCK = threading.RLock()


def _write_crash_report_file(sanitized_traceback: str) -> Path:
    """Persist crash report to a timestamped file in AppData."""
    try:
        app_dir = get_app_data_dir()
        crash_dir = app_dir / "crash_reports"
        crash_dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        report_file = crash_dir / f"crash_{ts}.log"
        with open(report_file, "w", encoding="utf-8") as f:
            f.write(f"NetCutter Diagnostic Crash Log - {datetime.now(timezone.utc).isoformat()}\n")
            f.write("=" * 80 + "\n\n")
            f.write(sanitized_traceback + "\n")
        return report_file
    except Exception as ex:
        logger.error("Failed to persist crash report file: %s", ex)
        return app_dir / "crash.log"


def global_exception_handler(exc_type, exc_value, exc_traceback):
    """
    Top-level exception hook that catches unhandled Python exceptions,
    redacts sensitive router tokens, logs the failure, and offers graceful recovery.
    """
    if issubclass(exc_type, KeyboardInterrupt):
        sys.__excepthook__(exc_type, exc_value, exc_traceback)
        return

    tb_lines = traceback.format_exception(exc_type, exc_value, exc_traceback)
    raw_tb = "".join(tb_lines)
    sanitized_tb = redact_sensitive_text(raw_tb)

    with _LOCK:
        logger.critical("Unhandled application exception intercepted:\n%s", sanitized_tb)
        report_path = _write_crash_report_file(sanitized_tb)

    # Check if a Qt Application is active in the current process
    try:
        from PySide6.QtWidgets import QApplication, QMessageBox
        app = QApplication.instance()
        if app and getattr(app, "_gui_active", False):
            # Show a clean diagnostic message box rather than crashing out abruptly
            msg_box = QMessageBox()
            msg_box.setIcon(QMessageBox.Critical)
            msg_box.setWindowTitle("NetCutter Diagnostic Notice")
            msg_box.setText(
                f"An unexpected internal error occurred:\n<b>{redact_sensitive_text(str(exc_value))}</b>\n\n"
                f"A diagnostic report has been safely saved to:\n<code>{report_path}</code>"
            )
            msg_box.setDetailedText(sanitized_tb)
            msg_box.setStandardButtons(QMessageBox.Ok)
            msg_box.exec()
            return
    except Exception:
        pass

    # Print sanitized traceback to stderr for CLI / headless mode
    sys.stderr.write(f"\n[NetCutter Critical Error]\n{sanitized_tb}\n")


def thread_exception_handler(args):
    """Exception hook for background Python threads (Python 3.8+)."""
    global_exception_handler(args.exc_type, args.exc_value, args.exc_traceback)


def install_crash_handler():
    """Install global process and thread exception hooks."""
    global _INSTALLED
    with _LOCK:
        if _INSTALLED:
            return
        sys.excepthook = global_exception_handler
        if hasattr(threading, "excepthook"):
            threading.excepthook = thread_exception_handler
        _INSTALLED = True
        logger.info("High-assurance crash handlers and sanitized diagnostics registered.")
