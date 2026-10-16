"""
Unit tests for Production-Grade Crash Reporting and Exception Protection.
Verifies redaction of sensitive router tokens in stack traces, report persistence,
and non-destructive exception hook registration.
"""
import os
import sys
import threading


from netcutter.common.crash_handler import (
    _write_crash_report_file,
    global_exception_handler,
    install_crash_handler,
)
from netcutter.common.logging import redact_sensitive_text


def test_redact_sensitive_text_masks_credentials():
    sample = (
        "Connecting with password=SuperSecretPassword123 and token=abc123xyz789 "
        "using bearer secret_token_value_here to router."
    )
    sanitized = redact_sensitive_text(sample)
    assert "SuperSecretPassword123" not in sanitized
    assert "secret_token_value_here" not in sanitized
    assert "[REDACTED]" in sanitized or "token=[REDACTED]" in sanitized or "bearer [REDACTED]" in sanitized


def test_crash_report_file_generation(tmp_path, monkeypatch):
    monkeypatch.setenv("LOCALAPPDATA", str(tmp_path))

    tb_content = (
        "Traceback (most recent call last):\n"
        "  File 'test.py', line 10, in <module>\n"
        "    raise RuntimeError('Simulated unhandled network crash')\n"
        "RuntimeError: Simulated unhandled network crash\n"
    )

    report_path = _write_crash_report_file(tb_content)
    assert report_path.exists()
    content = report_path.read_text(encoding="utf-8")
    assert "Simulated unhandled network crash" in content
    assert "NetCutter Diagnostic Crash Log" in content


def test_install_crash_handler_idempotent():
    orig_hook = sys.excepthook
    orig_thread_hook = getattr(threading, "excepthook", None)

    try:
        install_crash_handler()
        hook1 = sys.excepthook
        install_crash_handler()
        hook2 = sys.excepthook
        assert hook1 == hook2
    finally:
        sys.excepthook = orig_hook
        if orig_thread_hook and hasattr(threading, "excepthook"):
            threading.excepthook = orig_thread_hook
