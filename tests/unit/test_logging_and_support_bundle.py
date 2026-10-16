"""
Unit tests for structured logging, redaction filter, in-memory ring buffer, and support bundles.
"""
import logging
import zipfile
from pathlib import Path
from netcutter.common.logging import (
    RingBufferLogHandler,
    SensitiveDataFilter,
    generate_support_bundle,
    redact_sensitive_text,
)


def test_sensitive_data_redaction():
    text = "Connecting with password='super_secret_123' and token='tok_abc123xyz' to router"
    scrubbed = redact_sensitive_text(text)
    assert "super_secret_123" not in scrubbed
    assert "tok_abc123xyz" not in scrubbed
    assert "[REDACTED]" in scrubbed


def test_private_key_redaction():
    key_block = "-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0...\n-----END RSA PRIVATE KEY-----"
    scrubbed = redact_sensitive_text(f"Loaded router SSH key: {key_block}")
    assert "MIIEowIBAAKCAQEA0" not in scrubbed
    assert "[REDACTED PRIVATE KEY]" in scrubbed


def test_ring_buffer_log_handler_filtering():
    handler = RingBufferLogHandler(capacity=10)
    formatter = logging.Formatter("%(message)s")
    handler.setFormatter(formatter)

    logger = logging.getLogger("test_logger")
    logger.addHandler(handler)
    logger.setLevel(logging.DEBUG)

    logger.debug("Debug msg")
    logger.info("Info msg containing apple")
    logger.warning("Warn msg containing banana")
    logger.error("Error msg containing apple")

    # Filter by level
    errors = handler.get_entries(level_filter="ERROR")
    assert len(errors) == 1
    assert "Error msg" in errors[0].message

    # Filter by search query
    apples = handler.get_entries(search_query="apple")
    assert len(apples) == 2


def test_diagnostic_support_bundle_creation(tmp_path: Path):
    zip_dest = tmp_path / "bundle.zip"
    health_mock = {"overall_status": "HEALTHY", "checks": {}}

    bundle_path = generate_support_bundle(zip_dest, system_health_report=health_mock)
    assert bundle_path.exists()

    with zipfile.ZipFile(bundle_path, "r") as zf:
        file_list = zf.namelist()
        assert "sanitized_logs.txt" in file_list
        assert "system_environment.json" in file_list
        assert "health_diagnostics.json" in file_list
        assert "manifest.json" in file_list
