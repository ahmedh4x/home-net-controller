"""
Unit tests for AI Assistant privacy guarantees and opt-in network egress.
"""
import os
from unittest.mock import MagicMock
from netcutter.domain.models import Device, DeviceCategory, GatewayConfig, BackendType
from netcutter.services.ai_assistant import AIAssistantService


def test_ai_assistant_egress_disabled_by_default(monkeypatch):
    monkeypatch.setenv("HNC_LLM_ENDPOINT", "https://api.openai.com/v1")
    monkeypatch.delenv("HNC_ENABLE_AI_EGRESS", raising=False)
    monkeypatch.delenv("NETCUTTER_ENABLE_AI_EGRESS", raising=False)

    device_repo = MagicMock()
    gw_repo = MagicMock()
    audit_repo = MagicMock()
    gw_mgr = MagicMock()

    svc = AIAssistantService(device_repo, gw_repo, audit_repo, gw_mgr)
    assert svc.llm_client is None, "AI remote client must not initialize without explicit opt-in"


def test_ai_assistant_sanitization_removes_ips_and_macs():
    dev1 = Device(
        display_name="Ahmed's Personal iPhone",
        primary_mac="00:11:22:33:44:55",
        ipv4_addresses=["192.168.1.105"],
        vendor="Apple, Inc.",
        category=DeviceCategory.SMARTPHONE,
    )
    dev2 = Device(
        display_name="Secret Server",
        primary_mac="02:00:00:12:34:56",
        ipv4_addresses=["192.168.1.200"],
        vendor=None,
        category=DeviceCategory.UNKNOWN,
    )
    gw = GatewayConfig(
        name="Main Router",
        host="192.168.1.1",
        backend_type=BackendType.OPENWRT,
    )
    errors = [
        "Connection refused to 192.168.1.1:22 for user admin with password 'secret'",
        "ARP conflict detected for 00:11:22:33:44:55",
    ]

    sanitized = AIAssistantService.sanitize_context_for_egress([dev1, dev2], gw, errors)

    assert "total_monitored_devices" in sanitized
    assert sanitized["total_monitored_devices"] == 2

    # Check devices
    dev_entries = sanitized["sanitized_devices"]
    for entry in dev_entries:
        # MAC and IP must NOT exist in the payload
        assert "primary_mac" not in entry
        assert "mac" not in entry
        assert "ipv4" not in entry
        assert "192.168.1.105" not in str(entry)
        assert "00:11:22:33:44:55" not in str(entry)
        assert "Ahmed" not in str(entry)

    # Check diagnostic events redaction
    assert sanitized["diagnostic_events"][0] == "Connection refused to <IP_REDACTED>:22 for user admin with password 'secret'"
    assert sanitized["diagnostic_events"][1] == "ARP conflict detected for <MAC_REDACTED>"
