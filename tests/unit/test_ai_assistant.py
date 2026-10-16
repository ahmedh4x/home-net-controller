"""
Unit tests for the AI Diagnostic and Troubleshooting Assistant.
"""
from __future__ import annotations

import pytest
from unittest.mock import MagicMock

from netcutter.domain.models import BackendType, Device, GatewayConfig, InternetAccessState, PolicyStatus
from netcutter.persistence.database import Database
from netcutter.persistence.repository import AuditRepository, DeviceRepository, GatewayRepository
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.ai_assistant import AIAssistantService, ActionRiskLevel
from netcutter.services.gateway_manager import GatewayManager


@pytest.fixture
def ai_service_env(tmp_path):
    db_path = str(tmp_path / "test_ai.db")
    db = Database(db_path)
    device_repo = DeviceRepository(db)
    gw_repo = GatewayRepository(db)
    audit_repo = AuditRepository(db)
    secret_store = SecretStore()
    gw_manager = GatewayManager(db, gw_repo, secret_store)

    # Setup active mock gateway
    gw = GatewayConfig(
        gateway_id="gw-test",
        name="Test Gateway",
        host="192.168.1.1",
        port=22,
        backend_type=BackendType.MOCK,
        username="admin",
        is_active=True,
    )
    gw_repo.upsert(gw)
    gw_manager.set_active_gateway(gw.gateway_id)

    # Setup test devices
    d1 = Device(
        device_guid="dev-1",
        primary_mac="00:11:22:33:44:55",
        ipv4_addresses=["192.168.1.50"],
        hostname="Workstation-Alpha",
        display_name="Alpha PC",
        is_online=True,
    )
    device_repo.upsert(d1)

    # d2: Private randomized MAC (02:xx) and blocked
    d2 = Device(
        device_guid="dev-2",
        primary_mac="02:bb:cc:dd:ee:ff",
        ipv4_addresses=["192.168.1.51"],
        hostname="iPhone-15",
        display_name="Guest iPhone",
        is_online=True,
    )
    d2.desired_policy.internet_access = InternetAccessState.BLOCKED
    d2.policy_status = PolicyStatus.DRIFTED
    device_repo.upsert(d2)

    # d3: Bandwidth shaped
    d3 = Device(
        device_guid="dev-3",
        primary_mac="00:aa:bb:cc:dd:ee",
        ipv4_addresses=["192.168.1.52"],
        hostname="Smart-TV",
        display_name="Smart-TV",
        is_online=True,
    )
    d3.desired_policy.download_limit_kbps = 2048
    d3.desired_policy.upload_limit_kbps = 512
    device_repo.upsert(d3)

    service = AIAssistantService(device_repo, gw_repo, audit_repo, gw_manager)
    return service, device_repo, gw_repo


def test_ai_assistant_deterministic_overview(ai_service_env):
    service, _, _ = ai_service_env
    res = service.query("")

    assert "Network Healthy" in res.summary
    assert res.confidence == 1.0
    assert "Policy Drift Detected" in res.markdown_details
    assert "Randomized / Private MACs" in res.markdown_details
    assert "Smart-TV" in res.markdown_details or "2048 Kbps" in res.markdown_details

    # Should propose reconciliation due to drifted device
    assert any(p.action_type == "RUN_RECONCILIATION" for p in res.action_proposals)
    for p in res.action_proposals:
        assert p.requires_confirmation is True


def test_ai_assistant_troubleshooting_block_unblock_query(ai_service_env):
    service, _, _ = ai_service_env

    # 1. Block command query
    res_block = service.query("block Workstation-Alpha")
    assert len(res_block.action_proposals) == 1
    proposal = res_block.action_proposals[0]
    assert proposal.action_type == "BLOCK_DEVICE"
    assert proposal.target_id == "dev-1"
    assert proposal.requires_confirmation is True
    assert proposal.risk_level == ActionRiskLevel.MEDIUM

    # 2. Unblock command query by MAC
    res_unblock = service.query("unblock 02:bb:cc:dd:ee:ff")
    assert len(res_unblock.action_proposals) == 1
    proposal_unblock = res_unblock.action_proposals[0]
    assert proposal_unblock.action_type == "UNBLOCK_DEVICE"
    assert proposal_unblock.target_id == "dev-2"
    assert proposal_unblock.requires_confirmation is True


def test_ai_assistant_bandwidth_and_security_audit(ai_service_env):
    service, _, _ = ai_service_env

    # Bandwidth query
    res_bw = service.query("why is network speed slow")
    assert "Smart-TV" in res_bw.markdown_details
    assert "throttled to 2048 Kbps" in res_bw.markdown_details

    # Security query
    res_sec = service.query("run security audit on devices")
    assert "Randomized MACs" in res_sec.markdown_details
    assert "02:bb:cc:dd:ee:ff" in res_sec.markdown_details


def test_ai_assistant_safe_fallback_when_llm_fails(ai_service_env, monkeypatch):
    service, _, _ = ai_service_env

    # Force a failing mock LLM client
    mock_llm = MagicMock()
    mock_llm.complete.side_effect = RuntimeError("Connection timed out to LLM endpoint")
    service.llm_client = mock_llm

    # Query should catch exception and fallback gracefully to deterministic engine
    res = service.query("how to reconcile state")
    assert res is not None
    assert "Policy Synchronization & Drift Engine" in res.markdown_details
    assert res.source_model == "Deterministic Local Intelligence"
