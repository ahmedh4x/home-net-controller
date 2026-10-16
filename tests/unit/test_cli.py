"""
Unit and functional tests for the NetCutter Command-Line Interface (CLI).
"""
from __future__ import annotations

import io
import json
import sys
from contextlib import redirect_stdout
from unittest.mock import patch
import pytest

from netcutter.cli.main import build_parser, main


def test_cli_parser_build():
    parser = build_parser()
    args = parser.parse_args(["devices", "--refresh", "--json"])
    assert args.command == "devices"
    assert args.refresh is True
    assert args.json is True

    args_ai = parser.parse_args(["ai", "check network security", "--json"])
    assert args_ai.command == "ai"
    assert args_ai.query == "check network security"
    assert args_ai.json is True


def test_cli_gateways_json_output():
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        with patch.object(sys, "argv", ["netcutter", "gateways", "--json"]):
            main(["gateways", "--json"])

    raw = out_buf.getvalue()
    data = json.loads(raw)
    assert isinstance(data, list)
    assert len(data) >= 1
    assert "name" in data[0]
    assert "backend_type" in data[0]


def test_cli_diagnostics_json_output():
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        main(["diagnostics", "--json"])

    raw = out_buf.getvalue()
    data = json.loads(raw)
    assert isinstance(data, dict)
    assert "gateway_name" in data
    assert "checks" in data
    assert "capabilities" in data


def test_cli_devices_json_output():
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        main(["devices", "--json"])

    raw = out_buf.getvalue()
    data = json.loads(raw)
    assert isinstance(data, list)


def test_cli_ai_subcommand_json():
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        main(["ai", "security audit", "--json"])

    raw = out_buf.getvalue()
    data = json.loads(raw)
    assert isinstance(data, dict)
    assert "summary" in data
    assert "markdown_details" in data
    assert "action_proposals" in data
    assert data["confidence"] > 0.0


def test_cli_ai_subcommand_plain_text():
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        main(["ai", "status"])

    raw = out_buf.getvalue()
    assert "[AI Copilot" in raw
    assert "Summary:" in raw


def test_cli_block_nonexistent_device():
    with pytest.raises(SystemExit) as exc:
        main(["block", "dead-beef-missing-target"])
    assert exc.value.code == 1


def test_cli_gateways_plain_text():
    out_buf = io.StringIO()
    with redirect_stdout(out_buf):
        main(["gateways"])
    raw = out_buf.getvalue()
    assert "Configured Gateways" in raw
    assert "* ACTIVE" in raw or "INACTIVE" in raw


def test_cli_rename_device():
    from netcutter.persistence.database import Database
    from netcutter.persistence.repository import DeviceRepository
    from netcutter.domain.models import Device

    db = Database()
    repo = DeviceRepository(db)

    # Ensure at least one test device exists in DB (self-contained for fresh CI runners)
    target_mac = "00:11:22:33:44:99"
    test_device = Device(
        display_name="Initial-Test-Device",
        primary_mac=target_mac,
        ipv4_addresses=["192.168.1.199"],
    )
    repo.upsert(test_device)

    # Rename it via CLI
    rename_buf = io.StringIO()
    with redirect_stdout(rename_buf):
        main(["rename", target_mac, "Test-Renamed-Device", "--json"])
    result = json.loads(rename_buf.getvalue())
    assert result["success"] is True
    assert result["display_name"] == "Test-Renamed-Device"

    # Verify updated in repository
    updated = repo.get_by_mac(target_mac)
    assert updated is not None
    assert updated.display_name == "Test-Renamed-Device"



