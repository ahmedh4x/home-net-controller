"""
Hardened Verification Tests for Linux nftables/tc QoS, MikroTik IPv6 REST, and Identity Protection.
"""
from unittest.mock import MagicMock, patch
import pytest
from netcutter.backends.linux import LinuxGatewayBackend
from netcutter.backends.mikrotik import MikroTikBackend
from netcutter.backends.base import DiscoveredDeviceRaw
from netcutter.domain.models import BackendType, GatewayConfig, Device
from netcutter.services.identity_engine import IdentityEngine


def test_linux_deterministic_class_id():
    cfg = GatewayConfig(name="OpenWrt Test", host="192.168.1.1", backend_type=BackendType.OPENWRT)
    backend1 = LinuxGatewayBackend(cfg)
    cid1 = backend1._get_class_id("00:11:22:33:44:55")
    
    # Fresh backend instance simulating controller restart
    backend2 = LinuxGatewayBackend(cfg)
    cid2 = backend2._get_class_id("00:11:22:33:44:55")
    
    assert cid1 == cid2
    assert 10 <= cid1 <= 64010


def test_linux_nat_safe_qos_command_generation():
    cfg = GatewayConfig(
        name="OpenWrt",
        host="192.168.1.1",
        wan_interface="eth1",
        lan_interface="br-lan",
        backend_type=BackendType.OPENWRT,
    )
    backend = LinuxGatewayBackend(cfg)
    backend.is_connected = MagicMock(return_value=True)

    executed_commands = []

    def mock_exec(cmd: str):
        executed_commands.append(cmd)
        if "tc class show" in cmd:
            return 0, "class htb 1:1234 rate 2048kbit ceil 2048kbit", ""
        return 0, "", ""

    backend._exec_command = mock_exec

    mac = "00:11:22:33:44:55"
    cid = backend._get_class_id(mac)
    ips = ["192.168.1.50", "2001:db8::50"]

    res = backend.set_bandwidth_limit(mac, ips, dl_kbps=5120, ul_kbps=2048)
    assert res.success is True

    # 1. Verify WAN HTB class created
    assert any(f"tc class replace dev eth1 parent 1: classid 1:{cid} htb rate 2048kbit" in c for c in executed_commands)
    # 2. Verify WAN tc filter uses fw mark handle (NAT-safe)
    assert any(f"tc filter replace dev eth1 protocol all parent 1: prio 1 handle {cid} fw flowid 1:{cid}" in c for c in executed_commands)
    # 3. Verify nftables prerouting map element added for MAC and IPv6
    assert any(f"nft add element inet netcutter mac_to_mark {{ {mac} : {cid} }}" in c for c in executed_commands)
    assert any(f"nft add element inet netcutter ip6_to_mark {{ 2001:db8::50 : {cid} }}" in c for c in executed_commands)
    # 4. Verify LAN egress shapes both IPv4 and IPv6
    assert any(f"tc filter replace dev br-lan protocol ip parent 1: prio 1 u32 match ip dst 192.168.1.50 flowid 1:{cid}" in c for c in executed_commands)
    assert any(f"tc filter replace dev br-lan protocol ipv6 parent 1: prio 2 u32 match ip6 dst 2001:db8::50 flowid 1:{cid}" in c for c in executed_commands)


def test_linux_block_evicts_flowtable_and_dual_stack_conntrack():
    cfg = GatewayConfig(name="OpenWrt", host="192.168.1.1", backend_type=BackendType.OPENWRT)
    backend = LinuxGatewayBackend(cfg)
    backend.is_connected = MagicMock(return_value=True)

    executed_commands = []

    def mock_exec(cmd: str):
        executed_commands.append(cmd)
        if "nft list set" in cmd:
            return 0, "00:11:22:33:44:55", ""
        return 0, "", ""

    backend._exec_command = mock_exec

    mac = "00:11:22:33:44:55"
    ips = ["192.168.1.50", "2001:db8::50"]

    res = backend.block_device(mac, ips)
    assert res.success is True

    # Verify flowtable flush
    assert any("nft flush flowtable inet fw4 ft" in c for c in executed_commands)
    # Verify bidirectional conntrack flush for IPv4
    assert any("conntrack -D -s 192.168.1.50" in c for c in executed_commands)
    assert any("conntrack -D -d 192.168.1.50" in c for c in executed_commands)
    # Verify bidirectional conntrack flush for IPv6
    assert any("conntrack -D -f ipv6 -s 2001:db8::50" in c for c in executed_commands)
    assert any("conntrack -D -f ipv6 -d 2001:db8::50" in c for c in executed_commands)


def test_mikrotik_dual_stack_rules_and_connection_removal():
    cfg = GatewayConfig(name="MikroTik Router", host="192.168.88.1", backend_type=BackendType.MIKROTIK)
    backend = MikroTikBackend(cfg)

    mock_session = MagicMock()
    # Mock GET /ip/firewall/filter and /ipv6/firewall/filter returning empty list (rule missing)
    mock_get_response = MagicMock()
    mock_get_response.status_code = 200
    mock_get_response.json.return_value = []
    mock_session.get.return_value = mock_get_response

    backend._session = mock_session

    # Test _ensure_firewall_rules adds both v4 and v6
    backend._ensure_firewall_rules()

    put_urls = [call.args[0] for call in mock_session.put.call_args_list]
    assert any("/ip/firewall/filter" in url for url in put_urls)
    assert any("/ipv6/firewall/filter" in url for url in put_urls)

    # Test block_device with multi-IP
    mac = "00:11:22:33:44:55"
    ips = ["192.168.88.20", "2001:db8::20"]
    backend.block_device(mac, ips)

    post_calls = [call.args[0] for call in mock_session.post.call_args_list]
    assert any("/ip/firewall/connection/remove" in url for url in post_calls)
    assert any("/ipv6/firewall/connection/remove" in url for url in post_calls)


def test_identity_engine_generic_hostname_anti_merge():
    from netcutter.persistence.database import Database
    from netcutter.persistence.repository import DeviceRepository
    import tempfile
    import os

    with tempfile.NamedTemporaryFile(suffix=".db", delete=False) as tf:
        db_path = tf.name

    try:
        db = Database(db_path)
        repo = DeviceRepository(db)
        engine = IdentityEngine(db, repo)

        # Existing device 1: Phone with generic hostname "android"
        raw1 = [
            DiscoveredDeviceRaw(
                mac="02:00:00:00:00:01",  # Locally administered (randomized)
                ipv4_addresses=["192.168.1.10"],
                hostname="android",
            )
        ]
        devs1 = engine.process_discovery(raw1)
        assert len(devs1) == 1
        guid1 = devs1[0].device_guid

        # Device 2 arrives: Different phone also named "android"
        raw2 = [
            DiscoveredDeviceRaw(
                mac="02:00:00:00:00:02",
                ipv4_addresses=["192.168.1.20"],
                hostname="android",
            )
        ]
        devs2 = engine.process_discovery(raw2)
        assert len(devs2) == 1
        guid2 = devs2[0].device_guid

        # Must NOT merge into guid1! They must be separate devices!
        assert guid1 != guid2
        assert len(repo.get_all()) == 2
    finally:
        if os.path.exists(db_path):
            os.remove(db_path)


def test_ssh_host_key_pinning_and_mismatch():
    import base64
    import hashlib
    import paramiko
    from netcutter.backends.linux import HostKeyFingerprintPolicy

    # Generate a dummy RSA key
    dummy_key = paramiko.RSAKey.generate(1024)
    raw_hash = hashlib.sha256(dummy_key.asbytes()).digest()
    correct_fp = "SHA256:" + base64.b64encode(raw_hash).decode("utf-8").rstrip("=")

    # 1. First-use acceptance: policy records fingerprint and accepts
    policy_first = HostKeyFingerprintPolicy(expected_fingerprint=None)
    mock_client = MagicMock()
    policy_first.missing_host_key(mock_client, "192.168.1.1", dummy_key)
    assert policy_first.recorded_fingerprint == correct_fp
    mock_client.get_host_keys().add.assert_called_once()

    # 2. Strict matching with pinned fingerprint
    policy_match = HostKeyFingerprintPolicy(expected_fingerprint=correct_fp)
    mock_client2 = MagicMock()
    policy_match.missing_host_key(mock_client2, "192.168.1.1", dummy_key)
    mock_client2.get_host_keys().add.assert_called_once()

    # 3. Mismatch rejection: wrong pinned fingerprint
    policy_mismatch = HostKeyFingerprintPolicy(expected_fingerprint="SHA256:FAKEFINGERPRINT1234567890")
    with pytest.raises(paramiko.SSHException) as exc_info:
        policy_mismatch.missing_host_key(mock_client2, "192.168.1.1", dummy_key)
    assert "Host key verification failed" in str(exc_info.value)


def test_mikrotik_simple_queue_patch_and_error_handling():
    cfg = GatewayConfig(name="MikroTik Test", host="192.168.88.1", backend_type=BackendType.MIKROTIK)
    backend = MikroTikBackend(cfg, password="test")
    backend._session = MagicMock()

    mac = "00:11:22:33:44:55"
    queue_name = "netcutter_001122334455"
    ips = ["192.168.88.50"]

    # Scenario 1: Queue exists -> uses PATCH
    get_mock = MagicMock()
    get_mock.status_code = 200
    get_mock.json.return_value = [{"name": queue_name, ".id": "*A1"}]
    patch_mock = MagicMock()
    patch_mock.status_code = 200
    backend._session.get.return_value = get_mock
    backend._session.patch.return_value = patch_mock

    # Mock observed state to verify
    with patch.object(backend, "query_observed_state") as mock_obs:
        from netcutter.backends.base import ObservedPolicy
        mock_obs.return_value = ObservedPolicy(download_limit_kbps=5000, upload_limit_kbps=2000)
        res = backend.set_bandwidth_limit(mac, ips, dl_kbps=5000, ul_kbps=2000)
        assert res.success is True
        assert "Updated" in res.details
        backend._session.patch.assert_called_once()
        backend._session.put.assert_not_called()

    # Scenario 2: RouterOS returns 400 error
    backend._session.reset_mock()
    backend._session.get.return_value.status_code = 404
    backend._session.get.return_value.json.return_value = []
    put_mock = MagicMock()
    put_mock.status_code = 400
    put_mock.text = "invalid argument max-limit"
    backend._session.put.return_value = put_mock

    res_err = backend.set_bandwidth_limit(mac, ips, dl_kbps=5000, ul_kbps=2000)
    assert res_err.success is False
    assert "HTTP 400" in res_err.error


