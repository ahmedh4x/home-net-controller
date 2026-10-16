"""
Unit & Integration Tests for Website & Domain Blocking Subsystem.
Tests validation, normalization, subdomain matching, precedence, persistence,
backend enforcement, and TLS SNI extraction.
"""
import pytest
from datetime import datetime, timezone
from pathlib import Path

from netcutter.backends.capabilities import BackendCapabilities
from netcutter.backends.mock_backend import MockGatewayBackend
from netcutter.backends.windows_lan import WindowsLanInterceptorBackend
from netcutter.domain.domain_validator import (
    is_domain_match,
    normalize_domain,
    validate_domain,
)
from netcutter.domain.models import (
    BlockedDomainEvent,
    Device,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
    GatewayConfig,
)
from netcutter.persistence.database import Database
from netcutter.persistence.repository import DomainBlockingRepository
from netcutter.services.domain_blocking_service import DomainBlockingService


# -------------------------------------------------------------
# Test 1: Domain Normalization and Validation
# -------------------------------------------------------------
def test_domain_normalization():
    # URL schemes stripped
    assert normalize_domain("https://example.com") == "example.com"
    assert normalize_domain("http://sub.test.org/path/index.html") == "sub.test.org"
    assert normalize_domain("HTTPS://WWW.GOOGLE.COM/") == "www.google.com"

    # Ports stripped
    assert normalize_domain("example.com:8080") == "example.com"
    assert normalize_domain("https://example.com:443/api") == "example.com"

    # Wildcards normalized
    assert normalize_domain("*.example.com") == "example.com"
    assert normalize_domain("*example.com") == "example.com"

    # Trailing dots stripped
    assert normalize_domain("example.com.") == "example.com"


def test_domain_validation_success():
    valid, err, norm = validate_domain("example.com")
    assert valid is True
    assert norm == "example.com"
    assert err is None

    valid, err, norm = validate_domain("sub.domain.co.uk")
    assert valid is True
    assert norm == "sub.domain.co.uk"

    valid, err, norm = validate_domain("my-site-123.net")
    assert valid is True
    assert norm == "my-site-123.net"


def test_domain_validation_rejections():
    # Empty
    valid, err, _ = validate_domain("")
    assert valid is False
    assert "cannot be empty" in err

    # IPv4 address
    valid, err, _ = validate_domain("192.168.1.1")
    assert valid is False
    assert "IP address" in err

    # IPv6 address
    valid, err, _ = validate_domain("::1")
    assert valid is False

    # Invalid characters
    valid, err, _ = validate_domain("example$.com")
    assert valid is False
    assert "invalid characters" in err

    # Single label (no TLD)
    valid, err, _ = validate_domain("localhost")
    assert valid is False
    assert "top-level domain" in err

    # All-numeric TLD
    valid, err, _ = validate_domain("example.123")
    assert valid is False
    assert "cannot be entirely numeric" in err

    # Consecutive dots
    valid, err, _ = validate_domain("example..com")
    assert valid is False
    assert "consecutive dots" in err


# -------------------------------------------------------------
# Test 2: Exact vs Subdomain Matching
# -------------------------------------------------------------
def test_subdomain_matching():
    # Subdomain match mode: matches root and proper subdomains
    assert is_domain_match("example.com", "example.com", include_subdomains=True) is True
    assert is_domain_match("sub.example.com", "example.com", include_subdomains=True) is True
    assert is_domain_match("a.b.c.example.com", "example.com", include_subdomains=True) is True

    # Must NOT match partial names or different domains
    assert is_domain_match("notexample.com", "example.com", include_subdomains=True) is False
    assert is_domain_match("example.co", "example.com", include_subdomains=True) is False
    assert is_domain_match("example.com.org", "example.com", include_subdomains=True) is False


def test_exact_domain_matching():
    # Exact mode: ONLY matches exact hostname
    assert is_domain_match("example.com", "example.com", include_subdomains=False) is True
    assert is_domain_match("sub.example.com", "example.com", include_subdomains=False) is False
    assert is_domain_match("notexample.com", "example.com", include_subdomains=False) is False


# -------------------------------------------------------------
# Test 3: Domain Rule Repository CRUD
# -------------------------------------------------------------
def test_domain_rule_repository_crud(tmp_path):
    db_file = str(tmp_path / "test_domains.db")
    db = Database(db_file)
    repo = DomainBlockingRepository(db)

    rule = DomainBlockingRule(
        domain="ads.tracker.com",
        match_type=DomainMatchType.SUBDOMAIN,
        target_scope=DomainScope.GLOBAL,
        is_enabled=True,
        enforcement_status=DomainEnforcementStatus.ACTIVE,
        notes="Global ad blocking",
    )
    repo.upsert_rule(rule)

    # Read back
    fetched = repo.get_rule(rule.rule_id)
    assert fetched is not None
    assert fetched.domain == "ads.tracker.com"
    assert fetched.match_type == DomainMatchType.SUBDOMAIN
    assert fetched.target_scope == DomainScope.GLOBAL
    assert fetched.is_enabled is True
    assert fetched.enforcement_status == DomainEnforcementStatus.ACTIVE
    assert fetched.notes == "Global ad blocking"
    assert fetched.hits_count == 0

    # Increment hits
    repo.increment_hits(rule.rule_id, 5)
    fetched2 = repo.get_rule(rule.rule_id)
    assert fetched2.hits_count == 5

    # Record event
    event = BlockedDomainEvent(
        rule_id=rule.rule_id,
        domain="ads.tracker.com",
        client_ip="192.168.1.50",
        client_mac="00:11:22:33:44:55",
        action="DNS_SINKHOLE_ZERO_IP",
        mechanism="Layer-2 DNS Interceptor",
    )
    repo.record_event(event)

    events = repo.get_recent_events(10)
    assert len(events) == 1
    assert events[0].domain == "ads.tracker.com"
    assert events[0].client_ip == "192.168.1.50"

    # Delete
    deleted = repo.delete_rule(rule.rule_id)
    assert deleted is True
    assert repo.get_rule(rule.rule_id) is None


# -------------------------------------------------------------
# Test 4: DomainBlockingService Lifecycle & Precedence
# -------------------------------------------------------------
def test_domain_blocking_service_with_mock_backend(tmp_path):
    db_file = str(tmp_path / "test_svc_domains.db")
    db = Database(db_file)
    mock_backend = MockGatewayBackend()

    class MockGwManager:
        def get_active_backend(self):
            return mock_backend

    svc = DomainBlockingService(db, gateway_manager=MockGwManager())

    # Add global rule
    ok, rule, err = svc.add_rule("malicious-site.org", match_type=DomainMatchType.SUBDOMAIN)
    assert ok is True
    assert rule is not None
    assert rule.enforcement_status == DomainEnforcementStatus.ACTIVE

    # Verify rule is in mock backend
    verified, msg = mock_backend.verify_domain_rule(rule)
    assert verified is True
    assert "malicious-site.org" in msg

    # Duplicate rejection
    ok_dup, _, err_dup = svc.add_rule("malicious-site.org")
    assert ok_dup is False
    assert "already exists" in err_dup

    # Simulate DNS query from client: should be blocked
    is_blocked, evt = mock_backend.simulate_dns_query("00:11:22:33:44:55", "sub.malicious-site.org")
    assert is_blocked is True
    assert evt is not None
    assert evt.domain == "sub.malicious-site.org"

    # Simulate unrelated domain: should NOT be blocked
    is_blocked_unrelated, _ = mock_backend.simulate_dns_query("00:11:22:33:44:55", "google.com")
    assert is_blocked_unrelated is False

    # Disable rule
    ok_dis, _ = svc.disable_rule(rule.rule_id)
    assert ok_dis is True
    is_blocked_now, _ = mock_backend.simulate_dns_query("00:11:22:33:44:55", "malicious-site.org")
    assert is_blocked_now is False

    # Delete rule
    ok_del, _ = svc.delete_rule(rule.rule_id)
    assert ok_del is True
    assert len(svc.get_rules()) == 0


def test_device_specific_rule_precedence(tmp_path):
    db_file = str(tmp_path / "test_precedence.db")
    db = Database(db_file)
    mock_backend = MockGatewayBackend()

    class MockGwManager:
        def get_active_backend(self):
            return mock_backend

    dev_guid = "phone-guid-123"
    dev_mac = "aa:bb:cc:dd:ee:ff"

    class MockDeviceService:
        def get_device_by_guid(self, guid):
            if guid == dev_guid:
                return Device(
                    device_guid=dev_guid,
                    display_name="Test Phone",
                    primary_mac=dev_mac,
                    ipv4_addresses=["192.168.1.55"],
                )
            return None

    svc = DomainBlockingService(
        db, gateway_manager=MockGwManager(), device_service=MockDeviceService()
    )

    # Add Device-specific rule for Test Phone on socialmedia.com
    ok, rule, _ = svc.add_rule(
        "socialmedia.com",
        target_scope=DomainScope.DEVICE,
        target_device_guid=dev_guid,
    )
    assert ok is True
    assert rule.target_scope == DomainScope.DEVICE
    assert rule.target_mac == dev_mac

    # Test Phone queries socialmedia.com -> BLOCKED
    is_blocked, evt = mock_backend.simulate_dns_query(dev_mac, "socialmedia.com")
    assert is_blocked is True
    assert evt.client_mac == dev_mac

    # Other device (laptop) queries socialmedia.com -> ALLOWED (unaffected by device rule!)
    other_mac = "11:22:33:44:55:66"
    is_blocked_other, _ = mock_backend.simulate_dns_query(other_mac, "socialmedia.com")
    assert is_blocked_other is False


# -------------------------------------------------------------
# Test 5: TLS SNI Extraction Logic
# -------------------------------------------------------------
def test_tls_sni_extraction():
    # Build a minimal synthetic TLS ClientHello packet bytes with SNI "example.com"
    # SNI extension type: 0x0000, host_name type: 0x00, name: "example.com"
    sni_hostname = b"example.com"
    sni_entry = b"\x00" + len(sni_hostname).to_bytes(2, "big") + sni_hostname
    sni_list = len(sni_entry).to_bytes(2, "big") + sni_entry
    sni_ext = b"\x00\x00" + len(sni_list).to_bytes(2, "big") + sni_list

    # ClientHello content
    # version(2) + random(32) + session_id(1 + 0) + cipher_suites(2 + 2) + comp(1 + 1) + extensions
    ch_body = (
        b"\x03\x03"  # TLS 1.2
        + (b"\x00" * 32)  # random
        + b"\x00"  # session id len 0
        + b"\x00\x02\x00\x9c"  # cipher suites: len 2, TLS_RSA_WITH_AES_128_GCM_SHA256
        + b"\x01\x00"  # compression: len 1, null compression
        + len(sni_ext).to_bytes(2, "big") + sni_ext
    )

    # Handshake header: type 1 (ClientHello), len 3 bytes
    hs_header = b"\x01" + len(ch_body).to_bytes(3, "big") + ch_body

    # TLS Record Header: content type 0x16 (Handshake), version 0x0301, len 2 bytes
    tls_record = b"\x16\x03\x01" + len(hs_header).to_bytes(2, "big") + hs_header

    extracted = WindowsLanInterceptorBackend._extract_tls_sni(tls_record)
    assert extracted == "example.com"

    # Malformed / Non-TLS payload should return None without error
    assert WindowsLanInterceptorBackend._extract_tls_sni(b"GET / HTTP/1.1\r\n") is None
    assert WindowsLanInterceptorBackend._extract_tls_sni(b"") is None
    assert WindowsLanInterceptorBackend._extract_tls_sni(b"\x16\x03\x01\x00") is None


# -------------------------------------------------------------
# Test 6: Windows LAN Domain Rule Scoping and Verification
# -------------------------------------------------------------
def test_windows_lan_domain_rule_matching(tmp_path):
    backend = WindowsLanInterceptorBackend()

    rule_global = DomainBlockingRule(
        domain="global-blocked.com",
        match_type=DomainMatchType.SUBDOMAIN,
        target_scope=DomainScope.GLOBAL,
        is_enabled=True,
    )
    rule_device = DomainBlockingRule(
        domain="device-blocked.com",
        match_type=DomainMatchType.EXACT,
        target_scope=DomainScope.DEVICE,
        target_mac="aa:bb:cc:11:22:33",
        target_ip="192.168.1.100",
        is_enabled=True,
    )

    backend.apply_domain_rule(rule_global)
    backend.apply_domain_rule(rule_device)

    # 1. Matching global rule from any client
    match_res = backend._match_domain_rule("sub.global-blocked.com", "any:mac", "192.168.1.200")
    assert match_res is not None
    assert match_res.domain == "global-blocked.com"

    # 2. Matching device-specific rule from targeted MAC
    match_dev = backend._match_domain_rule("device-blocked.com", "aa:bb:cc:11:22:33", "192.168.1.100")
    assert match_dev is not None
    assert match_dev.domain == "device-blocked.com"

    # 3. Matching device-specific rule from DIFFERENT client -> NOT matched!
    match_diff = backend._match_domain_rule("device-blocked.com", "other:mac", "192.168.1.101")
    assert match_diff is None

    # Disconnect clears rules
    backend.disconnect()
    assert len(backend.query_domain_rules()) == 0
