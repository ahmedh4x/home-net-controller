"""
Unit Tests for Device Identity, MAC Normalization, and OUI Resolution.
"""
import pytest
from netcutter.domain.identity import (
    calculate_identity_confidence,
    is_locally_administered_mac,
    normalize_mac,
    resolve_vendor_by_mac,
)
from netcutter.domain.models import ConfidenceLevel


def test_mac_normalization():
    assert normalize_mac("00:1a:2B:3c:4D:5e") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("00-1A-2B-3C-4D-5E") == "00:1a:2b:3c:4d:5e"
    assert normalize_mac("001a2b3c4d5e") == "00:1a:2b:3c:4d:5e"

    with pytest.raises(ValueError):
        normalize_mac("invalid_mac_string")
    with pytest.raises(ValueError):
        normalize_mac("00:11:22:33:44")


def test_locally_administered_mac_detection():
    # Bit 1 of octet 0 = 1 (LAA / Randomized MAC)
    assert is_locally_administered_mac("be:d0:74:aa:bb:cc") is True
    assert is_locally_administered_mac("02:00:00:00:00:00") is True
    assert is_locally_administered_mac("da:a1:19:22:33:44") is True

    # Bit 1 of octet 0 = 0 (Globally Unique OUI / Hardware MAC)
    assert is_locally_administered_mac("00:23:6c:45:89:12") is False
    assert is_locally_administered_mac("b8:27:eb:11:22:33") is False


def test_oui_vendor_resolution():
    assert resolve_vendor_by_mac("00:23:6c:11:22:33") == "Apple"
    assert resolve_vendor_by_mac("b8:27:eb:aa:bb:cc") == "Raspberry Pi Foundation"
    assert resolve_vendor_by_mac("50:c7:bf:01:02:03") == "TP-Link"
    # Randomized MACs report as private
    assert resolve_vendor_by_mac("be:d0:74:aa:bb:cc") == "Randomized / Private MAC"


def test_identity_confidence_computation():
    # Hardware MAC -> High confidence
    conf, is_rand = calculate_identity_confidence("00:23:6c:11:22:33", "My-MacBook", None, False)
    assert conf == ConfidenceLevel.HIGH
    assert is_rand is False

    # Randomized MAC with historical match -> High confidence
    conf, is_rand = calculate_identity_confidence("be:d0:74:aa:bb:cc", "Demo-iPhone", None, True)
    assert conf == ConfidenceLevel.HIGH
    assert is_rand is True

    # Randomized MAC with Hostname and DUID -> Medium confidence
    conf, is_rand = calculate_identity_confidence("be:d0:74:aa:bb:cc", "Demo-iPhone", "duid-123", False)
    assert conf == ConfidenceLevel.MEDIUM
    assert is_rand is True

    # Randomized MAC with no signals -> Ambiguous
    conf, is_rand = calculate_identity_confidence("be:d0:74:aa:bb:cc", None, None, False)
    assert conf == ConfidenceLevel.AMBIGUOUS
    assert is_rand is True


def test_format_device_display_name():
    from netcutter.domain.identity import format_device_display_name
    from netcutter.domain.models import DeviceCategory

    # 1. Meaningful DHCP hostname preserved
    assert format_device_display_name("DESKTOP-8K3N72A", "Dell", DeviceCategory.LAPTOP_PC) == "DESKTOP-8K3N72A"
    assert format_device_display_name("Demo-iPhone", "Apple", DeviceCategory.SMARTPHONE) == "Demo-iPhone"

    # 2. Known vendor with clean category label and IP
    name = format_device_display_name(
        None,
        "Samsung Electronics",
        DeviceCategory.SMART_TV,
        ipv4_addresses=["192.168.1.30"],
        mac="00:07:ab:11:22:33",
    )
    assert name == "Samsung Smart TV (192.168.1.30)"

    # 3. Known vendor PC with IP
    name = format_device_display_name(
        "*",  # generic hostname placeholder
        "Dell Inc.",
        DeviceCategory.LAPTOP_PC,
        ipv4_addresses=["192.168.1.10"],
        mac="00:24:e8:11:22:33",
    )
    assert name == "Dell Windows PC (192.168.1.10)"

    # 4. Randomized MAC fallback
    name = format_device_display_name(
        None,
        "Randomized / Private MAC",
        DeviceCategory.UNKNOWN,
        ipv4_addresses=["192.168.1.55"],
        mac="be:d0:74:aa:bb:cc",
        is_randomized=True,
    )
    assert name == "Private Client (192.168.1.55)"

    # 5. Generic unknown device with IP
    name = format_device_display_name(
        None,
        None,
        DeviceCategory.UNKNOWN,
        ipv4_addresses=["192.168.1.99"],
        mac="00:11:22:33:44:55",
        is_randomized=False,
    )
    assert name == "Client (192.168.1.99)"
