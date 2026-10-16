"""
Unit tests for Device Classification and Evidence-Based Identity Engine.
Verifies all 10 DeviceCategory classifications, 4-tier evidence hierarchy,
randomized MAC handling, and repository persistence.
"""
import pytest

from netcutter.domain.identity import classify_device, resolve_vendor_by_mac
from netcutter.domain.models import ConfidenceLevel, Device, DeviceCategory
from netcutter.persistence.database import Database
from netcutter.persistence.repository import DeviceRepository
from netcutter.services.identity_engine import IdentityEngine


def test_classification_level1_router_metadata():
    # Level 1 takes precedence over other clues
    cat, basis, conf = classify_device(
        mac="00:11:22:33:44:55",
        hostname="generic-host",
        raw_metadata={"device_type": "Smart TV"}
    )
    assert cat == DeviceCategory.SMART_TV
    assert "Router reported metadata" in basis
    assert conf == ConfidenceLevel.HIGH

    cat, basis, conf = classify_device(
        mac="00:11:22:33:44:55",
        raw_metadata={"device_type": "Mobile Phone"}
    )
    assert cat == DeviceCategory.SMARTPHONE
    assert conf == ConfidenceLevel.HIGH


def test_classification_level2_dhcp_hostnames():
    # Smartphone: iPhone
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="Demo-iPhone")
    assert cat == DeviceCategory.SMARTPHONE
    assert "iPhone" in basis

    # Tablet: iPad
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="LivingRoom-iPad")
    assert cat == DeviceCategory.TABLET
    assert "iPad" in basis

    # PC / Laptop
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="DESKTOP-8K3N72A")
    assert cat == DeviceCategory.LAPTOP_PC

    # Mac
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="MacBookPro-M2")
    assert cat == DeviceCategory.MAC

    # Smart TV
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="Samsung-SmartTV")
    assert cat == DeviceCategory.SMART_TV

    # Network Printer
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="HP-LaserJet-Pro")
    assert cat == DeviceCategory.PRINTER

    # Gaming Console
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="PlayStation-5-Living")
    assert cat == DeviceCategory.GAMING_CONSOLE

    # Router / AP
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="OpenWrt-AccessPoint")
    assert cat == DeviceCategory.ROUTER_AP

    # IoT / Embedded
    cat, basis, _ = classify_device(mac="00:11:22:33:44:55", hostname="esp32-temp-sensor")
    assert cat == DeviceCategory.IOT_DEVICE


def test_classification_level3_oui_vendors():
    # Raspberry Pi -> IoT Device
    cat, basis, conf = classify_device(
        mac="b8:27:eb:00:11:22",
        vendor="Raspberry Pi Trading Ltd"
    )
    assert cat == DeviceCategory.IOT_DEVICE
    assert conf == ConfidenceLevel.HIGH

    # Sony Interactive -> Gaming Console
    cat, basis, conf = classify_device(
        mac="00:d9:d1:00:11:22",
        vendor="Sony Interactive Entertainment"
    )
    assert cat == DeviceCategory.GAMING_CONSOLE
    assert conf == ConfidenceLevel.HIGH

    # Roku -> Smart TV
    cat, basis, conf = classify_device(
        mac="b0:a7:37:00:11:22",
        vendor="Roku, Inc."
    )
    assert cat == DeviceCategory.SMART_TV

    # Brother -> Printer
    cat, basis, conf = classify_device(
        mac="00:80:77:00:11:22",
        vendor="Brother Industries"
    )
    assert cat == DeviceCategory.PRINTER


def test_classification_level4_randomized_mac_and_fallbacks():
    # Locally administered bit set: 02:xx:xx:xx:xx:xx
    rand_mac = "02:11:22:33:44:55"
    cat, basis, conf = classify_device(mac=rand_mac, hostname=None)
    assert cat == DeviceCategory.UNKNOWN
    assert conf == ConfidenceLevel.AMBIGUOUS
    assert "Randomized" in basis

    # Randomized MAC with iPhone hostname gets medium confidence
    cat, basis, conf = classify_device(mac=rand_mac, hostname="iPhone-15")
    assert cat == DeviceCategory.SMARTPHONE
    assert conf == ConfidenceLevel.MEDIUM

    # Unicast non-randomized MAC with no vendor and no recognizable name
    cat, basis, conf = classify_device(mac="00:11:22:33:44:55", hostname="host-node-4")
    assert cat == DeviceCategory.UNKNOWN
    assert conf == ConfidenceLevel.LOW


def test_identity_engine_auto_classification_and_repository(tmp_path):
    from netcutter.backends.base import DiscoveredDeviceRaw

    db_file = str(tmp_path / "test_classification.db")
    db = Database(db_file)
    repo = DeviceRepository(db)
    engine = IdentityEngine(db, repo)

    # Ingest a device event with OUI vendor
    raw = DiscoveredDeviceRaw(
        mac="b8:27:eb:aa:bb:cc",
        ipv4_addresses=["192.168.1.150"],
        hostname="raspi-server",
    )
    devs = engine.process_discovery([raw])
    assert len(devs) == 1
    dev = devs[0]

    assert dev.category == DeviceCategory.IOT_DEVICE
    assert "Raspberry Pi" in dev.classification_basis

    # Verify persistent round-trip
    loaded = repo.get_by_guid(dev.device_guid)
    assert loaded is not None
    assert loaded.category == DeviceCategory.IOT_DEVICE
    assert loaded.classification_basis == dev.classification_basis
