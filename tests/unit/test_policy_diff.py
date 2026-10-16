"""
Unit Tests for Policy Diffing and Bandwidth Conversions.
"""
from netcutter.domain.models import (
    BandwidthLimit,
    DevicePolicyState,
    InternetAccessState,
)
from netcutter.domain.policy import calculate_policy_diff


def test_bandwidth_limit_model():
    unlimited = BandwidthLimit(0)
    assert unlimited.is_unlimited is True
    assert unlimited.to_display_string() == "Unlimited"

    kbps_limit = BandwidthLimit(512)
    assert kbps_limit.is_unlimited is False
    assert kbps_limit.to_display_string() == "512 Kbps"

    mbps_limit = BandwidthLimit(10240)
    assert mbps_limit.rate_mbps == 10.0
    assert mbps_limit.to_display_string() == "10 Mbps"


def test_policy_diff_block_detection():
    desired = DevicePolicyState(internet_access=InternetAccessState.BLOCKED)
    observed = DevicePolicyState(internet_access=InternetAccessState.ALLOWED)

    diff = calculate_policy_diff(desired, observed)
    assert diff.has_drift is True
    assert diff.needs_block is True
    assert diff.needs_unblock is False


def test_policy_diff_unblock_detection():
    desired = DevicePolicyState(internet_access=InternetAccessState.ALLOWED)
    observed = DevicePolicyState(internet_access=InternetAccessState.BLOCKED)

    diff = calculate_policy_diff(desired, observed)
    assert diff.has_drift is True
    assert diff.needs_unblock is True
    assert diff.needs_block is False


def test_policy_diff_bandwidth_rate_mismatch():
    desired = DevicePolicyState(download_limit_kbps=5120, upload_limit_kbps=1024)
    observed = DevicePolicyState(download_limit_kbps=2048, upload_limit_kbps=1024)

    diff = calculate_policy_diff(desired, observed)
    assert diff.has_drift is True
    assert diff.needs_download_update is True
    assert diff.needs_upload_update is False


def test_policy_diff_in_sync():
    desired = DevicePolicyState(
        internet_access=InternetAccessState.ALLOWED,
        download_limit_kbps=10240,
        upload_limit_kbps=2048,
    )
    observed = DevicePolicyState(
        internet_access=InternetAccessState.ALLOWED,
        download_limit_kbps=10240,
        upload_limit_kbps=2048,
    )

    diff = calculate_policy_diff(desired, observed)
    assert diff.has_drift is False
    assert diff.describe() == "In Sync"
