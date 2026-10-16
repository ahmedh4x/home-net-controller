"""
Network Quality of Service (QoS) Rate Acceptance Tests.
"""
from netcutter.diagnostics.network_test import NetworkAcceptanceTester


def test_qos_rate_tolerance_acceptance():
    # Target: 5000 Kbps (5 Mbps)
    # Scenario 1: Exact target (625,000 bytes per second = 5000 Kbps)
    passed, rate, msg = NetworkAcceptanceTester.verify_rate_tolerance(
        target_kbps=5000,
        measured_bytes=625_000,
        duration_seconds=1.0,
    )
    assert passed is True
    assert round(rate) == 5000

    # Scenario 2: Within 10% jitter tolerance (4600 Kbps)
    passed, rate, msg = NetworkAcceptanceTester.verify_rate_tolerance(
        target_kbps=5000,
        measured_bytes=575_000,
        duration_seconds=1.0,
    )
    assert passed is True
    assert "PASS" in msg

    # Scenario 3: Outside tolerance (>15% leakage, e.g. 7000 Kbps)
    passed, rate, msg = NetworkAcceptanceTester.verify_rate_tolerance(
        target_kbps=5000,
        measured_bytes=875_000,
        duration_seconds=1.0,
    )
    assert passed is False
    assert "FAIL" in msg
