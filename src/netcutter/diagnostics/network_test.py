"""
Network Packet Path Acceptance Tester.
Simulates and tests bandwidth rate shaping and firewall drop behavior.
"""
from __future__ import annotations

import time
from typing import Dict, Tuple
from netcutter.domain.models import Device


class NetworkAcceptanceTester:
    """
    Validates that rate-limiting and drop enforcement match expected tolerances.
    """
    @staticmethod
    def verify_rate_tolerance(target_kbps: int, measured_bytes: int, duration_seconds: float) -> Tuple[bool, float, str]:
        """
        Calculates throughput in Kbps and tests if within ±15% of target rate.
        """
        if duration_seconds <= 0:
            return False, 0.0, "Invalid test duration"
        
        measured_kbps = (measured_bytes * 8) / (duration_seconds * 1000)
        tolerance = target_kbps * 0.15  # 15% standard networking jitter tolerance
        lower_bound = target_kbps - tolerance
        upper_bound = target_kbps + tolerance

        passed = lower_bound <= measured_kbps <= upper_bound
        msg = (
            f"Measured: {measured_kbps:.1f} Kbps, Target: {target_kbps} Kbps "
            f"[{'PASS' if passed else 'FAIL'}]"
        )
        return passed, measured_kbps, msg
