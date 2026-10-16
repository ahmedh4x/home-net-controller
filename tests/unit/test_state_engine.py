"""
Unit tests for the Network State Engine, state transitions, and invariants.
"""
import pytest
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import DevicePolicyState, InternetAccessState
from netcutter.domain.state_engine import (
    EnforcementState,
    NetworkStateEngine,
    OperationState,
    StateTransitionError,
    SyncState,
)


def test_state_engine_in_sync_evaluation():
    desired = DevicePolicyState(internet_access=InternetAccessState.BLOCKED, download_limit_kbps=0, upload_limit_kbps=0)
    observed = DevicePolicyState(internet_access=InternetAccessState.BLOCKED, download_limit_kbps=0, upload_limit_kbps=0)

    res = NetworkStateEngine.evaluate_enforcement(
        desired=desired,
        observed=observed,
        last_op_state=OperationState.SUCCEEDED,
        backend_connected=True,
    )

    assert res.enforcement_state == EnforcementState.CONFIRMED
    assert res.sync_state == SyncState.IN_SYNC
    assert not res.can_reconcile


def test_state_engine_drift_evaluation():
    desired = DevicePolicyState(internet_access=InternetAccessState.BLOCKED)
    observed = DevicePolicyState(internet_access=InternetAccessState.ALLOWED)

    res = NetworkStateEngine.evaluate_enforcement(
        desired=desired,
        observed=observed,
        last_op_state=OperationState.IDLE,
        backend_connected=True,
    )

    assert res.enforcement_state == EnforcementState.OUT_OF_SYNC
    assert res.sync_state == SyncState.DIVERGENT
    assert res.can_reconcile
    assert "Access mismatch" in res.reason


def test_state_engine_unsupported_capability_invariant():
    desired = DevicePolicyState(download_limit_kbps=5000)
    observed = DevicePolicyState()
    caps = BackendCapabilities.OFFPATH_IPV4_ENFORCEMENT  # No shaping

    res = NetworkStateEngine.evaluate_enforcement(
        desired=desired,
        observed=observed,
        backend_connected=True,
        backend_caps=caps,
    )

    assert res.enforcement_state == EnforcementState.UNSUPPORTED
    assert res.sync_state == SyncState.DEGRADED
    assert not res.can_reconcile


def test_state_engine_timeout_uncertainty_invariant():
    desired = DevicePolicyState(internet_access=InternetAccessState.BLOCKED)
    observed = DevicePolicyState(internet_access=InternetAccessState.ALLOWED)

    res = NetworkStateEngine.evaluate_enforcement(
        desired=desired,
        observed=observed,
        last_op_state=OperationState.TIMED_OUT,
        last_op_error="Socket timeout waiting for ACK",
        backend_connected=True,
    )

    # Uncertainty must be explicit (UNKNOWN), never false success
    assert res.enforcement_state == EnforcementState.UNKNOWN
    assert res.sync_state == SyncState.UNVERIFIABLE


def test_state_engine_illegal_transition_rejection():
    # Invariant: Cannot transition to CONFIRMED without verification
    with pytest.raises(StateTransitionError):
        NetworkStateEngine.transition(
            current=EnforcementState.PENDING,
            target=EnforcementState.CONFIRMED,
            operation_state=OperationState.RUNNING,
            verification_verified=False,
        )

    # Invariant: Cannot transition to CONFIRMED if operation failed
    with pytest.raises(StateTransitionError):
        NetworkStateEngine.transition(
            current=EnforcementState.PENDING,
            target=EnforcementState.CONFIRMED,
            operation_state=OperationState.FAILED,
            verification_verified=True,
        )
