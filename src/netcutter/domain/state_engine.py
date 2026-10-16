"""
Network State Engine for NetCutter.
Provides rigorous state modeling, explicit uncertainty tracking, and invariant enforcement.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import DevicePolicyState


class OperationState(str, Enum):
    """Lifecycle state of an enforcement mutation command."""
    IDLE = "IDLE"
    QUEUED = "QUEUED"
    RUNNING = "RUNNING"
    SUCCEEDED = "SUCCEEDED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    TIMED_OUT = "TIMED_OUT"
    PARTIAL = "PARTIAL"


class EnforcementState(str, Enum):
    """Actual gateway enforcement status for a device policy."""
    CONFIRMED = "CONFIRMED"          # Kernel rules verified present & active
    PENDING = "PENDING"              # Mutation in flight or queued
    FAILED = "FAILED"                # Mutation attempt failed
    OUT_OF_SYNC = "OUT_OF_SYNC"      # Discrepancy between desired and observed
    UNKNOWN = "UNKNOWN"              # State cannot be verified (e.g. timeout or disconnect)
    UNSUPPORTED = "UNSUPPORTED"      # Requested policy not supported by backend


class SyncState(str, Enum):
    """Overall consistency between local desired intent and observed router state."""
    IN_SYNC = "IN_SYNC"
    DIVERGENT = "DIVERGENT"
    UNVERIFIABLE = "UNVERIFIABLE"
    DEGRADED = "DEGRADED"


class StateTransitionError(ValueError):
    """Raised when an illegal or invariant-violating state transition is attempted."""
    pass


@dataclass
class StateTransitionRecord:
    """Audit record of a state transition."""
    transition_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    from_enforcement: EnforcementState = EnforcementState.UNKNOWN
    to_enforcement: EnforcementState = EnforcementState.UNKNOWN
    operation_state: OperationState = OperationState.IDLE
    operation_id: Optional[str] = None
    reason: str = ""
    error: Optional[str] = None


@dataclass
class PolicyEvaluationResult:
    """Result of evaluating desired vs observed state against backend capabilities."""
    enforcement_state: EnforcementState
    sync_state: SyncState
    operation_state: OperationState
    reason: str
    can_reconcile: bool
    requires_preview: bool


class NetworkStateEngine:
    """
    Manages and validates state transitions for device network policies.
    Guarantees state invariants:
    1. A failed operation is NEVER silently marked as CONFIRMED.
    2. Unsupported operations are marked UNSUPPORTED, never SUCCEEDED.
    3. Timeouts result in UNKNOWN state, explicitly representing uncertainty.
    4. Confirmed status requires verified backend observation.
    """

    @staticmethod
    def evaluate_enforcement(
        desired: DevicePolicyState,
        observed: Optional[DevicePolicyState],
        last_op_state: OperationState = OperationState.IDLE,
        last_op_error: Optional[str] = None,
        backend_connected: bool = True,
        backend_caps: Optional[BackendCapabilities] = None,
        verification_verified: bool = False,
    ) -> PolicyEvaluationResult:
        """
        Evaluate full policy and synchronization state with invariant enforcement.
        """
        # Invariant: If backend is disconnected, state cannot be verified
        if not backend_connected:
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.UNKNOWN,
                sync_state=SyncState.UNVERIFIABLE,
                operation_state=last_op_state,
                reason="Gateway backend is disconnected or offline",
                can_reconcile=False,
                requires_preview=False,
            )

        # Invariant: Check capability support
        if backend_caps is not None:
            if desired.has_download_limit or desired.has_upload_limit:
                has_shaping = bool(
                    (backend_caps & BackendCapabilities.DOWNLOAD_SHAPING)
                    or (backend_caps & BackendCapabilities.UPLOAD_SHAPING)
                )
                if not has_shaping:
                    return PolicyEvaluationResult(
                        enforcement_state=EnforcementState.UNSUPPORTED,
                        sync_state=SyncState.DEGRADED,
                        operation_state=OperationState.FAILED,
                        reason="Active backend does not support QoS bandwidth shaping",
                        can_reconcile=False,
                        requires_preview=True,
                    )

        # Invariant: Operation failed or timed out
        if last_op_state == OperationState.TIMED_OUT:
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.UNKNOWN,
                sync_state=SyncState.UNVERIFIABLE,
                operation_state=OperationState.TIMED_OUT,
                reason=f"Operation timed out: {last_op_error or 'No response from router'}",
                can_reconcile=True,
                requires_preview=False,
            )

        if last_op_state == OperationState.FAILED:
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.FAILED,
                sync_state=SyncState.DIVERGENT,
                operation_state=OperationState.FAILED,
                reason=f"Enforcement failed: {last_op_error or 'Unknown error'}",
                can_reconcile=True,
                requires_preview=False,
            )

        if last_op_state == OperationState.PARTIAL:
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.OUT_OF_SYNC,
                sync_state=SyncState.DEGRADED,
                operation_state=OperationState.PARTIAL,
                reason=f"Partial enforcement applied: {last_op_error or 'One or more steps failed'}",
                can_reconcile=True,
                requires_preview=False,
            )

        # If operation is still running or queued
        if last_op_state in (OperationState.QUEUED, OperationState.RUNNING):
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.PENDING,
                sync_state=SyncState.DIVERGENT,
                operation_state=last_op_state,
                reason="Policy mutation is currently being applied",
                can_reconcile=False,
                requires_preview=False,
            )

        # No observed state available yet
        if observed is None:
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.UNKNOWN,
                sync_state=SyncState.UNVERIFIABLE,
                operation_state=last_op_state,
                reason="Router kernel state has not been queried yet",
                can_reconcile=True,
                requires_preview=False,
            )

        # Compare desired vs observed
        is_blocked_match = desired.internet_access == observed.internet_access
        is_dl_match = desired.download_limit_kbps == observed.download_limit_kbps
        is_ul_match = desired.upload_limit_kbps == observed.upload_limit_kbps

        if is_blocked_match and is_dl_match and is_ul_match:
            # Confirmed state
            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.CONFIRMED,
                sync_state=SyncState.IN_SYNC,
                operation_state=OperationState.SUCCEEDED,
                reason="Desired policy verified on gateway",
                can_reconcile=False,
                requires_preview=False,
            )
        else:
            # Policy drift detected
            diff_parts = []
            if not is_blocked_match:
                diff_parts.append(
                    f"Access mismatch (Desired: {desired.internet_access.value}, Observed: {observed.internet_access.value})"
                )
            if not is_dl_match:
                diff_parts.append(
                    f"Download mismatch (Desired: {desired.download_limit_kbps}k, Observed: {observed.download_limit_kbps}k)"
                )
            if not is_ul_match:
                diff_parts.append(
                    f"Upload mismatch (Desired: {desired.upload_limit_kbps}k, Observed: {observed.upload_limit_kbps}k)"
                )

            return PolicyEvaluationResult(
                enforcement_state=EnforcementState.OUT_OF_SYNC,
                sync_state=SyncState.DIVERGENT,
                operation_state=last_op_state,
                reason="Policy drift: " + "; ".join(diff_parts),
                can_reconcile=True,
                requires_preview=False,
            )

    @staticmethod
    def transition(
        current: EnforcementState,
        target: EnforcementState,
        operation_state: OperationState,
        verification_verified: bool = False,
    ) -> EnforcementState:
        """
        Validate and execute a formal state transition.
        Raises StateTransitionError if the transition violates core invariants.
        """
        # Invariant 1: Cannot transition to CONFIRMED without verification or matching observed state
        if target == EnforcementState.CONFIRMED and not verification_verified:
            raise StateTransitionError(
                "Invariant Violation: Cannot transition to CONFIRMED without positive verification from backend."
            )

        # Invariant 2: Cannot transition to CONFIRMED if operation failed
        if target == EnforcementState.CONFIRMED and operation_state in (
            OperationState.FAILED,
            OperationState.TIMED_OUT,
            OperationState.CANCELLED,
        ):
            raise StateTransitionError(
                f"Invariant Violation: Cannot transition to CONFIRMED when operation state is {operation_state.value}."
            )

        return target
