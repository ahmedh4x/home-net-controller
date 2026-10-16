"""
Policy and Drift Calculation Domain Logic.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from netcutter.domain.models import DevicePolicyState, InternetAccessState


@dataclass
class PolicyDiff:
    """Represents differences between Desired and Observed network policies."""
    needs_block: bool = False
    needs_unblock: bool = False
    needs_download_update: bool = False
    needs_upload_update: bool = False
    needs_download_remove: bool = False
    needs_upload_remove: bool = False

    @property
    def has_drift(self) -> bool:
        return any([
            self.needs_block,
            self.needs_unblock,
            self.needs_download_update,
            self.needs_upload_update,
            self.needs_download_remove,
            self.needs_upload_remove,
        ])

    def describe(self) -> str:
        changes = []
        if self.needs_block:
            changes.append("Block Internet Access")
        elif self.needs_unblock:
            changes.append("Unblock Internet Access")
        if self.needs_download_update:
            changes.append("Update Download Rate")
        elif self.needs_download_remove:
            changes.append("Remove Download Limit")
        if self.needs_upload_update:
            changes.append("Update Upload Rate")
        elif self.needs_upload_remove:
            changes.append("Remove Upload Limit")
        return ", ".join(changes) if changes else "In Sync"


def calculate_policy_diff(
    desired: DevicePolicyState, observed: Optional[DevicePolicyState]
) -> PolicyDiff:
    """Compute exact divergence between desired and observed policy states."""
    if observed is None:
        return PolicyDiff(
            needs_block=desired.is_blocked,
            needs_download_update=desired.has_download_limit,
            needs_upload_update=desired.has_upload_limit,
        )

    needs_block = (
        desired.internet_access == InternetAccessState.BLOCKED
        and observed.internet_access != InternetAccessState.BLOCKED
    )
    needs_unblock = (
        desired.internet_access == InternetAccessState.ALLOWED
        and observed.internet_access == InternetAccessState.BLOCKED
    )

    needs_dl_update = (
        desired.download_limit_kbps > 0
        and desired.download_limit_kbps != observed.download_limit_kbps
    )
    needs_dl_remove = (
        desired.download_limit_kbps == 0 and observed.download_limit_kbps > 0
    )

    needs_ul_update = (
        desired.upload_limit_kbps > 0
        and desired.upload_limit_kbps != observed.upload_limit_kbps
    )
    needs_ul_remove = (
        desired.upload_limit_kbps == 0 and observed.upload_limit_kbps > 0
    )

    return PolicyDiff(
        needs_block=needs_block,
        needs_unblock=needs_unblock,
        needs_download_update=needs_dl_update,
        needs_upload_update=needs_ul_update,
        needs_download_remove=needs_dl_remove,
        needs_upload_remove=needs_ul_remove,
    )
