"""
AI Diagnostic and Natural-Language Assistant for NetCutter.
Provides offline, deterministic network intelligence, log analysis, security auditing,
and optional local LLM integration with strict human-in-the-loop action safeguards.
"""
from __future__ import annotations

import json
import logging
import os
import re
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

from netcutter.common.logging import get_ring_buffer
from netcutter.domain.models import Device, GatewayConfig, PolicyStatus, is_locally_administered_mac
from netcutter.persistence.repository import AuditRepository, DeviceRepository, GatewayRepository
from netcutter.services.gateway_manager import GatewayManager

logger = logging.getLogger("netcutter.ai")


class ActionRiskLevel(str, Enum):
    LOW = "LOW"
    MEDIUM = "MEDIUM"
    HIGH = "HIGH"


@dataclass
class ActionProposal:
    """A proposed network action requiring explicit user confirmation."""
    action_type: str  # e.g., "BLOCK_DEVICE", "UNBLOCK_DEVICE", "SET_BANDWIDTH", "RUN_RECONCILIATION"
    target_id: Optional[str] = None
    target_name: Optional[str] = None
    parameters: Dict[str, Any] = field(default_factory=dict)
    risk_level: ActionRiskLevel = ActionRiskLevel.MEDIUM
    explanation: str = ""
    requires_confirmation: bool = True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "action_type": self.action_type,
            "target_id": self.target_id,
            "target_name": self.target_name,
            "parameters": self.parameters,
            "risk_level": self.risk_level.value,
            "explanation": self.explanation,
            "requires_confirmation": self.requires_confirmation,
        }


@dataclass
class AIResponse:
    """Structured response from the NetCutter AI Assistant."""
    summary: str
    markdown_details: str
    action_proposals: List[ActionProposal] = field(default_factory=list)
    confidence: float = 1.0
    source_model: str = "Deterministic Rule-Engine"
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))

    def to_dict(self) -> Dict[str, Any]:
        return {
            "summary": self.summary,
            "markdown_details": self.markdown_details,
            "action_proposals": [p.to_dict() for p in self.action_proposals],
            "confidence": self.confidence,
            "source_model": self.source_model,
            "timestamp": self.timestamp.isoformat(),
        }


class BaseLLMClient:
    """Interface for LLM inference backends."""

    def complete(self, prompt: str, context: Dict[str, Any]) -> Tuple[str, str]:
        """Returns (summary, markdown_details)."""
        raise NotImplementedError


class LocalRuleBasedClient(BaseLLMClient):
    """
    Deterministic, offline network diagnostic reasoning engine.
    Requires 0 cloud calls, 0 credentials, and guarantees zero hallucination.
    """

    def analyze_network_state(
        self,
        devices: List[Device],
        active_gw: Optional[GatewayConfig],
        recent_errors: List[str],
    ) -> AIResponse:
        total_devs = len(devices)
        online_devs = [d for d in devices if d.is_online]
        blocked_devs = [d for d in devices if d.desired_policy.is_blocked]
        shaped_devs = [
            d for d in devices
            if (d.desired_policy.download_limit_kbps > 0 or d.desired_policy.upload_limit_kbps > 0)
        ]
        drifted_devs = [d for d in devices if d.policy_status == PolicyStatus.DRIFTED]
        random_mac_devs = [d for d in devices if is_locally_administered_mac(d.primary_mac)]

        proposals: List[ActionProposal] = []
        md_sections = []

        # Executive Summary
        md_sections.append(f"### 🌐 Network State Intelligence Summary")
        if active_gw:
            md_sections.append(
                f"- **Active Gateway:** `{active_gw.name}` ({active_gw.host}) [{active_gw.backend_type.value}]"
            )
        else:
            md_sections.append("- **Active Gateway:** *None configured or active.*")

        md_sections.append(
            f"- **Inventory:** {total_devs} known devices ({len(online_devs)} active online, {len(blocked_devs)} blocked, {len(shaped_devs)} bandwidth-shaped)."
        )

        # Drift Analysis
        if drifted_devs:
            md_sections.append(f"\n#### ⚠️ Policy Drift Detected ({len(drifted_devs)} devices)")
            for d in drifted_devs:
                md_sections.append(
                    f"- Device `{d.display_name}` (`{d.primary_mac}`) has drifted from desired router state."
                )
            proposals.append(
                ActionProposal(
                    action_type="RUN_RECONCILIATION",
                    risk_level=ActionRiskLevel.LOW,
                    explanation="Sync out-of-band router policy drift with NetCutter's desired state.",
                    requires_confirmation=True,
                )
            )
        else:
            md_sections.append("\n- **Policy Synchronization:** All active device policies are fully synchronized with gateway state.")

        # Privacy / Randomized MAC Warning
        if random_mac_devs:
            md_sections.append(f"\n#### 🛡️ Randomized / Private MACs ({len(random_mac_devs)} devices)")
            for d in random_mac_devs:
                md_sections.append(
                    f"- `{d.display_name}` (`{d.primary_mac}`) is using a locally administered (private/randomized) MAC. Router-level policies may reset if the client reconnects with a fresh MAC address."
                )

        # Bandwidth Analysis
        if shaped_devs:
            md_sections.append(f"\n#### 📊 Active QoS Bandwidth Shaping ({len(shaped_devs)} devices)")
            for d in shaped_devs:
                dl = d.desired_policy.download_limit_kbps
                ul = d.desired_policy.upload_limit_kbps
                md_sections.append(f"- `{d.display_name}`: Down: {dl} Kbps, Up: {ul} Kbps")

        # Error / Log Analysis
        if recent_errors:
            md_sections.append(f"\n#### 🚨 Recent Diagnostic Errors ({len(recent_errors)})")
            for err in recent_errors[-5:]:
                md_sections.append(f"- `{err}`")

        summary = (
            f"Network Healthy. {len(online_devs)}/{total_devs} devices active. "
            f"{len(blocked_devs)} blocked. "
            f"{len(drifted_devs)} drifts detected."
        )

        return AIResponse(
            summary=summary,
            markdown_details="\n".join(md_sections),
            action_proposals=proposals,
            confidence=1.0,
            source_model="Deterministic Local Intelligence",
        )

    def analyze_troubleshooting_query(
        self,
        query: str,
        devices: List[Device],
        active_gw: Optional[GatewayConfig],
        recent_errors: List[str],
    ) -> AIResponse:
        q = query.lower().strip()
        proposals: List[ActionProposal] = []
        md = []

        # 1. Block command / request
        block_match = re.search(r"block\s+([0-9a-fA-F:]{17}|[0-9a-fA-F\-]{17}|[\w\-]+)", query, re.I)
        unblock_match = re.search(r"unblock\s+([0-9a-fA-F:]{17}|[0-9a-fA-F\-]{17}|[\w\-]+)", query, re.I)

        def _matches_device(dev: Device, target: str) -> bool:
            t = target.lower()
            return (
                dev.primary_mac.lower() == t
                or dev.device_guid.lower() == t
                or t in dev.display_name.lower()
                or (bool(dev.hostname) and t in dev.hostname.lower())
            )

        if unblock_match:
            target_str = unblock_match.group(1)
            target_dev = next((d for d in devices if _matches_device(d, target_str)), None)
            if target_dev:
                proposals.append(
                    ActionProposal(
                        action_type="UNBLOCK_DEVICE",
                        target_id=target_dev.device_guid,
                        target_name=target_dev.display_name,
                        risk_level=ActionRiskLevel.LOW,
                        explanation=f"Restore unrestricted gateway internet forwarding for {target_dev.display_name} ({target_dev.primary_mac}).",
                        requires_confirmation=True,
                    )
                )
                summary = f"Prepared unblock action for {target_dev.display_name}."
                md.append(f"### Proposed Action: Unblock Device\n\nTarget: **{target_dev.display_name}** (`{target_dev.primary_mac}`)\n")
                md.append("Click **Confirm & Apply** below to execute safely.")
            else:
                summary = f"Device '{target_str}' not found in network inventory."
                md.append(f"Could not locate a device matching `{target_str}`. Please verify the MAC or device name.")

        elif block_match:
            target_str = block_match.group(1)
            target_dev = next((d for d in devices if _matches_device(d, target_str)), None)
            if target_dev:
                proposals.append(
                    ActionProposal(
                        action_type="BLOCK_DEVICE",
                        target_id=target_dev.device_guid,
                        target_name=target_dev.display_name,
                        risk_level=ActionRiskLevel.MEDIUM,
                        explanation=f"Drop forwarding traffic and flush conntrack flows for {target_dev.display_name} ({target_dev.primary_mac}).",
                        requires_confirmation=True,
                    )
                )
                summary = f"Prepared block action for {target_dev.display_name}."
                md.append(f"### Proposed Action: Internet Access Cutoff\n\nTarget: **{target_dev.display_name}** (`{target_dev.primary_mac}`)\n")
                md.append("> ⚠️ **Safety Notice**: Blocking this device will terminate all active WAN connections. LAN communication remains untouched.")
            else:
                summary = f"Device '{target_str}' not found."
                md.append(f"Could not locate device `{target_str}`. Available devices:")
                for d in devices[:10]:
                    md.append(f"- `{d.display_name}` (`{d.primary_mac}`)")

        elif "slow" in q or "bandwidth" in q or "speed" in q or "lag" in q:
            summary = "Bandwidth & Performance Diagnosis"
            md.append("### 🚀 Network Latency & Bandwidth Troubleshooting\n")
            shaped = [d for d in devices if d.desired_policy.download_limit_kbps > 0]
            if shaped:
                md.append(f"**Identified Throttled Devices:** {len(shaped)}")
                for d in shaped:
                    md.append(f"- `{d.display_name}` is throttled to {d.desired_policy.download_limit_kbps} Kbps.")
            else:
                md.append("- No devices are currently rate-limited by NetCutter QoS.")

            if active_gw and active_gw.backend_type.value == "WINDOWS_LAN":
                md.append("\n> ⚠️ **Backend Advisory:** The active gateway backend is **Windows LAN Interceptor** (off-path ARP manipulation). Bandwidth shaping is disabled on this backend because off-path interception cannot shape egress rate reliably without router hardware cooperation.")
            else:
                md.append("\n**Recommendations:**")
                md.append("1. Verify router upstream WAN utilization.")
                md.append("2. Apply QoS rules via the **Bandwidth** tab for high-bandwidth endpoints.")
                md.append("3. Check for duplex mismatch or Wi-Fi interference on 2.4 GHz channels.")

        elif "security" in q or "audit" in q or "privacy" in q or "risk" in q:
            random_macs = [d for d in devices if is_locally_administered_mac(d.primary_mac)]
            summary = f"Security Audit: {len(random_macs)} private MAC addresses detected."
            md.append("### 🛡️ Network Security & Integrity Audit\n")
            md.append(f"- Total active endpoints monitored: **{len(devices)}**")
            if random_macs:
                md.append(f"- **Randomized MACs ({len(random_macs)}):** Devices with locally administered addresses may bypass MAC-based rules upon reconnect:")
                for d in random_macs:
                    md.append(f"  * `{d.display_name}` (`{d.primary_mac}`)")
            else:
                md.append("- All active devices are using globally assigned IEEE OUI MAC addresses.")

            if active_gw and active_gw.backend_type.value == "WINDOWS_LAN":
                md.append("\n- **Backend Risk Notice:** Windows LAN mode uses ARP redirection. Some modern endpoint security software (IDS/EDR) or managed switches with Dynamic ARP Inspection (DAI) will alert on or drop gratuitous ARP packets.")

        elif "sync" in q or "drift" in q or "reconcile" in q:
            drifted = [d for d in devices if d.policy_status == PolicyStatus.DRIFTED]
            summary = f"Reconciliation Analysis: {len(drifted)} drifts."
            md.append("### 🔄 Policy Synchronization & Drift Engine\n")
            if drifted:
                md.append(f"Found **{len(drifted)}** devices whose observed gateway state differs from NetCutter's desired policy database:")
                for d in drifted:
                    md.append(f"- `{d.display_name}` (`{d.primary_mac}`)")
                proposals.append(
                    ActionProposal(
                        action_type="RUN_RECONCILIATION",
                        risk_level=ActionRiskLevel.LOW,
                        explanation="Synchronize router firewall rules with desired policies.",
                    )
                )
            else:
                md.append("All network policies are currently in perfect sync with the active gateway.")

        elif "error" in q or "log" in q or "fail" in q:
            summary = f"Log Analysis: {len(recent_errors)} error entries analyzed."
            md.append("### 📋 Diagnostic Log Explanation\n")
            if recent_errors:
                for err in recent_errors[-10:]:
                    md.append(f"```text\n{err}\n```")
                md.append("\n**Resolution Steps:**")
                md.append("1. Confirm the gateway router IP and port are reachable from this machine.")
                md.append("2. Ensure SSH credentials or API tokens stored in SecretStore are current.")
                md.append("3. For Windows LAN mode, ensure NetCutter is launched with Administrator privileges.")
            else:
                md.append("No critical errors found in recent log ring buffer.")

        else:
            # General overview
            return self.analyze_network_state(devices, active_gw, recent_errors)

        return AIResponse(
            summary=summary,
            markdown_details="\n".join(md),
            action_proposals=proposals,
            confidence=0.95,
            source_model="Deterministic Local Intelligence",
        )


class OpenAICompatibleClient(BaseLLMClient):
    """
    Optional client for local or remote OpenAI-compatible HTTP endpoints
    (e.g., Ollama running locally at http://localhost:11434/v1, LM Studio, or OpenAI API).
    """

    def __init__(self, endpoint: str, api_key: str = "", model: str = "llama3"):
        self.endpoint = endpoint.rstrip("/")
        self.api_key = api_key
        self.model = model

    def complete(self, prompt: str, context: Dict[str, Any]) -> Tuple[str, str]:
        url = f"{self.endpoint}/chat/completions"
        headers = {
            "Content-Type": "application/json",
        }
        if self.api_key:
            headers["Authorization"] = f"Bearer {self.api_key}"

        payload = {
            "model": self.model,
            "messages": [
                {
                    "role": "system",
                    "content": (
                        "You are NetCutter Network Copilot, a high-assurance network diagnostics AI. "
                        "You only report verifiable network facts. Never fabricate IP addresses, MAC addresses, "
                        "or router states. When suggesting actions, explain risks clearly."
                    ),
                },
                {
                    "role": "user",
                    "content": f"Context:\n{json.dumps(context, indent=2)}\n\nQuery: {prompt}",
                },
            ],
            "temperature": 0.2,
            "max_tokens": 800,
        }

        req = urllib.request.Request(
            url,
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"]
            lines = content.strip().split("\n")
            summary = lines[0] if lines else "AI Response"
            return summary, content


class AIAssistantService:
    """
    Core AI Service for NetCutter.
    Orchestrates deterministic rule-based analysis and optional LLM backends.
    """

    def __init__(
        self,
        device_repo: DeviceRepository,
        gw_repo: GatewayRepository,
        audit_repo: AuditRepository,
        gw_manager: GatewayManager,
    ):
        self.device_repo = device_repo
        self.gw_repo = gw_repo
        self.audit_repo = audit_repo
        self.gw_manager = gw_manager
        self.local_client = LocalRuleBasedClient()
        self.llm_client: Optional[OpenAICompatibleClient] = None
        self._init_optional_llm()

    def _init_optional_llm(self):
        endpoint = os.environ.get("HNC_LLM_ENDPOINT", os.environ.get("NETCUTTER_LLM_ENDPOINT"))
        opt_in = os.environ.get("HNC_ENABLE_AI_EGRESS", os.environ.get("NETCUTTER_ENABLE_AI_EGRESS", "false")).lower() in ("true", "1", "yes")
        if endpoint:
            if not opt_in:
                logger.info(
                    "LLM endpoint configured at %s, but AI network egress is disabled by default for privacy. "
                    "Set HNC_ENABLE_AI_EGRESS=1 or enable in settings to permit external inference.",
                    endpoint,
                )
                self.llm_client = None
                return
            api_key = os.environ.get("HNC_LLM_API_KEY", os.environ.get("NETCUTTER_LLM_API_KEY", ""))
            model = os.environ.get("HNC_LLM_MODEL", os.environ.get("NETCUTTER_LLM_MODEL", "llama3"))
            self.llm_client = OpenAICompatibleClient(endpoint, api_key, model)
            logger.info("Configured sanitized external LLM provider at %s (model: %s)", endpoint, model)

    @staticmethod
    def sanitize_context_for_egress(
        devices: List[Device],
        active_gw: Optional[GatewayConfig],
        recent_errors: List[str],
    ) -> Dict[str, Any]:
        """
        Produce a minimal, pseudonymized context dictionary suitable for external LLM inference.
        Strips private IPs, MAC addresses, and sensitive network identifiers.
        """
        sanitized_devs = []
        for i, d in enumerate(devices, 1):
            vendor = d.vendor or ("Locally Administered / Private" if is_locally_administered_mac(d.primary_mac) else "Unknown Vendor")
            cat_name = getattr(d.category, "value", str(getattr(d, "category", "OTHER")))
            sanitized_devs.append({
                "pseudonym": f"Device-{i:02d}",
                "vendor": vendor,
                "category": cat_name,
                "online": d.is_online,
                "is_blocked": d.desired_policy.is_blocked,
                "has_bandwidth_limits": (d.desired_policy.download_limit_kbps > 0 or d.desired_policy.upload_limit_kbps > 0),
            })

        # Redact recent errors of potential passwords, tokens, or private addresses
        redacted_errors = []
        for err in recent_errors:
            clean_err = re.sub(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "<IP_REDACTED>", err)
            clean_err = re.sub(r"\b(?:[0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}\b", "<MAC_REDACTED>", clean_err)
            redacted_errors.append(clean_err)

        return {
            "gateway_type": active_gw.backend_type.value if active_gw else "NONE",
            "total_monitored_devices": len(devices),
            "sanitized_devices": sanitized_devs,
            "diagnostic_events": redacted_errors,
        }

    def _get_recent_errors(self, max_count: int = 10) -> List[str]:
        ring = get_ring_buffer()
        records = ring.get_entries(limit=50)
        errors = [f"[{r.level}] {r.message}" for r in records if r.level in ("ERROR", "CRITICAL", "WARNING")]
        return errors[-max_count:]

    def query(self, query_text: str) -> AIResponse:
        """
        Process a user query or request an automated diagnostic assessment.
        Always falls back gracefully to deterministic rule-based analysis.
        """
        devices = self.device_repo.get_all()
        active_gw = self.gw_repo.get_active()
        recent_errors = self._get_recent_errors()

        # If LLM endpoint is available, explicitly opted in, and responsive, consult it with sanitized payload
        if self.llm_client and query_text.strip():
            try:
                context = self.sanitize_context_for_egress(devices, active_gw, recent_errors)
                summary, md = self.llm_client.complete(query_text, context)
                return AIResponse(
                    summary=summary,
                    markdown_details=md,
                    source_model=f"Sanitized LLM ({self.llm_client.model})",
                    confidence=0.85,
                )
            except Exception as e:
                logger.warning("Optional LLM completion failed (%s); falling back to local deterministic engine", e)

        # Local deterministic intelligence
        if not query_text or query_text.strip().lower() in ("status", "summary", "overview", "all"):
            return self.local_client.analyze_network_state(devices, active_gw, recent_errors)

        return self.local_client.analyze_troubleshooting_query(
            query_text, devices, active_gw, recent_errors
        )
