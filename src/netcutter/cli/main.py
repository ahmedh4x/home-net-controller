"""
Command-Line Interface (CLI) for NetCutter.
Consumes the same core application services and AI Assistant as the GUI.
Supports human-readable and machine-readable JSON output formats.
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Dict, List

from netcutter.diagnostics.health import DiagnosticsService
from netcutter.domain.models import Device, DomainMatchType, DomainScope, GatewayConfig
from netcutter.persistence.database import Database
from netcutter.persistence.repository import (
    AuditRepository,
    DeviceRepository,
    GatewayRepository,
)
from netcutter.persistence.secret_store import SecretStore
from netcutter.services.ai_assistant import AIAssistantService
from netcutter.services.audit_service import AuditService
from netcutter.services.device_service import DeviceService
from netcutter.services.domain_blocking_service import DomainBlockingService
from netcutter.services.gateway_manager import GatewayManager
from netcutter.services.identity_engine import IdentityEngine
from netcutter.services.policy_service import PolicyService
from netcutter.services.reconciliation import ReconciliationEngine



def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="hnc",
        description="Home Net Controller (HNC) — Network Management, Policy Control & Diagnostics CLI",
    )
    parser.add_argument("--version", action="version", version="Home Net Controller (HNC) v0.0.1")
    parser.add_argument("--json", action="store_true", help="Output results in JSON format")
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # devices
    p_dev = subparsers.add_parser("devices", help="List discovered network devices")
    p_dev.add_argument("--refresh", action="store_true", help="Trigger gateway discovery scan first")
    p_dev.add_argument("--json", action="store_true", help="Output device list as JSON")

    # block
    p_block = subparsers.add_parser("block", help="Block Internet access for a device")
    p_block.add_argument("target", help="Device MAC, GUID, or name")
    p_block.add_argument("--json", action="store_true", help="Output result as JSON")

    # unblock
    p_unblock = subparsers.add_parser("unblock", help="Unblock Internet access for a device")
    p_unblock.add_argument("target", help="Device MAC, GUID, or name")
    p_unblock.add_argument("--json", action="store_true", help="Output result as JSON")

    # limit
    p_limit = subparsers.add_parser("limit", help="Set bandwidth rate shaping for a device")
    p_limit.add_argument("target", help="Device MAC, GUID, or name")
    p_limit.add_argument("--download", type=int, default=0, help="Download rate limit in Kbps (0=unlimited)")
    p_limit.add_argument("--upload", type=int, default=0, help="Upload rate limit in Kbps (0=unlimited)")
    p_limit.add_argument("--json", action="store_true", help="Output result as JSON")

    # remove-limit
    p_unlimit = subparsers.add_parser("remove-limit", help="Remove bandwidth rate limits")
    p_unlimit.add_argument("target", help="Device MAC, GUID, or name")
    p_unlimit.add_argument("--json", action="store_true", help="Output result as JSON")

    # reconcile
    p_rec = subparsers.add_parser("reconcile", help="Run reconciliation pass between desired and observed state")
    p_rec.add_argument("--json", action="store_true", help="Output reconciliation results as JSON")

    # diagnostics
    p_diag = subparsers.add_parser("diagnostics", help="Run gateway diagnostics and capability audit")
    p_diag.add_argument("--json", action="store_true", help="Output diagnostics report as JSON")

    # gateways
    p_gw = subparsers.add_parser("gateways", help="List configured router gateways")
    p_gw.add_argument("--json", action="store_true", help="Output gateways list as JSON")

    # events
    p_ev = subparsers.add_parser("events", help="View recent audit logs")
    p_ev.add_argument("--limit", type=int, default=20, help="Number of events to display")
    p_ev.add_argument("--json", action="store_true", help="Output audit events as JSON")

    # ai
    p_ai = subparsers.add_parser("ai", help="Query AI Network Copilot for security analysis or troubleshooting")
    p_ai.add_argument("query", help="Question or prompt for AI Copilot")
    p_ai.add_argument("--json", action="store_true", help="Output AI response as JSON")

    # domains
    p_domains = subparsers.add_parser("domains", help="Manage website & domain blocking rules")
    p_domains.add_argument("--json", action="store_true", help="Output results in JSON format")
    p_domains_sub = p_domains.add_subparsers(dest="domains_action", help="Domain action")

    # domains list
    p_dlist = p_domains_sub.add_parser("list", help="List all configured domain rules")
    p_dlist.add_argument("--json", action="store_true", help="Output as JSON")

    # domains add
    p_dadd = p_domains_sub.add_parser("add", help="Add a new domain blocking rule")
    p_dadd.add_argument("domain", help="Domain to block (e.g. example.com)")
    p_dadd.add_argument("--exact", action="store_true", help="Match exact domain only (exclude subdomains)")
    p_dadd.add_argument("--device", help="Target device MAC, GUID, or name")
    p_dadd.add_argument("--notes", help="Optional notes")
    p_dadd.add_argument("--json", action="store_true", help="Output as JSON")

    # domains remove
    p_drem = p_domains_sub.add_parser("remove", help="Remove a domain blocking rule")
    p_drem.add_argument("target", help="Rule ID or domain name to remove")
    p_drem.add_argument("--json", action="store_true", help="Output as JSON")

    # domains verify
    p_dver = p_domains_sub.add_parser("verify", help="Audit and verify live enforcement status")
    p_dver.add_argument("--json", action="store_true", help="Output as JSON")

    # domains events
    p_devt = p_domains_sub.add_parser("events", help="View recent intercepted domain events")
    p_devt.add_argument("--limit", type=int, default=50, help="Max events to display")
    p_devt.add_argument("--json", action="store_true", help="Output as JSON")

    return parser



def main(args=None):
    parser = build_parser()
    parsed = parser.parse_args(args)

    if not parsed.command:
        parser.print_help()
        sys.exit(0)

    # Determine whether global or subcommand requested JSON
    is_json = getattr(parsed, "json", False)

    db = Database()
    secret_store = SecretStore()
    device_repo = DeviceRepository(db)
    gw_repo = GatewayRepository(db)
    audit_repo = AuditRepository(db)

    identity_engine = IdentityEngine(db, device_repo)
    gw_manager = GatewayManager(db, gw_repo, secret_store)
    device_service = DeviceService(device_repo, identity_engine, gw_manager)
    policy_service = PolicyService(device_repo, audit_repo, gw_manager)
    audit_service = AuditService(audit_repo)
    diag_service = DiagnosticsService(gw_manager)
    reconcile_engine = ReconciliationEngine(device_repo, audit_repo, gw_manager, policy_service)
    ai_service = AIAssistantService(device_repo, gw_repo, audit_repo, gw_manager)

    # Activate gateway
    all_gws = gw_repo.get_all()
    if not all_gws:
        from netcutter.domain.models import BackendType
        default_gw = GatewayConfig(
            name="Simulator Gateway (Mock)",
            host="127.0.0.1",
            port=22,
            backend_type=BackendType.MOCK,
            username="admin",
            is_active=True,
        )
        gw_repo.upsert(default_gw)
        active_gw = default_gw
    else:
        active_gw = gw_repo.get_active() or all_gws[0]

    if active_gw:
        gw_manager.set_active_gateway(active_gw.gateway_id)

    def find_device(target: str) -> Device | None:
        # Check by GUID first, then MAC, then display name
        dev = device_repo.get_by_guid(target)
        if not dev:
            dev = device_repo.get_by_mac(target)
        if not dev:
            all_devs = device_repo.get_all()
            for d in all_devs:
                if d.display_name.lower() == target.lower() or (d.hostname and d.hostname.lower() == target.lower()):
                    return d
        return dev

    if parsed.command == "devices":
        if parsed.refresh:
            if not is_json:
                print("[*] Polling active gateway for network discovery...")
            device_service.refresh_discovery()
        devices = device_service.get_all_devices()
        if is_json:
            out = [
                {
                    "device_guid": d.device_guid,
                    "name": d.display_name,
                    "mac": d.primary_mac,
                    "ipv4": d.primary_ipv4,
                    "online": d.is_online,
                    "policy_blocked": d.desired_policy.is_blocked,
                    "download_limit_kbps": d.desired_policy.download_limit_kbps,
                    "upload_limit_kbps": d.desired_policy.upload_limit_kbps,
                    "policy_status": d.policy_status.value,
                    "is_randomized_mac": d.is_randomized_mac,
                }
                for d in devices
            ]
            print(json.dumps(out, indent=2))
        else:
            print(f"\nDiscovered Devices ({len(devices)} total):")
            print(f"{'NAME':<20} {'STATE':<8} {'MAC':<18} {'IPv4':<16} {'INTERNET':<10} {'DL (Kbps)':<10} {'UL (Kbps)':<10} {'SYNC':<12}")
            print("-" * 110)
            for d in devices:
                state = "ONLINE" if d.is_online else "OFFLINE"
                policy = "BLOCKED" if d.desired_policy.is_blocked else "ALLOWED"
                dl = str(d.desired_policy.download_limit_kbps) if d.desired_policy.download_limit_kbps else "Unlim"
                ul = str(d.desired_policy.upload_limit_kbps) if d.desired_policy.upload_limit_kbps else "Unlim"
                print(f"{d.display_name[:19]:<20} {state:<8} {d.primary_mac:<18} {d.primary_ipv4:<16} {policy:<10} {dl:<10} {ul:<10} {d.policy_status.value:<12}")

    elif parsed.command == "block":
        dev = find_device(parsed.target)
        if not dev:
            if is_json:
                print(json.dumps({"success": False, "error": f"Device '{parsed.target}' not found"}))
            else:
                print(f"[ERROR] Device '{parsed.target}' not found.")
            sys.exit(1)
        if not is_json:
            print(f"[*] Enforcing Internet Block on {dev.display_name} ({dev.primary_mac})...")
        res = policy_service.block_device(dev.device_guid)
        if is_json:
            print(json.dumps({"success": res.success, "details": res.details, "error": res.error, "verified": res.verification_verified}))
        else:
            if res.success:
                print(f"[+] SUCCESS: {res.details} (Verified on router: {res.verification_verified})")
            else:
                print(f"[-] FAILED: {res.error}")
                sys.exit(1)

    elif parsed.command == "unblock":
        dev = find_device(parsed.target)
        if not dev:
            if is_json:
                print(json.dumps({"success": False, "error": f"Device '{parsed.target}' not found"}))
            else:
                print(f"[ERROR] Device '{parsed.target}' not found.")
            sys.exit(1)
        if not is_json:
            print(f"[*] Removing Internet Block for {dev.display_name} ({dev.primary_mac})...")
        res = policy_service.unblock_device(dev.device_guid)
        if is_json:
            print(json.dumps({"success": res.success, "details": res.details, "error": res.error, "verified": res.verification_verified}))
        else:
            if res.success:
                print(f"[+] SUCCESS: {res.details} (Verified on router: {res.verification_verified})")
            else:
                print(f"[-] FAILED: {res.error}")
                sys.exit(1)

    elif parsed.command == "limit":
        dev = find_device(parsed.target)
        if not dev:
            if is_json:
                print(json.dumps({"success": False, "error": f"Device '{parsed.target}' not found"}))
            else:
                print(f"[ERROR] Device '{parsed.target}' not found.")
            sys.exit(1)
        if not is_json:
            print(f"[*] Applying Bandwidth Shaping on {dev.display_name}: DL={parsed.download}k, UL={parsed.upload}k...")
        res = policy_service.set_bandwidth_limits(dev.device_guid, parsed.download, parsed.upload)
        if is_json:
            print(json.dumps({"success": res.success, "details": res.details, "error": res.error}))
        else:
            if res.success:
                print(f"[+] SUCCESS: {res.details}")
            else:
                print(f"[-] FAILED: {res.error}")
                sys.exit(1)

    elif parsed.command == "remove-limit":
        dev = find_device(parsed.target)
        if not dev:
            if is_json:
                print(json.dumps({"success": False, "error": f"Device '{parsed.target}' not found"}))
            else:
                print(f"[ERROR] Device '{parsed.target}' not found.")
            sys.exit(1)
        if not is_json:
            print(f"[*] Removing Bandwidth Shaping for {dev.display_name}...")
        res = policy_service.remove_bandwidth_limits(dev.device_guid)
        if is_json:
            print(json.dumps({"success": res.success, "details": res.details, "error": res.error}))
        else:
            if res.success:
                print(f"[+] SUCCESS: {res.details}")
            else:
                print(f"[-] FAILED: {res.error}")
                sys.exit(1)

    elif parsed.command == "reconcile":
        if not is_json:
            print("[*] Executing state reconciliation cycle...")
        results = reconcile_engine.reconcile_once()
        if is_json:
            out = {guid: status.value if hasattr(status, "value") else str(status) for guid, status in results.items()}
            print(json.dumps(out, indent=2))
        else:
            print(f"[+] Evaluated {len(results)} devices. Reconciliation status:")
            for guid, status in results.items():
                print(f"    - {guid}: {status}")

    elif parsed.command == "diagnostics":
        if not is_json:
            print("[*] Running full gateway diagnostics...")
        report = diag_service.run_full_diagnostics()
        if is_json:
            out = {
                "gateway_name": report.gateway_name,
                "overall_healthy": report.overall_healthy,
                "timestamp": report.timestamp.isoformat(),
                "checks": [{"name": c.name, "passed": c.passed, "details": c.details, "latency_ms": c.latency_ms} for c in report.checks],
                "capabilities": report.capabilities_matrix,
            }
            print(json.dumps(out, indent=2))
        else:
            print(f"\nGateway Diagnostics Report: {report.gateway_name}")
            print(f"Overall Status: {'HEALTHY' if report.overall_healthy else 'ISSUES DETECTED'}\n")
            print("Checks:")
            for c in report.checks:
                mark = "[PASS]" if c.passed else "[FAIL]"
                print(f"  {mark:<7} {c.name}: {c.details}")
            print("\nSupported Capabilities:")
            for cap, val in report.capabilities_matrix.items():
                print(f"  • {cap:<35}: {val}")

    elif parsed.command == "gateways":
        gws = gw_repo.get_all()
        if is_json:
            out = [
                {
                    "gateway_id": g.gateway_id,
                    "name": g.name,
                    "host": g.host,
                    "port": g.port,
                    "backend_type": g.backend_type.value,
                    "is_active": g.is_active,
                    "status": g.status.value,
                }
                for g in gws
            ]
            print(json.dumps(out, indent=2))
        else:
            print(f"\nConfigured Gateways ({len(gws)} total):")
            for g in gws:
                active = "★ ACTIVE" if g.is_active else "  INACTIVE"
                print(f"{active} | {g.name:<25} | {g.host}:{g.port} [{g.backend_type.value}] | Status: {g.status.value}")

    elif parsed.command == "events":
        evs = audit_service.get_recent_events(parsed.limit)
        if is_json:
            out = [
                {
                    "timestamp": e.timestamp.isoformat(),
                    "status": e.status,
                    "action": e.action.value,
                    "device_name": e.device_name,
                    "details": e.details,
                }
                for e in evs
            ]
            print(json.dumps(out, indent=2))
        else:
            print(f"\nAudit Log (Last {len(evs)} events):")
            for e in evs:
                print(f"{e.timestamp.strftime('%Y-%m-%d %H:%M:%S')} [{e.status}] {e.action.value:<22} target={e.device_name or 'Gateway'} - {e.details}")

    elif parsed.command == "ai":
        resp = ai_service.query(parsed.query)
        if is_json:
            print(json.dumps(resp.to_dict(), indent=2))
        else:
            print(f"\n[AI Copilot ({resp.source_model})]")
            print(f"Summary: {resp.summary}\n")
            print(resp.markdown_details)
            if resp.action_proposals:
                print("\nProposed Actions (Verification Required):")
                for p in resp.action_proposals:
                    print(f"  • [{p.risk_level.value}] {p.action_type}: {p.explanation}")

    elif parsed.command == "domains":
        domain_service = DomainBlockingService(db, gateway_manager=gw_manager, device_service=device_service)
        action = getattr(parsed, "domains_action", "list") or "list"

        if action == "list":
            rules = domain_service.get_rules()
            if is_json:
                out = [
                    {
                        "rule_id": r.rule_id,
                        "domain": r.domain,
                        "match_type": r.match_type.value,
                        "target_scope": r.target_scope.value,
                        "target_device": r.display_scope,
                        "is_enabled": r.is_enabled,
                        "status": r.enforcement_status.value,
                        "hits": r.hits_count,
                        "created_at": r.created_at.isoformat(),
                        "last_verified": r.last_verified_at.isoformat() if r.last_verified_at else None,
                    }
                    for r in rules
                ]
                print(json.dumps(out, indent=2))
            else:
                print(f"\nConfigured Domain Rules ({len(rules)} total):")
                if not rules:
                    print("  No domain blocking rules configured.")
                for r in rules:
                    en_str = "ENABLED" if r.is_enabled else "DISABLED"
                    print(f"[{en_str}] {r.domain:<28} | {r.display_match_type:<20} | Scope: {r.display_scope:<25} | Status: {r.enforcement_status.value} (Hits: {r.hits_count})")

        elif action == "add":
            target_device_guid = None
            scope = DomainScope.GLOBAL
            if parsed.device:
                scope = DomainScope.DEVICE
                matched_dev = None
                for d in device_service.get_all_devices():
                    if parsed.device.lower() in (d.primary_mac.lower(), d.device_guid.lower(), d.display_name.lower()):
                        matched_dev = d
                        break
                if not matched_dev:
                    print(f"Error: Target device '{parsed.device}' not found.")
                    sys.exit(1)
                target_device_guid = matched_dev.device_guid

            match_type = DomainMatchType.EXACT if parsed.exact else DomainMatchType.SUBDOMAIN
            ok, rule, err = domain_service.add_rule(
                raw_domain=parsed.domain,
                match_type=match_type,
                target_scope=scope,
                target_device_guid=target_device_guid,
                notes=parsed.notes,
            )
            if is_json:
                print(json.dumps({"success": ok, "rule_id": rule.rule_id if rule else None, "error": err}, indent=2))
            else:
                if ok and rule:
                    print(f"Successfully added domain rule for '{rule.domain}' ({rule.match_type.value}). Status: {rule.enforcement_status.value}")
                else:
                    print(f"Failed to add rule: {err}")
                    sys.exit(1)

        elif action == "remove":
            target_rule_id = parsed.target
            for r in domain_service.get_rules():
                if r.domain == parsed.target:
                    target_rule_id = r.rule_id
                    break
            ok, err = domain_service.delete_rule(target_rule_id)
            if is_json:
                print(json.dumps({"success": ok, "error": err}, indent=2))
            else:
                if ok:
                    print(f"Successfully removed domain rule '{parsed.target}'.")
                else:
                    print(f"Failed to remove rule: {err or 'Rule not found'}")
                    sys.exit(1)

        elif action == "verify":
            results = domain_service.verify_all_rules()
            if is_json:
                out = {rid: {"success": s, "details": d} for rid, (s, d) in results.items()}
                print(json.dumps(out, indent=2))
            else:
                print("\nDomain Rules Live Verification Audit:")
                for rid, (s, d) in results.items():
                    rule = domain_service.get_rule(rid)
                    dom = rule.domain if rule else rid
                    status = "✓ VERIFIED" if s else "✗ FAILED"
                    print(f"  {status} {dom:<25}: {d}")

        elif action == "events":
            evts = domain_service.get_recent_events(parsed.limit)
            if is_json:
                out = [
                    {
                        "event_id": e.event_id,
                        "domain": e.domain,
                        "device": e.device_name or e.client_mac,
                        "client_ip": e.client_ip,
                        "action": e.action,
                        "mechanism": e.mechanism,
                        "timestamp": e.timestamp.isoformat(),
                    }
                    for e in evts
                ]
                print(json.dumps(out, indent=2))
            else:
                print(f"\nRecent Blocked Domain Events ({len(evts)} total):")
                for e in evts:
                    print(f"{e.timestamp.strftime('%H:%M:%S')} [{e.action}] {e.domain:<25} target={e.device_name or e.client_mac} ({e.client_ip}) via {e.mechanism}")



if __name__ == "__main__":
    main()
