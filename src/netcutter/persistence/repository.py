"""
Repositories for NetCutter Domain Entities.
"""
from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import List, Optional
from netcutter.domain.models import (
    BackendType,
    BlockedDomainEvent,
    ConfidenceLevel,
    Device,
    DeviceCategory,
    DevicePolicyState,
    DomainBlockingRule,
    DomainEnforcementStatus,
    DomainMatchType,
    DomainScope,
    GatewayConfig,
    GatewayStatus,
    InternetAccessState,
    PolicyStatus,
)
from netcutter.domain.events import AuditAction, AuditEvent
from netcutter.persistence.database import Database


class DeviceRepository:
    def __init__(self, db: Database):
        self.db = db

    def get_all(self) -> List[Device]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            rows = cursor.execute("SELECT * FROM devices ORDER BY display_name ASC").fetchall()
            return [self._row_to_device(row) for row in rows]

    def get_by_guid(self, guid: str) -> Optional[Device]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            row = cursor.execute("SELECT * FROM devices WHERE device_guid = ?", (guid,)).fetchone()
            return self._row_to_device(row) if row else None

    def get_by_mac(self, mac: str) -> Optional[Device]:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            row = cursor.execute("SELECT * FROM devices WHERE primary_mac = ?", (mac.lower(),)).fetchone()
            if row:
                return self._row_to_device(row)
            
            # Check historical MACs if not primary
            all_rows = cursor.execute("SELECT * FROM devices").fetchall()
            for r in all_rows:
                historical = json.loads(r["historical_macs_json"])
                if mac.lower() in [m.lower() for m in historical]:
                    return self._row_to_device(r)
            return None

    def upsert(self, device: Device) -> None:
        with self.db.get_connection() as conn:
            cursor = conn.cursor()
            # If an existing device has the same primary_mac, preserve its device_guid
            existing = cursor.execute("SELECT device_guid FROM devices WHERE primary_mac = ?", (device.primary_mac.lower(),)).fetchone()
            if existing and existing["device_guid"] != device.device_guid:
                device.device_guid = existing["device_guid"]

            cursor.execute("""
            INSERT INTO devices (
                device_guid, display_name, primary_mac, historical_macs_json,
                ipv4_json, ipv6_json, hostname, vendor, dhcp_client_id, duid,
                first_seen, last_seen, is_online, confidence_level, is_randomized_mac,
                category, classification_basis,
                desired_internet_access, desired_dl_kbps, desired_ul_kbps,
                observed_internet_access, observed_dl_kbps, observed_ul_kbps,
                policy_status, last_policy_error, last_sync
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(device_guid) DO UPDATE SET
                display_name = excluded.display_name,
                primary_mac = excluded.primary_mac,
                historical_macs_json = excluded.historical_macs_json,
                ipv4_json = excluded.ipv4_json,
                ipv6_json = excluded.ipv6_json,
                hostname = excluded.hostname,
                vendor = excluded.vendor,
                dhcp_client_id = excluded.dhcp_client_id,
                duid = excluded.duid,
                last_seen = excluded.last_seen,
                is_online = excluded.is_online,
                confidence_level = excluded.confidence_level,
                is_randomized_mac = excluded.is_randomized_mac,
                category = excluded.category,
                classification_basis = excluded.classification_basis,
                desired_internet_access = excluded.desired_internet_access,
                desired_dl_kbps = excluded.desired_dl_kbps,
                desired_ul_kbps = excluded.desired_ul_kbps,
                observed_internet_access = excluded.observed_internet_access,
                observed_dl_kbps = excluded.observed_dl_kbps,
                observed_ul_kbps = excluded.observed_ul_kbps,
                policy_status = excluded.policy_status,
                last_policy_error = excluded.last_policy_error,
                last_sync = excluded.last_sync;
            """, (
                device.device_guid,
                device.display_name,
                device.primary_mac,
                json.dumps(device.historical_macs),
                json.dumps(device.ipv4_addresses),
                json.dumps(device.ipv6_addresses),
                device.hostname,
                device.vendor,
                device.dhcp_client_id,
                device.duid,
                device.first_seen.isoformat(),
                device.last_seen.isoformat(),
                1 if device.is_online else 0,
                device.confidence_level.value,
                1 if device.is_randomized_mac else 0,
                device.category.value if hasattr(device.category, "value") else str(device.category),
                device.classification_basis,
                device.desired_policy.internet_access.value,
                device.desired_policy.download_limit_kbps,
                device.desired_policy.upload_limit_kbps,
                device.observed_policy.internet_access.value,
                device.observed_policy.download_limit_kbps,
                device.observed_policy.upload_limit_kbps,
                device.policy_status.value,
                device.last_policy_error,
                device.last_sync.isoformat() if device.last_sync else None,
            ))
            conn.commit()

    def delete(self, guid: str) -> None:
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM devices WHERE device_guid = ?", (guid,))
            conn.commit()

    def _row_to_device(self, row) -> Device:
        first_seen = datetime.fromisoformat(row["first_seen"])
        last_seen = datetime.fromisoformat(row["last_seen"])
        last_sync = datetime.fromisoformat(row["last_sync"]) if row["last_sync"] else None
        
        desired = DevicePolicyState(
            internet_access=InternetAccessState(row["desired_internet_access"]),
            download_limit_kbps=row["desired_dl_kbps"],
            upload_limit_kbps=row["desired_ul_kbps"],
        )
        observed = DevicePolicyState(
            internet_access=InternetAccessState(row["observed_internet_access"]),
            download_limit_kbps=row["observed_dl_kbps"],
            upload_limit_kbps=row["observed_ul_kbps"],
        )

        category_str = row["category"] if "category" in row.keys() and row["category"] else "Unknown Device"
        try:
            category = DeviceCategory(category_str)
        except Exception:
            category = DeviceCategory.UNKNOWN

        classification_basis = row["classification_basis"] if "classification_basis" in row.keys() and row["classification_basis"] else ""

        return Device(
            device_guid=row["device_guid"],
            display_name=row["display_name"],
            primary_mac=row["primary_mac"],
            historical_macs=json.loads(row["historical_macs_json"]),
            ipv4_addresses=json.loads(row["ipv4_json"]),
            ipv6_addresses=json.loads(row["ipv6_json"]),
            hostname=row["hostname"],
            vendor=row["vendor"],
            dhcp_client_id=row["dhcp_client_id"],
            duid=row["duid"],
            first_seen=first_seen,
            last_seen=last_seen,
            is_online=bool(row["is_online"]),
            confidence_level=ConfidenceLevel(row["confidence_level"]),
            is_randomized_mac=bool(row["is_randomized_mac"]),
            category=category,
            classification_basis=classification_basis,
            desired_policy=desired,
            observed_policy=observed,
            policy_status=PolicyStatus(row["policy_status"]),
            last_policy_error=row["last_policy_error"],
            last_sync=last_sync,
        )


class GatewayRepository:
    def __init__(self, db: Database):
        self.db = db

    def get_all(self) -> List[GatewayConfig]:
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM gateways ORDER BY name ASC").fetchall()
            return [self._row_to_gateway(r) for r in rows]

    def get_active(self) -> Optional[GatewayConfig]:
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM gateways WHERE is_active = 1 LIMIT 1").fetchone()
            return self._row_to_gateway(row) if row else None

    def upsert(self, gw: GatewayConfig) -> None:
        with self.db.get_connection() as conn:
            conn.execute("""
            INSERT INTO gateways (
                gateway_id, name, host, port, backend_type, username,
                auth_secret_id, is_active, lan_interface, wan_interface,
                last_sync, status, last_error,
                ssh_host_key_fingerprint, ssh_key_data, tls_verify, tls_ca_path, tls_fingerprint
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(gateway_id) DO UPDATE SET
                name = excluded.name,
                host = excluded.host,
                port = excluded.port,
                backend_type = excluded.backend_type,
                username = excluded.username,
                auth_secret_id = excluded.auth_secret_id,
                is_active = excluded.is_active,
                lan_interface = excluded.lan_interface,
                wan_interface = excluded.wan_interface,
                last_sync = excluded.last_sync,
                status = excluded.status,
                last_error = excluded.last_error,
                ssh_host_key_fingerprint = excluded.ssh_host_key_fingerprint,
                ssh_key_data = excluded.ssh_key_data,
                tls_verify = excluded.tls_verify,
                tls_ca_path = excluded.tls_ca_path,
                tls_fingerprint = excluded.tls_fingerprint;
            """, (
                gw.gateway_id,
                gw.name,
                gw.host,
                gw.port,
                gw.backend_type.value,
                gw.username,
                gw.auth_secret_id,
                1 if gw.is_active else 0,
                gw.lan_interface,
                gw.wan_interface,
                gw.last_sync.isoformat() if gw.last_sync else None,
                gw.status.value,
                gw.last_error,
                gw.ssh_host_key_fingerprint,
                gw.ssh_key_data,
                1 if gw.tls_verify else 0,
                gw.tls_ca_path,
                gw.tls_fingerprint,
            ))
            conn.commit()

    def _row_to_gateway(self, row) -> GatewayConfig:
        last_sync = datetime.fromisoformat(row["last_sync"]) if row["last_sync"] else None
        # Safely handle potential missing keys if older row
        def get_col(col_name, default=None):
            try:
                return row[col_name]
            except (IndexError, KeyError):
                return default

        return GatewayConfig(
            gateway_id=row["gateway_id"],
            name=row["name"],
            host=row["host"],
            port=row["port"],
            backend_type=BackendType(row["backend_type"]),
            username=row["username"],
            auth_secret_id=row["auth_secret_id"],
            is_active=bool(row["is_active"]),
            lan_interface=row["lan_interface"],
            wan_interface=row["wan_interface"],
            last_sync=last_sync,
            status=GatewayStatus(row["status"]),
            last_error=row["last_error"],
            ssh_host_key_fingerprint=get_col("ssh_host_key_fingerprint"),
            ssh_key_data=get_col("ssh_key_data"),
            tls_verify=bool(get_col("tls_verify", 0)),
            tls_ca_path=get_col("tls_ca_path"),
            tls_fingerprint=get_col("tls_fingerprint"),
        )


class AuditRepository:
    def __init__(self, db: Database):
        self.db = db

    def add(self, event: AuditEvent) -> None:
        with self.db.get_connection() as conn:
            conn.execute("""
            INSERT INTO audit_events (
                event_id, timestamp, action, device_guid, device_name,
                gateway_id, details, status, error
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.timestamp.isoformat(),
                event.action.value,
                event.device_guid,
                event.device_name,
                event.gateway_id,
                event.details,
                event.status,
                event.error,
            ))
            conn.commit()

    def get_recent(self, limit: int = 100) -> List[AuditEvent]:
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM audit_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [
                AuditEvent(
                    event_id=r["event_id"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    action=AuditAction(r["action"]),
                    device_guid=r["device_guid"],
                    device_name=r["device_name"],
                    gateway_id=r["gateway_id"],
                    details=r["details"],
                    status=r["status"],
                    error=r["error"],
                )
                for r in rows
            ]


@dataclass
class NotificationItem:
    notification_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    category: str = "INFO"  # SUCCESS, INFO, WARNING, ERROR, CRITICAL
    title: str = ""
    message: str = ""
    is_read: bool = False
    related_guid: Optional[str] = None
    action_type: Optional[str] = None
    action_payload: Optional[str] = None


class NotificationRepository:
    def __init__(self, db: Database):
        self.db = db

    def add(self, item: NotificationItem) -> None:
        with self.db.get_connection() as conn:
            conn.execute("""
            INSERT INTO notifications (
                notification_id, timestamp, category, title, message,
                is_read, related_guid, action_type, action_payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                item.notification_id,
                item.timestamp.isoformat(),
                item.category,
                item.title,
                item.message,
                1 if item.is_read else 0,
                item.related_guid,
                item.action_type,
                item.action_payload,
            ))
            conn.commit()

    def get_all(self, limit: int = 200, unread_only: bool = False) -> List[NotificationItem]:
        with self.db.get_connection() as conn:
            query = "SELECT * FROM notifications"
            params = []
            if unread_only:
                query += " WHERE is_read = 0"
            query += " ORDER BY timestamp DESC LIMIT ?"
            params.append(limit)
            rows = conn.execute(query, tuple(params)).fetchall()
            return [
                NotificationItem(
                    notification_id=r["notification_id"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    category=r["category"],
                    title=r["title"],
                    message=r["message"],
                    is_read=bool(r["is_read"]),
                    related_guid=r["related_guid"],
                    action_type=r["action_type"],
                    action_payload=r["action_payload"],
                )
                for r in rows
            ]

    def get_unread_count(self) -> int:
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) as cnt FROM notifications WHERE is_read = 0").fetchone()
            return row["cnt"] if row else 0

    def mark_as_read(self, notification_id: str) -> None:
        with self.db.get_connection() as conn:
            conn.execute("UPDATE notifications SET is_read = 1 WHERE notification_id = ?", (notification_id,))
            conn.commit()

    def mark_all_as_read(self) -> None:
        with self.db.get_connection() as conn:
            conn.execute("UPDATE notifications SET is_read = 1")
            conn.commit()

    def clear_all(self) -> None:
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM notifications")
            conn.commit()


class DomainBlockingRepository:
    """Repository for managing persistent domain blocking rules and audit events."""
    def __init__(self, db: Database):
        self.db = db

    def upsert_rule(self, rule: DomainBlockingRule) -> None:
        with self.db.get_connection() as conn:
            conn.execute("""
            INSERT INTO domain_blocking_rules (
                rule_id, domain, match_type, target_scope, target_device_guid,
                target_device_name, target_mac, target_ip, is_enabled,
                enforcement_status, last_error, created_at, updated_at,
                last_verified_at, notes, hits_count
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(rule_id) DO UPDATE SET
                domain = excluded.domain,
                match_type = excluded.match_type,
                target_scope = excluded.target_scope,
                target_device_guid = excluded.target_device_guid,
                target_device_name = excluded.target_device_name,
                target_mac = excluded.target_mac,
                target_ip = excluded.target_ip,
                is_enabled = excluded.is_enabled,
                enforcement_status = excluded.enforcement_status,
                last_error = excluded.last_error,
                updated_at = excluded.updated_at,
                last_verified_at = excluded.last_verified_at,
                notes = excluded.notes,
                hits_count = excluded.hits_count;
            """, (
                rule.rule_id,
                rule.domain,
                rule.match_type.value if isinstance(rule.match_type, DomainMatchType) else str(rule.match_type),
                rule.target_scope.value if isinstance(rule.target_scope, DomainScope) else str(rule.target_scope),
                rule.target_device_guid,
                rule.target_device_name,
                rule.target_mac,
                rule.target_ip,
                1 if rule.is_enabled else 0,
                rule.enforcement_status.value if isinstance(rule.enforcement_status, DomainEnforcementStatus) else str(rule.enforcement_status),
                rule.last_error,
                rule.created_at.isoformat() if rule.created_at else datetime.now(timezone.utc).isoformat(),
                rule.updated_at.isoformat() if rule.updated_at else datetime.now(timezone.utc).isoformat(),
                rule.last_verified_at.isoformat() if rule.last_verified_at else None,
                rule.notes,
                rule.hits_count,
            ))
            conn.commit()

    def get_rule(self, rule_id: str) -> Optional[DomainBlockingRule]:
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT * FROM domain_blocking_rules WHERE rule_id = ?", (rule_id,)).fetchone()
            return self._row_to_rule(row) if row else None

    def get_all_rules(self) -> List[DomainBlockingRule]:
        with self.db.get_connection() as conn:
            rows = conn.execute("SELECT * FROM domain_blocking_rules ORDER BY created_at DESC").fetchall()
            return [self._row_to_rule(r) for r in rows]

    def get_rules_for_device(self, device_guid: str) -> List[DomainBlockingRule]:
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_blocking_rules WHERE target_device_guid = ? OR target_scope = 'GLOBAL' ORDER BY created_at DESC",
                (device_guid,)
            ).fetchall()
            return [self._row_to_rule(r) for r in rows]

    def delete_rule(self, rule_id: str) -> bool:
        with self.db.get_connection() as conn:
            res = conn.execute("DELETE FROM domain_blocking_rules WHERE rule_id = ?", (rule_id,))
            conn.commit()
            return res.rowcount > 0

    def increment_hits(self, rule_id: str, count: int = 1) -> None:
        with self.db.get_connection() as conn:
            conn.execute("UPDATE domain_blocking_rules SET hits_count = hits_count + ? WHERE rule_id = ?", (count, rule_id))
            conn.commit()

    def record_event(self, event: BlockedDomainEvent) -> None:
        with self.db.get_connection() as conn:
            conn.execute("""
            INSERT INTO domain_blocking_events (
                event_id, rule_id, domain, device_guid, device_name,
                client_ip, client_mac, timestamp, action, mechanism, details
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                event.event_id,
                event.rule_id,
                event.domain,
                event.device_guid,
                event.device_name,
                event.client_ip,
                event.client_mac,
                event.timestamp.isoformat() if event.timestamp else datetime.now(timezone.utc).isoformat(),
                event.action,
                event.mechanism,
                event.details,
            ))
            conn.commit()

    def get_recent_events(self, limit: int = 100) -> List[BlockedDomainEvent]:
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM domain_blocking_events ORDER BY timestamp DESC LIMIT ?", (limit,)
            ).fetchall()
            return [
                BlockedDomainEvent(
                    event_id=r["event_id"],
                    rule_id=r["rule_id"],
                    domain=r["domain"],
                    device_guid=r["device_guid"],
                    device_name=r["device_name"],
                    client_ip=r["client_ip"],
                    client_mac=r["client_mac"],
                    timestamp=datetime.fromisoformat(r["timestamp"]),
                    action=r["action"],
                    mechanism=r["mechanism"],
                    details=r["details"] or "",
                )
                for r in rows
            ]

    def clear_events(self) -> None:
        with self.db.get_connection() as conn:
            conn.execute("DELETE FROM domain_blocking_events")
            conn.commit()

    def _row_to_rule(self, row) -> DomainBlockingRule:
        last_verified = datetime.fromisoformat(row["last_verified_at"]) if row["last_verified_at"] else None
        return DomainBlockingRule(
            rule_id=row["rule_id"],
            domain=row["domain"],
            match_type=DomainMatchType(row["match_type"]),
            target_scope=DomainScope(row["target_scope"]),
            target_device_guid=row["target_device_guid"],
            target_device_name=row["target_device_name"],
            target_mac=row["target_mac"],
            target_ip=row["target_ip"],
            is_enabled=bool(row["is_enabled"]),
            enforcement_status=DomainEnforcementStatus(row["enforcement_status"]),
            last_error=row["last_error"],
            created_at=datetime.fromisoformat(row["created_at"]),
            updated_at=datetime.fromisoformat(row["updated_at"]),
            last_verified_at=last_verified,
            notes=row["notes"],
            hits_count=row["hits_count"] or 0,
        )


