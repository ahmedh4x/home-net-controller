"""
SQLite Database Initializer and Connection Provider.
"""
from __future__ import annotations

import os
import sqlite3
from pathlib import Path


from contextlib import contextmanager
from netcutter.common.paths import get_app_data_dir


import threading


class Database:
    def __init__(self, db_path: str = None):
        if db_path is None:
            app_dir = get_app_data_dir()
            primary_db = app_dir / "hnc.db"
            legacy_db = app_dir / "netcutter.db"
            if not primary_db.exists() and legacy_db.exists():
                db_path = str(legacy_db)
            else:
                db_path = str(primary_db)
        self.db_path = db_path
        self._lock = threading.RLock()
        self._init_schema()

    @contextmanager
    def get_connection(self):
        with self._lock:
            conn = sqlite3.connect(self.db_path, timeout=30.0)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA journal_mode = WAL;")
            conn.execute("PRAGMA foreign_keys = ON;")
            try:
                yield conn
            finally:
                conn.close()

    def _init_schema(self):
        with self.get_connection() as conn:
            cursor = conn.cursor()
            
            # Devices Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS devices (
                device_guid TEXT PRIMARY KEY,
                display_name TEXT NOT NULL,
                primary_mac TEXT NOT NULL UNIQUE,
                historical_macs_json TEXT NOT NULL,
                ipv4_json TEXT NOT NULL,
                ipv6_json TEXT NOT NULL,
                hostname TEXT,
                vendor TEXT,
                dhcp_client_id TEXT,
                duid TEXT,
                first_seen TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                is_online INTEGER NOT NULL DEFAULT 1,
                confidence_level TEXT NOT NULL,
                is_randomized_mac INTEGER NOT NULL DEFAULT 0,
                category TEXT NOT NULL DEFAULT 'Unknown Device',
                classification_basis TEXT NOT NULL DEFAULT '',
                desired_internet_access TEXT NOT NULL DEFAULT 'ALLOWED',
                desired_dl_kbps INTEGER NOT NULL DEFAULT 0,
                desired_ul_kbps INTEGER NOT NULL DEFAULT 0,
                observed_internet_access TEXT NOT NULL DEFAULT 'ALLOWED',
                observed_dl_kbps INTEGER NOT NULL DEFAULT 0,
                observed_ul_kbps INTEGER NOT NULL DEFAULT 0,
                policy_status TEXT NOT NULL DEFAULT 'SYNCHRONIZED',
                last_policy_error TEXT,
                last_sync TEXT
            );
            """)

            # Automatic column migration for existing databases
            existing_cols = {col["name"] for col in cursor.execute("PRAGMA table_info(devices)").fetchall()}
            if "category" not in existing_cols:
                cursor.execute("ALTER TABLE devices ADD COLUMN category TEXT NOT NULL DEFAULT 'Unknown Device';")
            if "classification_basis" not in existing_cols:
                cursor.execute("ALTER TABLE devices ADD COLUMN classification_basis TEXT NOT NULL DEFAULT '';")

            # Gateways Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS gateways (
                gateway_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL DEFAULT 22,
                backend_type TEXT NOT NULL,
                username TEXT NOT NULL,
                auth_secret_id TEXT,
                is_active INTEGER NOT NULL DEFAULT 1,
                lan_interface TEXT NOT NULL DEFAULT 'br-lan',
                wan_interface TEXT NOT NULL DEFAULT 'eth1',
                last_sync TEXT,
                status TEXT NOT NULL DEFAULT 'UNKNOWN',
                last_error TEXT,
                ssh_host_key_fingerprint TEXT,
                ssh_key_data TEXT,
                tls_verify INTEGER NOT NULL DEFAULT 0,
                tls_ca_path TEXT,
                tls_fingerprint TEXT
            );
            """)

            # Ensure columns exist if table was previously created
            for col, col_type in [
                ("ssh_host_key_fingerprint", "TEXT"),
                ("ssh_key_data", "TEXT"),
                ("tls_verify", "INTEGER NOT NULL DEFAULT 0"),
                ("tls_ca_path", "TEXT"),
                ("tls_fingerprint", "TEXT"),
            ]:
                try:
                    cursor.execute(f"ALTER TABLE gateways ADD COLUMN {col} {col_type};")
                except sqlite3.OperationalError:
                    pass  # column already exists

            # Encrypted Credentials Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS credentials (
                secret_id TEXT PRIMARY KEY,
                ciphertext_b64 TEXT NOT NULL,
                nonce_b64 TEXT NOT NULL
            );
            """)

            # Audit Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                device_guid TEXT,
                device_name TEXT,
                gateway_id TEXT,
                details TEXT NOT NULL,
                status TEXT NOT NULL,
                error TEXT
            );
            """)

            # Identity Correlation Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS identity_events (
                event_id TEXT PRIMARY KEY,
                device_guid TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                old_mac TEXT,
                new_mac TEXT NOT NULL,
                reason TEXT NOT NULL,
                confidence TEXT NOT NULL
            );
            """)

            # Application Settings Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS app_settings (
                key TEXT PRIMARY KEY,
                value TEXT NOT NULL
            );
            """)

            # In-App Notifications Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS notifications (
                notification_id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                message TEXT NOT NULL,
                is_read INTEGER NOT NULL DEFAULT 0,
                related_guid TEXT,
                action_type TEXT,
                action_payload TEXT
            );
            """)

            # Enforcement State History Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS enforcement_history (
                history_id TEXT PRIMARY KEY,
                device_guid TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                operation_id TEXT,
                operation_name TEXT NOT NULL,
                from_state TEXT NOT NULL,
                to_state TEXT NOT NULL,
                success INTEGER NOT NULL,
                error TEXT
            );
            """)

            # Domain Blocking Rules Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_blocking_rules (
                rule_id TEXT PRIMARY KEY,
                domain TEXT NOT NULL,
                match_type TEXT NOT NULL DEFAULT 'SUBDOMAIN',
                target_scope TEXT NOT NULL DEFAULT 'GLOBAL',
                target_device_guid TEXT,
                target_device_name TEXT,
                target_mac TEXT,
                target_ip TEXT,
                is_enabled INTEGER NOT NULL DEFAULT 1,
                enforcement_status TEXT NOT NULL DEFAULT 'Pending',
                last_error TEXT,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                last_verified_at TEXT,
                notes TEXT,
                hits_count INTEGER NOT NULL DEFAULT 0
            );
            """)

            # Domain Blocking Audit Events Table
            cursor.execute("""
            CREATE TABLE IF NOT EXISTS domain_blocking_events (
                event_id TEXT PRIMARY KEY,
                rule_id TEXT,
                domain TEXT NOT NULL,
                device_guid TEXT,
                device_name TEXT,
                client_ip TEXT,
                client_mac TEXT,
                timestamp TEXT NOT NULL,
                action TEXT NOT NULL,
                mechanism TEXT NOT NULL,
                details TEXT
            );
            """)

            conn.commit()


