"""
Gateway Manager Service.
Handles backend lifecycle, credential resolution, and health monitoring.
"""
from __future__ import annotations

import threading
from typing import Dict, List, Optional, Tuple
from netcutter.backends.base import IGatewayBackend
from netcutter.backends.capabilities import BackendCapabilities
from netcutter.domain.models import BackendType, GatewayConfig, GatewayStatus
from netcutter.persistence.database import Database
from netcutter.persistence.repository import GatewayRepository
from netcutter.persistence.secret_store import SecretStore


class GatewayManager:
    def __init__(
        self,
        db: Database,
        gateway_repo: GatewayRepository,
        secret_store: SecretStore,
    ):
        self.db = db
        self.gateway_repo = gateway_repo
        self.secret_store = secret_store
        self._active_backend: Optional[IGatewayBackend] = None
        self._active_config: Optional[GatewayConfig] = None
        self._lock = threading.Lock()

    def get_active_backend(self) -> Optional[IGatewayBackend]:
        with self._lock:
            return self._active_backend

    def get_active_config(self) -> Optional[GatewayConfig]:
        with self._lock:
            return self._active_config

    def set_active_gateway(self, gateway_id: str, secret_plaintext: Optional[str] = None) -> Tuple[bool, str]:
        """Activate and connect to the specified gateway router."""
        with self._lock:
            all_gws = self.gateway_repo.get_all()
            target_gw = next((g for g in all_gws if g.gateway_id == gateway_id), None)
            if not target_gw:
                return False, f"Gateway with ID {gateway_id} not found."

            # Disconnect current backend if any
            if self._active_backend:
                try:
                    self._active_backend.disconnect()
                except Exception:
                    pass
                self._active_backend = None

            # Retrieve secret if not passed in directly
            password = secret_plaintext
            if not password and target_gw.auth_secret_id:
                try:
                    with self.db.get_connection() as conn:
                        row = conn.execute(
                            "SELECT ciphertext_b64, nonce_b64 FROM credentials WHERE secret_id = ?",
                            (target_gw.auth_secret_id,),
                        ).fetchone()
                        if row:
                            password = self.secret_store.decrypt(
                                row["ciphertext_b64"], row["nonce_b64"]
                            )
                except Exception as ex:
                    target_gw.status = GatewayStatus.DEGRADED
                    target_gw.last_error = f"Secret decryption error: {ex}"
                    self.gateway_repo.upsert(target_gw)
                    return False, f"Failed to decrypt credentials: {ex}"

            # Instantiate backend
            backend = self._create_backend_instance(target_gw, password)

            # Connect
            connected = backend.connect()
            if connected:
                target_gw.status = GatewayStatus.ONLINE
                target_gw.last_error = None
                self._active_backend = backend
                self._active_config = target_gw
                # Mark as active in DB
                for gw in all_gws:
                    gw.is_active = (gw.gateway_id == target_gw.gateway_id)
                    self.gateway_repo.upsert(gw)
                return True, f"Successfully connected to {target_gw.name} ({target_gw.host})"
            else:
                target_gw.status = GatewayStatus.OFFLINE
                self.gateway_repo.upsert(target_gw)
                return False, target_gw.last_error or "Connection failed"

    def disconnect_active(self) -> None:
        """Disconnect active gateway and run cleanup/restoration."""
        with self._lock:
            if self._active_backend:
                try:
                    self._active_backend.disconnect()
                except Exception:
                    pass
                self._active_backend = None
                self._active_config = None

    def test_connection(
        self, config: GatewayConfig, secret_plaintext: Optional[str] = None
    ) -> Tuple[bool, str]:
        """Test connection parameters without making it the persistent active gateway."""
        backend = self._create_backend_instance(config, secret_plaintext)

        try:
            connected = backend.connect()
            if connected:
                ok, msg = backend.health_check()
                backend.disconnect()
                return ok, msg
            return False, config.last_error or "Failed to connect to gateway."
        except Exception as ex:
            return False, str(ex)

    def _create_backend_instance(
        self, config: GatewayConfig, password: Optional[str] = None
    ) -> IGatewayBackend:
        """Lazy backend factory to prevent circular import dependencies."""
        if config.backend_type == BackendType.OPENWRT:
            from netcutter.backends.openwrt import OpenWrtBackend
            return OpenWrtBackend(config, password)
        elif config.backend_type == BackendType.LINUX:
            from netcutter.backends.linux import LinuxGatewayBackend
            return LinuxGatewayBackend(config, password)
        elif config.backend_type == BackendType.MIKROTIK:
            from netcutter.backends.mikrotik import MikroTikBackend
            return MikroTikBackend(config, password)
        elif config.backend_type == BackendType.WINDOWS_LAN:
            from netcutter.backends.windows_lan import WindowsLanInterceptorBackend
            return WindowsLanInterceptorBackend(config)
        else:
            from netcutter.backends.mock_backend import MockGatewayBackend
            return MockGatewayBackend(config)

    def save_credential(self, secret_id: str, plaintext: str) -> None:
        """Encrypt and persist credential in the SQLite database."""
        ciphertext_b64, nonce_b64 = self.secret_store.encrypt(plaintext)
        with self.db.get_connection() as conn:
            conn.execute("""
            INSERT INTO credentials (secret_id, ciphertext_b64, nonce_b64)
            VALUES (?, ?, ?)
            ON CONFLICT(secret_id) DO UPDATE SET
                ciphertext_b64 = excluded.ciphertext_b64,
                nonce_b64 = excluded.nonce_b64;
            """, (secret_id, ciphertext_b64, nonce_b64))
            conn.commit()
