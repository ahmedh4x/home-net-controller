"""
Secure Credential Store using AES-GCM-256 Encryption.
"""
from __future__ import annotations

import base64
import logging
import os
import platform
from typing import Optional, Tuple
from netcutter.common.paths import get_app_data_dir
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

logger = logging.getLogger("netcutter.persistence.secret_store")


def _derive_legacy_key() -> bytes:
    seed = f"{platform.node()}-{platform.machine()}-NetCutterMasterKey-v1".encode()
    salt = b"netcutter_sec_salt_2026"
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return kdf.derive(seed)


def _load_or_generate_persistent_key() -> bytes:
    key_dir = str(get_app_data_dir())
    key_path = os.path.join(key_dir, "master.key")
    if os.path.exists(key_path):
        try:
            with open(key_path, "rb") as f:
                data = f.read().strip()
                if len(data) == 32:
                    return data
        except Exception as ex:
            logger.warning(f"Could not read master key file: {ex}")
    try:
        os.makedirs(key_dir, exist_ok=True)
        new_key = os.urandom(32)
        # Use restrictive file descriptor permissions on creation (0o600)
        fd = os.open(key_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "wb") as f:
            f.write(new_key)

        # On Windows, enforce restrictive user-only ACL via icacls
        if platform.system() == "Windows":
            try:
                import subprocess
                username = os.environ.get("USERNAME")
                if username:
                    # Remove inheritance and grant read/write only to current user
                    subprocess.run(
                        ["icacls", key_path, "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                        capture_output=True,
                        text=True,
                        timeout=5,
                    )
            except Exception as acl_ex:
                logger.debug(f"Could not set Windows ACL on master.key: {acl_ex}")

        return new_key
    except Exception as ex:
        logger.warning(f"Could not persist master key file, falling back to machine seed: {ex}")
        return _derive_legacy_key()


class SecretStore:
    """
    Encrypts and decrypts sensitive gateway secrets using high-entropy AESGCM keys.
    Plaintext secrets are never committed to SQLite or written to logs.
    """
    def __init__(self, key_material: Optional[bytes] = None):
        if key_material is None:
            self._key = _load_or_generate_persistent_key()
        else:
            self._key = key_material
        self._aesgcm = AESGCM(self._key)
        self._legacy_aesgcm = AESGCM(_derive_legacy_key())

    def encrypt(self, plaintext: str) -> Tuple[str, str]:
        """
        Encrypts plaintext string.
        Returns (base64_ciphertext, base64_nonce).
        """
        nonce = os.urandom(12)
        ciphertext = self._aesgcm.encrypt(nonce, plaintext.encode("utf-8"), None)
        return (
            base64.b64encode(ciphertext).decode("utf-8"),
            base64.b64encode(nonce).decode("utf-8"),
        )

    def decrypt(self, b64_ciphertext: str, b64_nonce: str) -> str:
        """Decrypts base64 encoded ciphertext and nonce to original string."""
        ciphertext = base64.b64decode(b64_ciphertext.encode("utf-8"))
        nonce = base64.b64decode(b64_nonce.encode("utf-8"))
        try:
            plaintext_bytes = self._aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode("utf-8")
        except Exception:
            # Fallback to legacy key in case ciphertext was created prior to persistent key
            plaintext_bytes = self._legacy_aesgcm.decrypt(nonce, ciphertext, None)
            return plaintext_bytes.decode("utf-8")

