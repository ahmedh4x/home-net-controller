"""
Secure Credential Store using AES-GCM-256 Encryption and Windows DPAPI Key Protection.
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

_DPAPI_ENTROPY = b"HNC_DPAPI_ENTROPY_SALT_v1"


def _is_windows() -> bool:
    return platform.system() == "Windows"


def _dpapi_protect(plaintext: bytes) -> bytes:
    """Encrypt raw key bytes using Windows Data Protection API (DPAPI)."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    p_data_in = DATA_BLOB(
        len(plaintext),
        ctypes.cast(ctypes.c_char_p(plaintext), ctypes.POINTER(ctypes.c_char)),
    )
    p_entropy = DATA_BLOB(
        len(_DPAPI_ENTROPY),
        ctypes.cast(ctypes.c_char_p(_DPAPI_ENTROPY), ctypes.POINTER(ctypes.c_char)),
    )
    p_data_out = DATA_BLOB()

    # dwFlags: 1 = CRYPTPROTECT_UI_FORBIDDEN
    res = ctypes.windll.crypt32.CryptProtectData(
        ctypes.byref(p_data_in),
        "HomeNetControllerMasterKey",
        ctypes.byref(p_entropy),
        None,
        None,
        1,
        ctypes.byref(p_data_out),
    )
    if not res:
        raise ctypes.WinError()

    try:
        return ctypes.string_at(p_data_out.pbData, p_data_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(p_data_out.pbData)


def _dpapi_unprotect(ciphertext: bytes) -> bytes:
    """Decrypt DPAPI ciphertext back to raw key bytes."""
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [
            ("cbData", wintypes.DWORD),
            ("pbData", ctypes.POINTER(ctypes.c_char)),
        ]

    p_data_in = DATA_BLOB(
        len(ciphertext),
        ctypes.cast(ctypes.c_char_p(ciphertext), ctypes.POINTER(ctypes.c_char)),
    )
    p_entropy = DATA_BLOB(
        len(_DPAPI_ENTROPY),
        ctypes.cast(ctypes.c_char_p(_DPAPI_ENTROPY), ctypes.POINTER(ctypes.c_char)),
    )
    p_data_out = DATA_BLOB()

    # dwFlags: 1 = CRYPTPROTECT_UI_FORBIDDEN
    res = ctypes.windll.crypt32.CryptUnprotectData(
        ctypes.byref(p_data_in),
        None,
        ctypes.byref(p_entropy),
        None,
        None,
        1,
        ctypes.byref(p_data_out),
    )
    if not res:
        raise ctypes.WinError()

    try:
        return ctypes.string_at(p_data_out.pbData, p_data_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(p_data_out.pbData)


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


def _apply_windows_acl(file_path: str) -> None:
    """Set user-only access control list on Windows."""
    if not _is_windows():
        return
    try:
        import subprocess
        username = os.environ.get("USERNAME")
        if username:
            subprocess.run(
                ["icacls", file_path, "/inheritance:r", "/grant:r", f"{username}:(R,W)"],
                capture_output=True,
                text=True,
                timeout=5,
            )
    except Exception as acl_ex:
        logger.debug("Could not set Windows ACL on key file: %s", acl_ex)


def _load_or_generate_persistent_key() -> Tuple[bytes, bool]:
    """
    Loads or generates persistent key.
    Returns (key_bytes, is_dpapi_protected).
    """
    key_dir = str(get_app_data_dir())
    dpapi_path = os.path.join(key_dir, "master.key.dpapi")
    plaintext_path = os.path.join(key_dir, "master.key")

    os.makedirs(key_dir, exist_ok=True)

    # 1. Try reading DPAPI-protected key on Windows
    if _is_windows() and os.path.exists(dpapi_path):
        try:
            with open(dpapi_path, "rb") as f:
                blob = f.read()
            raw_key = _dpapi_unprotect(blob)
            if len(raw_key) == 32:
                return raw_key, True
        except Exception as ex:
            logger.warning("Failed to decrypt DPAPI master key, checking fallbacks: %s", ex)

    # 2. Check for legacy plaintext master.key
    if os.path.exists(plaintext_path):
        try:
            with open(plaintext_path, "rb") as f:
                raw_key = f.read().strip()
            if len(raw_key) == 32:
                # If on Windows, migrate to DPAPI immediately and remove plaintext key
                if _is_windows():
                    try:
                        encrypted_blob = _dpapi_protect(raw_key)
                        fd = os.open(dpapi_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                        with open(fd, "wb") as f_out:
                            f_out.write(encrypted_blob)
                        _apply_windows_acl(dpapi_path)

                        # Securely shred and delete plaintext master.key
                        try:
                            with open(plaintext_path, "wb") as f_shred:
                                f_shred.write(os.urandom(32))
                            os.remove(plaintext_path)
                            logger.info("Migrated plaintext master.key to DPAPI master.key.dpapi successfully.")
                        except Exception as shred_ex:
                            logger.warning("Could not delete legacy plaintext master.key: %s", shred_ex)
                        return raw_key, True
                    except Exception as mig_ex:
                        logger.warning("Could not migrate master.key to DPAPI: %s", mig_ex)
                return raw_key, False
        except Exception as ex:
            logger.warning("Could not read plaintext master key: %s", ex)

    # 3. Generate a fresh 32-byte key
    new_key = os.urandom(32)
    if _is_windows():
        try:
            protected_blob = _dpapi_protect(new_key)
            fd = os.open(dpapi_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with open(fd, "wb") as f:
                f.write(protected_blob)
            _apply_windows_acl(dpapi_path)
            return new_key, True
        except Exception as ex:
            logger.warning("Could not write DPAPI-protected key; falling back to restricted file: %s", ex)

    # POSIX or Windows fallback: write with restrictive permissions 0o600
    try:
        fd = os.open(plaintext_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with open(fd, "wb") as f:
            f.write(new_key)
        _apply_windows_acl(plaintext_path)
        return new_key, False
    except Exception as ex:
        logger.warning("Could not persist master key file, falling back to machine seed: %s", ex)
        return _derive_legacy_key(), False


class SecretStore:
    """
    Encrypts and decrypts sensitive gateway secrets using high-entropy AESGCM keys.
    Plaintext secrets are never committed to SQLite or written to logs.
    On Windows, the AES key is protected at rest with DPAPI.
    """
    def __init__(self, key_material: Optional[bytes] = None):
        self._is_dpapi = False
        if key_material is None:
            self._key, self._is_dpapi = _load_or_generate_persistent_key()
        else:
            self._key = key_material
        self._aesgcm = AESGCM(self._key)
        self._legacy_aesgcm = AESGCM(_derive_legacy_key())

    @property
    def is_dpapi_protected(self) -> bool:
        """Returns True if the root key at rest is protected by Windows DPAPI."""
        return self._is_dpapi

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


