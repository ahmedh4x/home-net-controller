"""
Unit Tests for AES-GCM and Windows DPAPI Secret Store.
"""
import os
import platform
import pytest
from netcutter.persistence.secret_store import SecretStore, _derive_legacy_key
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def test_secret_encryption_and_decryption_roundtrip():
    store = SecretStore()
    secret = "SuperSecretRouterPassword_2026!#"

    ciphertext, nonce = store.encrypt(secret)
    assert ciphertext != secret
    assert nonce is not None

    decrypted = store.decrypt(ciphertext, nonce)
    assert decrypted == secret


def test_legacy_key_decryption_fallback():
    # Encrypt with legacy key
    legacy_key = _derive_legacy_key()
    legacy_gcm = AESGCM(legacy_key)
    nonce = os.urandom(12)
    secret = "LegacyRouterSecret_v0"
    raw_ct = legacy_gcm.encrypt(nonce, secret.encode("utf-8"), None)

    import base64
    b64_ct = base64.b64encode(raw_ct).decode("utf-8")
    b64_nonce = base64.b64encode(nonce).decode("utf-8")

    # Decrypt with standard store using persistent/DPAPI key
    store = SecretStore()
    decrypted = store.decrypt(b64_ct, b64_nonce)
    assert decrypted == secret


def test_dpapi_migration_from_plaintext_master_key(tmp_path, monkeypatch):
    # Simulate app data dir
    monkeypatch.setattr("netcutter.persistence.secret_store.get_app_data_dir", lambda: tmp_path)

    plaintext_key = os.urandom(32)
    master_key_file = tmp_path / "master.key"
    master_key_file.write_bytes(plaintext_key)

    # Initialize store which triggers migration on Windows
    store = SecretStore()
    secret = "MigratedSecretValue_42"
    ct, nonce = store.encrypt(secret)
    assert store.decrypt(ct, nonce) == secret

    if platform.system() == "Windows":
        # Plaintext master.key should be removed, and master.key.dpapi should exist
        assert not master_key_file.exists()
        dpapi_file = tmp_path / "master.key.dpapi"
        assert dpapi_file.exists()
        assert store.is_dpapi_protected is True

        # Second instantiation should read from master.key.dpapi and decrypt successfully
        store2 = SecretStore()
        assert store2.decrypt(ct, nonce) == secret
        assert store2.is_dpapi_protected is True

