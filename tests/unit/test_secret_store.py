"""
Unit Tests for AES-GCM Secret Store.
"""
from netcutter.persistence.secret_store import SecretStore


def test_secret_encryption_and_decryption_roundtrip():
    store = SecretStore()
    secret = "SuperSecretRouterPassword_2026!#"

    ciphertext, nonce = store.encrypt(secret)
    assert ciphertext != secret
    assert nonce is not None

    decrypted = store.decrypt(ciphertext, nonce)
    assert decrypted == secret
