# Testing & Quality Verification Guide

NetCutter implements a comprehensive automated test suite covering unit models, cryptographic stores, data repositories, reconciliation drift loops, backend validation, and QoS rate tolerance checks.

## Running Tests
Run pytest via the runner script:
```cmd
scripts\run_tests.bat
```
or via the terminal:
```sh
python -m pytest -v
```

## Test Coverage Summary
- `tests/unit/test_identity.py`:
  - MAC address normalization across various formats.
  - IEEE 802 Locally Administered Address (LAA / Randomized MAC) bit detection.
  - Vendor OUI lookup table (Apple, Raspberry Pi, TP-Link, Samsung).
  - Multi-signal identity confidence score computation.
- `tests/unit/test_policy_diff.py`:
  - Bandwidth limit unit conversions and display formatting.
  - Policy diffing: block detection, unblock detection, rate updates.
- `tests/unit/test_secret_store.py`:
  - AES-GCM-256 encryption and decryption round-trip.
- `tests/integration/test_persistence.py`:
  - SQLite database initialization in WAL mode.
  - Device CRUD, historical MAC queries, gateway configs, audit logs.
- `tests/integration/test_reconciliation.py`:
  - Drift injection and autonomous reconciliation recovery.
- `tests/integration/test_backends.py`:
  - Capability report formatting.
  - Input sanitization and shell injection prevention.
  - Full lifecycle execution on MockGatewayBackend.
- `tests/network/test_qos_shaping.py`:
  - Throughput bandwidth measurement and ±15% tolerance acceptance testing.
