# Contributing to Home Net Controller

Thank you for your interest in contributing to Home Net Controller! Home Net Controller (HNC) is an authorized, open-source network management and router policy orchestration controller.

---

## 1. Code of Conduct & Safety Discipline

Home Net Controller is built on the principle of **authorized administration** of network infrastructure.
- Never use Home Net Controller for unauthorized network disruption or testing against networks you do not own or have explicit authorization to administer.
- In automated tests and CI, always use mocks, synthetic traffic, and simulated backend fixtures. Tests must never disrupt host networking or require real router credentials.

---

## 2. Development Setup

### Prerequisites
- Python 3.10+ (x64)
- Git

### Initializing Environment
```bash
# Clone the repository
git clone https://github.com/ahmedh4x/home-net-controller.git
cd home-net-controller

# Create and activate a virtual environment
python -m venv .venv
# On Windows:
.venv\Scripts\activate
# On Linux/macOS:
source .venv/bin/activate

# Install in editable mode with development dependencies
pip install -e ".[dev]"
```

---

## 3. Running Tests

Home Net Controller enforces strict test verification. All PRs must pass the test suite without regressions.

```bash
# Run full test suite
python -m pytest -v

# Run fast unit tests only
python -m pytest tests/unit -v

# Run GUI automated tests (headless via pytest-qt)
python -m pytest tests/gui -v

# Run integration tests
python -m pytest tests/integration -v
```

---

## 4. Coding Standards

- **Type Hints:** All public functions, dataclasses, and services must include comprehensive Python type annotations.
- **Security First:**
  - Never bypass SSH host key verification or TLS certificate validation without explicit user opt-in and fingerprint pinning.
  - Never commit credentials, private keys, router passwords, or sensitive local IP addresses.
  - Use `SensitiveDataFilter` redaction when logging.
- **Backend Isolation:**
  - Gateway-Native backends (OpenWrt, Linux, MikroTik) and off-path interceptors (Windows LAN) must remain separate.
  - Never advertise or claim capabilities (e.g. QoS rate limiting or IPv6 filtering) on backends that do not genuinely support them.
- **Documentation:**
  - Document all architectural changes with Architecture Decision Records.

---

## 5. Pull Request Workflow

1. Fork the repository and create a descriptive branch:
   ```bash
   git checkout -b feature/my-improvement
   ```
2. Implement your changes following minimal, surgical changes (`karpathy-guidelines`).
3. Add targeted unit tests demonstrating the correctness of your change and verify with `pytest`.
4. Ensure code formatting is clean and no unrelated files are modified.
5. Submit a Pull Request describing:
   - Problem addressed.
   - Exact implementation changes.
   - Test evidence and commands used to verify.

---

## 6. License & Legal

By submitting contributions to Home Net Controller, you agree that your contributions will be licensed under the **[Apache License 2.0](LICENSE)**.
