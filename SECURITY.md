# Security Policy

## Supported Versions

Home Net Controller provides security fixes and updates for the following versions:

| Version | Supported          |
| ------- | ------------------ |
| 0.0.x   | :white_check_mark: |

---

## Reporting a Vulnerability

Home Net Controller is committed to providing a secure and safe network management environment. As a tool designed for authorized network administration, security vulnerabilities (particularly those related to unauthorized privilege escalation, network leakage, credential exposure, or accidental controller/gateway disruption) are treated with the highest priority.

### Reporting Procedure
If you discover a security vulnerability in Home Net Controller:

1. **Do NOT open a public issue.**
2. Send a detailed report to the security maintainers via GitHub Private Vulnerability Reporting or email the project owner directly.
3. Include the following details:
   - Type of vulnerability (e.g., credential storage exposure, off-path packet injection flaw, unhandled crash recovery gap).
   - Step-by-step instructions or proof-of-concept script to reproduce the issue.
   - Operating system and Python version.
   - Any potential mitigations or patches you have identified.

### Response Timeline
- **Initial Response:** Within 48 hours of report receipt.
- **Triage & Assessment:** Within 5 business days.
- **Remediation & Patch Release:** A CVE and patched release candidate will be published according to coordinated disclosure best practices.

---

## Safe Operation & Ethical Use

Home Net Controller is built solely for **authorized network administration**. Users must only operate Home Net Controller on networks they own or have received explicit, written administrative authorization to manage. 

The software contains safeguards designed to prevent accidental disruption of default gateways and controller hosts. Disabling or attempting to bypass these safeguards is strictly unsupported.
