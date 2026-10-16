# Security Architecture & Safeguards

Home Net Controller controls physical network forwarding equipment. Its security model strictly prevents unauthorized operations and system exploitation.

## 1. Zero Shell Injection Architecture
All inputs that are dispatched to router shells (MAC addresses, IP addresses, interface names, rate values) are strictly validated:
- MACs must match strict lowercase hex regex: `^[0-9a-f]{2}(:[0-9a-f]{2}){5}$`.
- IPs are validated using Python's `ipaddress` parser.
- Interfaces must match `^[a-zA-Z0-9_\-\.]+$`.
- Any command injection payload (e.g. `; rm -rf /`, `| reboot`, `&& cat /etc/shadow`) raises a `ValueError` immediately at the API boundary before any SSH channel is opened.

## 2. Hardware-Bound AES-GCM-256 Secret Storage
- Router admin credentials (passwords, tokens) are NEVER stored in plaintext.
- The `SecretStore` utilizes AES-GCM-256 with key derivation tied to machine node identity via PBKDF2-HMAC-SHA256 (100,000 iterations).
- Plaintext secrets are never written to log files, SQLite plaintext columns, or stdout.

## 3. Atomic State & Audit Logs
- Every administrative action is recorded in the immutable `audit_events` table with UTC timestamp, target device, action enum, details, and execution result.
