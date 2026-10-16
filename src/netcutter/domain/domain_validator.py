"""
Domain Validation, Normalization, and Matching Logic for NetCutter.
Handles RFC 1035 / 1123 domain validation, normalization, and subdomain matching.
"""
from __future__ import annotations

import re
from typing import List, Optional, Tuple
from urllib.parse import urlparse


# RFC 1035 / 1123 compliant label: letters, digits, hyphens (cannot start or end with hyphen)
LABEL_REGEX = re.compile(r"^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$", re.IGNORECASE)

# IPv4 regex to reject IP addresses as domain rules
IPV4_REGEX = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")


def normalize_domain(raw_input: str) -> str:
    """
    Safely normalize raw domain input:
    - Strips leading/trailing whitespace
    - Lowercases ASCII
    - Strips protocol scheme (http://, https://, ftp://, etc.)
    - Strips user credentials (user:pass@)
    - Strips port numbers (:443, :80)
    - Strips URL paths (/path), query strings (?foo=bar), and fragments (#hash)
    - Strips leading wildcard notation (*.) so the root domain is normalized
    - Strips trailing dots (FQDN root notation)
    """
    if not raw_input:
        return ""

    cleaned = raw_input.strip().lower()

    # If user provided a URL scheme, parse with urlparse
    if "://" in cleaned:
        try:
            parsed = urlparse(cleaned)
            cleaned = parsed.hostname or cleaned
        except Exception:
            pass
    elif cleaned.startswith("//"):
        cleaned = cleaned[2:]

    # Remove any lingering path or query
    if "/" in cleaned:
        cleaned = cleaned.split("/")[0]
    if "?" in cleaned:
        cleaned = cleaned.split("?")[0]
    if "#" in cleaned:
        cleaned = cleaned.split("#")[0]

    # Remove port if present and not IPv6
    if ":" in cleaned and not cleaned.startswith("["):
        cleaned = cleaned.split(":")[0]

    # Remove leading wildcard syntax (*.example.com -> example.com)
    while cleaned.startswith("*."):
        cleaned = cleaned[2:]
    if cleaned.startswith("*"):
        cleaned = cleaned[1:]

    # Strip trailing dots
    cleaned = cleaned.rstrip(".")

    return cleaned


def validate_domain(raw_input: str) -> Tuple[bool, Optional[str], str]:
    """
    Validates a domain string.
    Returns: (is_valid: bool, error_message: Optional[str], normalized_domain: str)
    """
    if not raw_input or not raw_input.strip():
        return False, "Domain name cannot be empty.", ""

    raw_trimmed = raw_input.strip()

    # Reject wildcard patterns like *.com or *example*
    if "*" in raw_trimmed:
        # Check if user tried wildcard syntax
        norm = normalize_domain(raw_trimmed)
        if not norm or norm.startswith("."):
            return (
                False,
                "Wildcard syntax '*' is not permitted. Select 'Include Subdomains' match type instead.",
                "",
            )

    normalized = normalize_domain(raw_trimmed)

    if not normalized:
        return False, "Invalid domain format.", ""

    # Check for IPv4 address
    if IPV4_REGEX.match(normalized):
        return (
            False,
            f"'{normalized}' is an IP address. Use Device Blocking or Firewall rules to block IPs.",
            "",
        )

    # Check for IPv6
    if ":" in normalized:
        return (
            False,
            "IP addresses are not permitted as domain rules. Please enter a valid domain name.",
            "",
        )

    # Overall length check (RFC 1035 max 253 characters)
    if len(normalized) > 253:
        return False, f"Domain exceeds maximum length of 253 characters ({len(normalized)} chars).", ""

    # Split into labels
    labels = normalized.split(".")
    if len(labels) < 2:
        return (
            False,
            "Domain must contain at least a name and a top-level domain (e.g., example.com).",
            "",
        )

    # Validate each label
    for i, label in enumerate(labels):
        if not label:
            return False, "Domain contains an empty label (consecutive dots).", ""
        if len(label) > 63:
            return False, f"Domain label '{label}' exceeds maximum 63 characters.", ""
        if not LABEL_REGEX.match(label):
            return (
                False,
                f"Domain label '{label}' contains invalid characters. Only letters, digits, and hyphens are allowed.",
                "",
            )

    # Check TLD (last label) cannot be all digits
    tld = labels[-1]
    if tld.isdigit():
        return False, f"Top-level domain '{tld}' cannot be entirely numeric.", ""

    return True, None, normalized


def is_domain_match(requested_domain: str, rule_domain: str, include_subdomains: bool = True) -> bool:
    """
    Determine if a requested domain matches a rule domain.
    
    If include_subdomains is True:
        'example.com' matches 'example.com' and 'sub.example.com' and 'a.b.example.com'
        but does NOT match 'notexample.com' or 'example.co'
    If include_subdomains is False (Exact):
        'example.com' ONLY matches 'example.com'
    """
    req_norm = normalize_domain(requested_domain)
    rule_norm = normalize_domain(rule_domain)

    if not req_norm or not rule_norm:
        return False

    if req_norm == rule_norm:
        return True

    if include_subdomains:
        # Must be a proper subdomain ending with dot + rule_norm
        suffix = "." + rule_norm
        return req_norm.endswith(suffix)

    return False
