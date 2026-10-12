"""Argument scanners for credentials, unsafe destinations, injection, and PII."""

from __future__ import annotations

import ipaddress
import json
import re
from typing import Any

from app.fail_closed import fail_closed
from app.schemas import InspectorResult

CREDENTIAL_RE = re.compile(
    r"(?i)\b(API_KEY|TOKEN|PASSWORD|SECRET|PRIVATE_KEY)\b\s*[:=]\s*[\"']?([^\s,;\"']{3,})"
)
SENSITIVE_PATH_RE = re.compile(
    r"(?i)(?:/etc/passwd|~[/\\]\.aws[/\\]credentials|\.env(?:\b|[/\\])|"
    r"~[/\\]\.ssh(?:[/\\]|\b)|\.git[/\\]config)"
)
IPV4_RE = re.compile(r"(?<![\w.])(?:\d{1,3}\.){3}\d{1,3}(?![\w.])")
IPV6_RE = re.compile(r"(?<![\w:])(?:[0-9A-Fa-f]{1,4}:){2,}[0-9A-Fa-f:.]{1,}(?![\w:])")
DOMAIN_RE = re.compile(r"(?i)\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}\b")
SQL_RE = re.compile(r"(?i)\bUNION\s+SELECT\b|\bDROP\s+TABLE\b|--|;\s*--|\bOR\s+1\s*=\s*1\b")
TRAVERSAL_RE = re.compile(r"(?i)(?:\.\./|\.\.%2f|\.\.\\|%2e%2e)")
BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{40,}(?:={0,2})(?![A-Za-z0-9+/])")
SSN_RE = re.compile(r"(?<!\d)\d{3}-\d{2}-\d{4}(?!\d)")
EMAIL_RE = re.compile(
    r"(?i)(?<![\w.!#$%&'*+/=?^`{|}~-])[\w.!#$%&'*+/=?^`{|}~-]+@[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?(?:\.[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?)+"
)
CARD_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")
KNOWN_TLDS = {
    "com",
    "org",
    "net",
    "edu",
    "gov",
    "mil",
    "int",
    "io",
    "ai",
    "dev",
    "app",
    "co",
    "uk",
    "de",
    "in",
    "ca",
    "au",
    "nz",
    "jp",
    "fr",
    "es",
    "it",
    "nl",
    "ch",
    "se",
    "no",
    "fi",
    "br",
    "mx",
    "us",
    "info",
    "biz",
    "name",
    "me",
    "tech",
    "cloud",
    "online",
    "site",
    "xyz",
    "store",
    "blog",
    "museum",
    "pro",
    "tv",
    "gg",
    "ly",
}
COMMON_DOMAINS = {
    "google.com",
    "microsoft.com",
    "amazon.com",
    "github.com",
    "openai.com",
    "apple.com",
    "paypal.com",
    "facebook.com",
    "instagram.com",
    "linkedin.com",
    "dropbox.com",
    "cloudflare.com",
}


def _distance(left: str, right: str) -> int:
    """Compute Levenshtein distance using one row of memory."""
    previous = list(range(len(right) + 1))
    for i, char_left in enumerate(left, 1):
        current = [i]
        for j, char_right in enumerate(right, 1):
            current.append(
                min(current[-1] + 1, previous[j] + 1, previous[j - 1] + (char_left != char_right))
            )
        previous = current
    return previous[-1]


def _valid_ip(match: str, version: int) -> bool:
    try:
        return ipaddress.ip_address(match).version == version
    except ValueError:
        return False


def _card_match(match: str) -> bool:
    digits = re.sub(r"\D", "", match)
    if not 13 <= len(digits) <= 19:
        return False
    return (
        digits.startswith("4")
        or digits[:2] in {"34", "37"}
        or 51 <= int(digits[:2]) <= 55
        or 2221 <= int(digits[:4]) <= 2720
    )


def _url_evidence(text: str) -> str | None:
    for match in IPV4_RE.finditer(text):
        if _valid_ip(match.group(0), 4):
            return match.group(0)
    for match in IPV6_RE.finditer(text):
        candidate = match.group(0).strip("[](){}.,;'")
        if _valid_ip(candidate, 6):
            return candidate
    for match in DOMAIN_RE.finditer(text):
        domain = match.group(0).casefold().rstrip(".")
        labels = domain.split(".")
        if labels[-1] not in KNOWN_TLDS:
            return domain
        for trusted in COMMON_DOMAINS:
            trusted_name = trusted.split(".")[0]
            candidate_name = labels[-2]
            if candidate_name != trusted_name and _distance(candidate_name, trusted_name) <= 1:
                return domain
    return None


def _matches(text: str) -> list[tuple[str, str, str]]:
    matches: list[tuple[str, str, str]] = []
    for match in CREDENTIAL_RE.finditer(text):
        matches.append(("Credential patterns", "critical", match.group(0)))
        break
    match = SENSITIVE_PATH_RE.search(text)
    if match:
        matches.append(("Sensitive file paths", "high", match.group(0)))
    evidence = _url_evidence(text)
    if evidence:
        matches.append(("Suspicious URLs", "high", evidence))
    match = SQL_RE.search(text)
    if match:
        matches.append(("SQL injection patterns", "critical", match.group(0)))
    match = TRAVERSAL_RE.search(text)
    if match:
        matches.append(("Path traversal", "high", match.group(0)))
    match = BASE64_RE.search(text)
    if match:
        matches.append(("Base64 blobs", "medium", match.group(0)[:80]))
    match = SSN_RE.search(text)
    if not match:
        match = next(
            (candidate for candidate in CARD_RE.finditer(text) if _card_match(candidate.group(0))),
            None,
        )
    if not match:
        match = EMAIL_RE.search(text)
    if match:
        matches.append(("PII patterns", "high", match.group(0)))
    return matches


def _inspector_error(exc: Exception) -> list[InspectorResult]:
    return [
        InspectorResult(
            scanner_name="internal_error",
            triggered=True,
            severity="critical",
            reason="Argument inspection failed closed",
            evidence=str(exc),
            step=-1,
        )
    ]


class ArgumentInspector:
    """Scan each ordered step and preserve its zero-based step index."""

    @fail_closed(_inspector_error)
    def scan(self, plan: dict[str, Any]) -> list[InspectorResult]:
        steps = plan.get("steps", [])
        if not isinstance(steps, list):
            raise TypeError("plan.steps must be a list")
        results: list[InspectorResult] = []
        scan_steps = steps or [plan]
        for index, step in enumerate(scan_steps):
            if not isinstance(step, dict):
                raise TypeError("each plan step must be an object")
            text = json.dumps(step, sort_keys=True, ensure_ascii=False, default=str)
            for scanner_name, severity, evidence in _matches(text):
                results.append(
                    InspectorResult(
                        scanner_name=scanner_name,
                        triggered=True,
                        severity=severity,
                        reason=f"Detected {scanner_name.casefold()} evidence",
                        match_preview=evidence[:50],
                        evidence=evidence,
                        step=index if steps else -1,
                    )
                )
        return results
