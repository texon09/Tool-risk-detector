"""Argument scanners for credentials, unsafe destinations, injection, and PII.

Bug-fix (feature/chat-demo): _url_evidence() previously ran the bare-domain
DOMAIN_RE against every JSON-serialised step, which caused filenames like
"notes.txt" to match as unknown-TLD domains and raise a false-positive
"Suspicious URLs" (high-severity) hit.  Decision.py then promoted a clean
ALLOW (ML score 0.02) to REVISE.

Fix: domain/host scanning now runs only on URL-bearing or free-text argument
values (keys such as url, uri, host, endpoint, to, recipient, body, message,
content) and values that explicitly carry a URL scheme (http://, https://,
ftp://).  It is SKIPPED for path-like argument keys (path, file, filename,
dir, directory) and for bare-filename values (no scheme, no "@", no path
separator).  IP-literal and full-URL detection are unchanged; all other
scanners (credentials, sensitive paths, PII, traversal, SQL, base64) are
unchanged and still run over the entire serialised step text.
"""

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

# ---------------------------------------------------------------------------
# Argument-key classification helpers
# ---------------------------------------------------------------------------

# Keys whose values are almost certainly local filesystem paths.
_PATH_KEYS = frozenset(
    {"path", "file", "filename", "filepath", "file_path", "dir", "directory",
     "source", "dest", "destination", "output", "input", "target"}
)

# Keys whose values are expected to carry URLs / hostnames / email addresses.
_URL_KEYS = frozenset(
    {"url", "uri", "host", "hostname", "endpoint", "to", "recipient",
     "email", "address", "from", "cc", "bcc", "reply_to",
     "body", "message", "content", "text", "payload", "subject", "query"}
)

# Regex: does the string contain a URL scheme anywhere in it?
_SCHEME_RE = re.compile(r"(?i)(?:https?|ftp|ftps|ssh|sftp)://")

# Regex: looks like a local / relative filesystem path.
# Matches paths starting with / ~ . ./ ../ or containing \ or multiple /
_LOCAL_PATH_RE = re.compile(
    r"""(?x)
    ^~[/\\]           # home-relative: ~/foo
  | ^[/\\]            # absolute POSIX / Windows UNC
  | ^\.{1,2}[/\\]     # relative: ./ or ../
  | [/\\].*[/\\]      # has at least two separators (multi-segment)
  | ^[A-Za-z]:\\      # Windows drive letter: C:\...
    """
)

# Bare filename: single stem, single dot, 1-6 char extension, NO dots in stem.
# Matches: notes.txt, run.py, data.csv, readme.md, script.sh
# Does NOT match: evil.invalid, attacker.example (stem has no "." restriction but
# the extension length 1-6 still lets .invalid through, so we additionally
# require the extension to be alphanumeric only and cap stem+ext total <= 40).
_BARE_FILENAME_RE = re.compile(
    r"^[A-Za-z0-9_\-]{1,32}\.[A-Za-z0-9]{1,6}$"
)


def _is_path_key(key: str) -> bool:
    """Return True if the argument key suggests a filesystem path value."""
    return key.lower().strip() in _PATH_KEYS


def _is_url_bearing_key(key: str) -> bool:
    """Return True if the argument key suggests a URL / host / email value."""
    return key.lower().strip() in _URL_KEYS


def _looks_like_local_path(value: str, path_key: bool = False) -> bool:
    """Return True when value looks like a bare filename or local path.

    ``path_key`` must be True when the argument key is a filesystem-path type
    (path, file, filename, dir, etc.).  Bare-hostname strings like
    'evil.invalid' are NOT local paths and must not be classified as such
    when the key is URL-bearing (host, endpoint, etc.).
    """
    if _SCHEME_RE.search(value):
        return False          # has a URL scheme → not a local path
    if "@" in value:
        return False          # email address → not a local path
    if _LOCAL_PATH_RE.search(value):
        return True           # absolute / home-relative / multi-segment path
    # Bare filename: no slash, no scheme, no @ — but ONLY treat as local path
    # if path_key=True (caller confirmed this is a filesystem-path argument).
    # Bare hostnames like 'evil.invalid' must NOT be classified as local paths
    # when they appear in host/endpoint/url keys.
    if path_key and _BARE_FILENAME_RE.match(value):
        return True
    return False


# ---------------------------------------------------------------------------
# Helpers shared with original implementation
# ---------------------------------------------------------------------------


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


def _url_evidence_in_text(text: str) -> str | None:
    """Run full URL/domain/IP detection on an already-validated text snippet.

    This is called only when the caller has established that ``text`` is
    plausibly a URL-bearing or free-text value (not a bare local filename).
    """
    # 1. IPv4 literals
    for match in IPV4_RE.finditer(text):
        if _valid_ip(match.group(0), 4):
            return match.group(0)
    # 2. IPv6 literals
    for match in IPV6_RE.finditer(text):
        candidate = match.group(0).strip("[](){}.,;'")
        if _valid_ip(candidate, 6):
            return candidate
    # 3. Bare domain / unknown-TLD domain
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


def _url_evidence(text: str) -> str | None:
    """Legacy entry-point: search the full serialised step JSON for suspicious
    URLs/IPs.  Called from _matches() which itself is only invoked after
    per-argument key/value filtering (see ArgumentInspector.scan below).

    Retained for compatibility; internally delegates to _url_evidence_in_text.
    """
    return _url_evidence_in_text(text)


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
    """Scan each ordered step and preserve its zero-based step index.

    Suspicious-URL detection is now applied only to argument values that are
    plausibly URL-bearing (by key name or by containing a URL scheme), or to
    the full serialised step text only after path-like values have been
    stripped out.  All other scanners (credentials, sensitive paths, PII,
    traversal, SQL, base64) continue to run on the full serialised step text.
    """

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

            # ----------------------------------------------------------------
            # Full step JSON — used by all scanners EXCEPT Suspicious URLs.
            # ----------------------------------------------------------------
            full_text = json.dumps(step, sort_keys=True, ensure_ascii=False, default=str)

            # ----------------------------------------------------------------
            # Run all scanners that are safe to run on full text.
            # We collect them first and then handle Suspicious URLs separately.
            # ----------------------------------------------------------------
            non_url_matches: list[tuple[str, str, str]] = []

            for match in CREDENTIAL_RE.finditer(full_text):
                non_url_matches.append(("Credential patterns", "critical", match.group(0)))
                break

            m = SENSITIVE_PATH_RE.search(full_text)
            if m:
                non_url_matches.append(("Sensitive file paths", "high", m.group(0)))

            m = SQL_RE.search(full_text)
            if m:
                non_url_matches.append(("SQL injection patterns", "critical", m.group(0)))

            m = TRAVERSAL_RE.search(full_text)
            if m:
                non_url_matches.append(("Path traversal", "high", m.group(0)))

            m = BASE64_RE.search(full_text)
            if m:
                non_url_matches.append(("Base64 blobs", "medium", m.group(0)[:80]))

            # PII — SSN, credit cards, email addresses
            pii_match = SSN_RE.search(full_text)
            if not pii_match:
                pii_match = next(
                    (c for c in CARD_RE.finditer(full_text) if _card_match(c.group(0))),
                    None,
                )
            if not pii_match:
                pii_match = EMAIL_RE.search(full_text)
            if pii_match:
                non_url_matches.append(("PII patterns", "high", pii_match.group(0)))

            # ----------------------------------------------------------------
            # Suspicious-URL scanner — restricted to URL-bearing / free-text
            # argument values to avoid false-positives on filenames.
            # ----------------------------------------------------------------
            url_evidence: str | None = None

            args = step.get("arguments", {})
            if isinstance(args, dict):
                for key, val in args.items():
                    val_str = str(val) if not isinstance(val, str) else val

                    if _is_path_key(key) and _looks_like_local_path(val_str, path_key=True):
                        # Definitively a local filesystem path — skip domain scan.
                        # All other scanners (sensitive-path, traversal, etc.) already
                        # ran on the full serialised step text above.
                        continue

                    # For non-path keys: always scan (URL-bearing keys, body, etc.)
                    # For path keys with non-local values (e.g. URLs in path arg): scan too.
                    evidence = _url_evidence_in_text(val_str)
                    if evidence:
                        url_evidence = evidence
                        break
            else:
                # args is not a dict (e.g. raw string) — scan it directly
                val_str = str(args)
                if not _looks_like_local_path(val_str):
                    url_evidence = _url_evidence_in_text(val_str)

            # Also scan body/content-like string fields at the step level
            if url_evidence is None:
                for field in ("body", "message", "content", "text", "payload"):
                    val = step.get(field)
                    if val is not None:
                        evidence = _url_evidence_in_text(str(val))
                        if evidence:
                            url_evidence = evidence
                            break

            # ----------------------------------------------------------------
            # Emit results
            # ----------------------------------------------------------------
            all_matches = non_url_matches
            if url_evidence:
                all_matches = list(non_url_matches) + [("Suspicious URLs", "high", url_evidence)]

            for scanner_name, severity, evidence in all_matches:
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
