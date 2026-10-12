import pytest
from app.rules.inspector import ArgumentInspector


@pytest.mark.parametrize(
    ("scanner", "unsafe_text"),
    [
        ("Credential patterns", "PASSWORD=correct-horse-battery"),
        ("Sensitive file paths", "read ~/.aws/credentials"),
        ("SQL injection patterns", "x' OR 1=1;--"),
        ("Path traversal", r"..\\secrets.txt"),
        ("Base64 blobs", "encoded=" + "A" * 48 + "=="),
        ("PII patterns", "mail a.user@example.net"),
    ],
)
def test_scanner_detects_match_and_ignores_safe_text(scanner, unsafe_text):
    inspector = ArgumentInspector()
    matched = inspector.scan({"steps": [{"arguments": {"text": unsafe_text}}]})
    safe = inspector.scan({"steps": [{"arguments": {"text": "ordinary public status"}}]})

    hit = next(result for result in matched if result.scanner_name == scanner)
    assert hit.triggered is True
    assert hit.evidence
    assert hit.step == 0
    assert not any(result.scanner_name == scanner for result in safe)


@pytest.mark.parametrize(
    "url",
    [
        "http://203.0.113.7/data",
        "https://[2001:db8::1]/",
        "https://goggle.com/login",
        "https://example.attackerzone/path",
    ],
)
def test_suspicious_url_scanner_matches_risky_addresses_and_domains(url):
    results = ArgumentInspector().scan({"steps": [{"arguments": {"url": url}}]})
    assert any(result.scanner_name == "Suspicious URLs" for result in results)


def test_suspicious_url_scanner_ignores_known_safe_domain():
    results = ArgumentInspector().scan(
        {"steps": [{"arguments": {"url": "https://example.com/status"}}]}
    )
    assert not any(result.scanner_name == "Suspicious URLs" for result in results)


@pytest.mark.parametrize(
    "text",
    [
        "SSN 123-45-6789",
        "Visa 4111 1111 1111 1111",
        "Mastercard 5555 5555 5555 4444",
        "Amex 378282246310005",
        "person@example.org",
    ],
)
def test_pii_scanner_covers_ssn_cards_and_email(text):
    results = ArgumentInspector().scan({"steps": [{"arguments": {"text": text}}]})
    assert any(result.scanner_name == "PII patterns" for result in results)


def test_sensitive_path_scanner_covers_required_paths():
    paths = ["/etc/passwd", "~/.aws/credentials", ".env", "~/.ssh/id_rsa", ".git/config"]
    for path in paths:
        results = ArgumentInspector().scan({"steps": [{"arguments": {"path": path}}]})
        assert any(result.scanner_name == "Sensitive file paths" for result in results), path


def test_credential_scanner_covers_all_required_names():
    for key in ("API_KEY", "TOKEN", "PASSWORD", "SECRET", "PRIVATE_KEY"):
        results = ArgumentInspector().scan(
            {"steps": [{"arguments": {"value": f"{key}=secretValue123"}}]}
        )
        assert any(result.scanner_name == "Credential patterns" for result in results), key


def test_step_number_and_fail_closed_result():
    inspector = ArgumentInspector()
    result = inspector.scan({"steps": [{"arguments": {}}, {"arguments": {"email": "a@b.com"}}]})
    assert next(hit for hit in result if hit.scanner_name == "PII patterns").step == 1
    error = inspector.scan({"steps": "not-a-list"})
    assert error[0].scanner_name == "internal_error"
    assert error[0].severity == "critical"
