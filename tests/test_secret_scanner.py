from pathlib import Path

from scripts.check_secrets import scan_repository, scan_text


def test_scanner_detects_private_key_material():
    content = "-----BEGIN " + "PRIVATE KEY-----\nnot-a-real-key\n"

    findings = scan_text(content, Path("config/identity.pem"))

    assert [finding.rule for finding in findings] == ["private-key"]


def test_scanner_detects_placeholder_credentials():
    placeholder = "your_" + "virustotal_key_here"
    content = f'api_key = "{placeholder}"\n'

    findings = scan_text(content, Path("app/example.py"))

    assert [finding.rule for finding in findings] == ["hardcoded-credential"]


def test_scanner_rejects_non_empty_env_secrets():
    content = "SERVICE_TOKEN=example-value-that-must-not-ship\n"

    findings = scan_text(content, Path(".env.production"))

    assert [finding.rule for finding in findings] == ["non-empty-env-secret"]


def test_scanner_allows_empty_documented_env_secrets():
    content = "ABUSEIPDB_API_KEY=\nVIRUSTOTAL_API_KEY=\nLOG_LEVEL=INFO\n"

    assert scan_text(content, Path(".env.example")) == []


def test_repository_secret_hygiene_is_clean():
    repository_root = Path(__file__).resolve().parents[1]

    assert scan_repository(repository_root) == []
