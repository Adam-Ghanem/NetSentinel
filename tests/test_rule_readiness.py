from pathlib import Path

from app.rules_engine import RulesEngine

_VALID_RULE = """
name: DNS visibility
protocol: UDP
dest_port: 53
description: Detect DNS traffic for readiness validation.
severity: Low
"""


def _write_rule(rules_dir, content: str, name: str = "rule.yaml") -> None:
    rules_dir.mkdir(parents=True, exist_ok=True)
    (rules_dir / name).write_text(content, encoding="utf-8")


def test_rules_readiness_is_healthy_for_valid_content(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir, _VALID_RULE)

    report = RulesEngine(rules_dir).readiness_report()

    assert report == {
        "status": "healthy",
        "files_seen": 1,
        "rules_loaded": 1,
        "load_errors": 0,
        "invalid_rules": 0,
    }


def test_rules_readiness_fails_when_no_rule_files_exist(tmp_path):
    report = RulesEngine(tmp_path / "rules").readiness_report()

    assert report["status"] == "unhealthy"
    assert report["files_seen"] == 0
    assert report["rules_loaded"] == 0


def test_rules_readiness_fails_closed_on_invalid_rule(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(
        rules_dir,
        "name: Invalid\ndescription: Missing a supported condition\nseverity: Low\n",
    )

    report = RulesEngine(rules_dir).readiness_report()

    assert report["status"] == "unhealthy"
    assert report["files_seen"] == 1
    assert report["rules_loaded"] == 0
    assert report["invalid_rules"] == 1


def test_rules_readiness_fails_closed_on_yaml_error(tmp_path):
    rules_dir = tmp_path / "rules"
    _write_rule(rules_dir, "name: [unterminated")

    report = RulesEngine(rules_dir).readiness_report()

    assert report["status"] == "unhealthy"
    assert report["files_seen"] == 1
    assert report["rules_loaded"] == 0
    assert report["load_errors"] == 1


def test_bundled_rules_load_without_validation_errors():
    rules_dir = Path(__file__).resolve().parents[1] / "rules"

    report = RulesEngine(rules_dir).readiness_report()

    assert report["status"] == "healthy"
    assert report["files_seen"] >= 1
    assert report["rules_loaded"] >= 1
    assert report["load_errors"] == 0
    assert report["invalid_rules"] == 0
