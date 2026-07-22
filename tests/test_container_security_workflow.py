from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]
WORKFLOW_PATH = REPOSITORY_ROOT / ".github" / "workflows" / "container-security.yml"
TRIVY_CONFIG_PATH = REPOSITORY_ROOT / "trivy.yaml"
TRIVY_SBOM_CONFIG_PATH = REPOSITORY_ROOT / "trivy-sbom.yaml"


def test_container_security_workflow_is_least_privilege_and_fail_closed():
    workflow = WORKFLOW_PATH.read_text(encoding="utf-8")

    assert "permissions:\n  contents: read" in workflow
    assert "aquasecurity/trivy-action@v0.36.0" in workflow
    assert "trivy-config: trivy.yaml" in workflow
    assert "exit-code: \"1\"" in workflow
    assert "severity: HIGH,CRITICAL" in workflow
    assert "ignore-unfixed: true" in workflow
    assert "trivy-config: trivy-sbom.yaml" in workflow
    assert "format: cyclonedx" in workflow
    assert "exit-code: \"0\"" in workflow
    assert "if-no-files-found: error" in workflow
    assert "retention-days: 30" in workflow


def test_trivy_policy_blocks_high_and_critical_fixed_vulnerabilities():
    config = yaml.safe_load(TRIVY_CONFIG_PATH.read_text(encoding="utf-8"))

    assert config["scan"]["scanners"] == ["vuln"]
    assert config["vulnerability"]["ignore-unfixed"] is True
    assert config["exit-code"] == 1
    assert config["severity"] == ["HIGH", "CRITICAL"]
    assert config["cache"]["dir"] == ".cache/trivy"


def test_sbom_policy_never_inherits_vulnerability_gate_exit_code():
    config = yaml.safe_load(TRIVY_SBOM_CONFIG_PATH.read_text(encoding="utf-8"))

    assert config["scan"]["scanners"] == ["vuln"]
    assert config["format"] == "cyclonedx"
    assert config["exit-code"] == 0
    assert config["cache"]["dir"] == ".cache/trivy"


def test_runtime_image_applies_security_updates_and_drops_build_tools():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "apt-get upgrade --yes --no-install-recommends" in dockerfile
    assert "pip uninstall --yes pip setuptools wheel jaraco.context" in dockerfile
