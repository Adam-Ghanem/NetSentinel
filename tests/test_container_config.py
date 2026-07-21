from pathlib import Path

import yaml


REPOSITORY_ROOT = Path(__file__).resolve().parents[1]


def test_dockerfile_uses_supported_non_root_runtime():
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")

    assert "slim-bookworm" in dockerfile
    assert "slim-buster" not in dockerfile
    assert "USER netsentinel:netsentinel" in dockerfile
    assert "STOPSIGNAL SIGTERM" in dockerfile
    assert "COPY --from=builder /opt/venv /opt/venv" in dockerfile
    assert "HEALTHCHECK" in dockerfile


def test_compose_defaults_to_least_privilege_runtime():
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["netsentinel"]

    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["init"] is True
    assert service["environment"]["AUTO_CREATE_SCHEMA"] == "false"
    assert service["environment"]["DEMO_MODE"] == "false"
    assert service["ports"][0].startswith("127.0.0.1:")
    assert service["healthcheck"]["retries"] == 3


def test_compose_persists_only_declared_runtime_data():
    compose = yaml.safe_load(
        (REPOSITORY_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )
    service = compose["services"]["netsentinel"]

    assert service["volumes"] == [
        "netsentinel-data:/data",
        "netsentinel-reports:/app/reports",
    ]
    assert set(compose["volumes"]) == {"netsentinel-data", "netsentinel-reports"}
    assert all(".:/app" not in volume for volume in service["volumes"])


def test_dockerignore_excludes_sensitive_and_generated_files():
    ignored = set(
        (REPOSITORY_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    )

    for expected in {".git", ".env", "*.db", "*.pcap", "tests", "docs"}:
        assert expected in ignored
