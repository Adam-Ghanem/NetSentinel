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
    assert "COPY --chown=netsentinel:netsentinel scripts ./scripts" in dockerfile
    assert "HEALTHCHECK" in dockerfile


def load_compose():
    return yaml.safe_load(
        (REPOSITORY_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    )


def test_compose_defaults_to_least_privilege_runtime():
    service = load_compose()["services"]["netsentinel"]

    assert service["read_only"] is True
    assert service["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in service["security_opt"]
    assert service["init"] is True
    assert service["environment"]["AUTO_CREATE_SCHEMA"] == "false"
    assert service["environment"]["DEMO_MODE"] == "false"
    assert service["ports"][0].startswith("127.0.0.1:")
    assert service["healthcheck"]["retries"] == 3


def test_compose_persists_only_declared_runtime_data():
    compose = load_compose()
    service = compose["services"]["netsentinel"]

    assert service["volumes"] == [
        "netsentinel-data:/data",
        "netsentinel-reports:/app/reports",
    ]
    assert set(compose["volumes"]) == {"netsentinel-data", "netsentinel-reports"}
    assert all(".:/app" not in volume for volume in service["volumes"])


def test_migration_job_is_explicit_and_least_privilege():
    migration = load_compose()["services"]["migrate"]

    assert migration["profiles"] == ["operations"]
    assert migration["command"][:2] == ["python", "scripts/run_migrations.py"]
    assert migration["restart"] == "no"
    assert migration["read_only"] is True
    assert migration["cap_drop"] == ["ALL"]
    assert "no-new-privileges:true" in migration["security_opt"]
    assert migration["healthcheck"] == {"disable": True}
    assert migration["volumes"] == ["netsentinel-data:/data"]
    assert "ports" not in migration


def test_dockerignore_excludes_sensitive_and_generated_files():
    ignored = set(
        (REPOSITORY_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    )

    for expected in {".git", ".env", "*.db", "*.pcap", "tests", "docs"}:
        assert expected in ignored


def test_dockerignore_keeps_runtime_copy_sources_available():
    ignored = set(
        (REPOSITORY_ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    )
    dockerfile = (REPOSITORY_ROOT / "Dockerfile").read_text(encoding="utf-8")

    runtime_sources = {"app", "dashboard", "rules", "migrations", "scripts", "assets"}

    for source in runtime_sources:
        assert f"COPY --chown=netsentinel:netsentinel {source} ./{source}" in dockerfile
        assert source not in ignored
