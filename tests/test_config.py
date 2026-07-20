import pytest
from pydantic import ValidationError

from app.config import Settings


def test_settings_use_safe_defaults():
    settings = Settings(_env_file=None)

    assert settings.ENVIRONMENT == "development"
    assert settings.DATABASE_URL == "sqlite:///netsentinel.db"
    assert settings.AUTO_CREATE_SCHEMA is True
    assert settings.DEMO_MODE is False
    assert settings.ABUSEIPDB_API_KEY == ""
    assert settings.VIRUSTOTAL_API_KEY == ""


def test_production_rejects_demo_mode():
    with pytest.raises(ValidationError, match="DEMO_MODE cannot be enabled in production"):
        Settings(
            _env_file=None,
            ENVIRONMENT="production",
            DEMO_MODE=True,
            AUTO_CREATE_SCHEMA=False,
        )


def test_production_rejects_automatic_schema_creation():
    with pytest.raises(ValidationError, match="AUTO_CREATE_SCHEMA must be disabled"):
        Settings(_env_file=None, ENVIRONMENT="production", AUTO_CREATE_SCHEMA=True)

    settings = Settings(
        _env_file=None,
        ENVIRONMENT="production",
        AUTO_CREATE_SCHEMA=False,
    )
    assert settings.AUTO_CREATE_SCHEMA is False


@pytest.mark.parametrize(
    "field_name,placeholder",
    [
        ("ABUSEIPDB_API_KEY", "your_abuseipdb_key_here"),
        ("VIRUSTOTAL_API_KEY", "replace-me"),
    ],
)
def test_placeholder_api_keys_are_rejected(field_name, placeholder):
    with pytest.raises(ValidationError, match="placeholder"):
        Settings(_env_file=None, **{field_name: placeholder})


def test_invalid_database_url_is_rejected():
    with pytest.raises(ValidationError, match="valid SQLAlchemy URL"):
        Settings(_env_file=None, DATABASE_URL="netsentinel.db")


def test_log_level_is_normalized_and_validated():
    settings = Settings(_env_file=None, LOG_LEVEL="ERROR")

    assert settings.LOG_LEVEL == "ERROR"

    with pytest.raises(ValidationError):
        Settings(_env_file=None, LOG_LEVEL="VERBOSE")
