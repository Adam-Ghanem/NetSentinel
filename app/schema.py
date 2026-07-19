"""Database schema version metadata and compatibility helpers."""

CURRENT_SCHEMA_VERSION = 1
SCHEMA_VERSION_TABLE = "netsentinel_schema"


def schema_compatibility(recorded_version):
    """Return a stable compatibility status for an observed schema version."""
    if recorded_version is None:
        return "unversioned"
    if recorded_version == CURRENT_SCHEMA_VERSION:
        return "current"
    if recorded_version < CURRENT_SCHEMA_VERSION:
        return "upgrade_required"
    return "newer_than_application"
