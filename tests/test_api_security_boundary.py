from api import create_app


def test_openapi_does_not_advertise_unimplemented_soar_mutations(tmp_path):
    application = create_app(database_url=f"sqlite:///{tmp_path / 'api-security.db'}")

    paths = application.openapi()["paths"]

    assert "/soar/block/{ip}" not in paths
    assert all(
        method == "get"
        for operations in paths.values()
        for method in operations
        if method in {"get", "post", "put", "patch", "delete"}
    )
