import ast
from pathlib import Path

DASHBOARD_PATH = Path("dashboard/streamlit_app.py")


def _dashboard_tree() -> ast.Module:
    return ast.parse(DASHBOARD_PATH.read_text(encoding="utf-8"))


def test_dashboard_does_not_import_legacy_whole_capture_reader():
    imported_names = set()
    for node in ast.walk(_dashboard_tree()):
        if isinstance(node, ast.ImportFrom):
            imported_names.update(alias.name for alias in node.names)
        elif isinstance(node, ast.Import):
            imported_names.update(alias.name for alias in node.names)

    assert "rdpcap" not in imported_names
    assert "tempfile" not in imported_names


def test_dashboard_uses_reviewed_uploaded_capture_ingestion_service():
    tree = _dashboard_tree()
    imported_names = {
        alias.name
        for node in ast.walk(tree)
        if isinstance(node, ast.ImportFrom)
        for alias in node.names
    }
    called_names = {
        node.func.id
        for node in ast.walk(tree)
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)
    }

    assert "ingest_uploaded_capture" in imported_names
    assert "ingest_uploaded_capture" in called_names


def test_dashboard_does_not_materialize_entire_upload_buffer():
    attribute_names = {
        node.attr for node in ast.walk(_dashboard_tree()) if isinstance(node, ast.Attribute)
    }

    assert "getbuffer" not in attribute_names
