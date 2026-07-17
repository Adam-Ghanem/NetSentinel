from pathlib import Path

from scripts.check_dependency_pins import find_unpinned_requirements, main


def test_pin_checker_accepts_exact_versions(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests==2.32.4\npackage[extra]==1.2.3\n", encoding="utf-8")

    assert find_unpinned_requirements(requirements) == []


def test_pin_checker_rejects_ranges_and_unversioned_packages(tmp_path):
    requirements = tmp_path / "requirements.txt"
    requirements.write_text("requests>=2.32\nscapy\n", encoding="utf-8")

    assert find_unpinned_requirements(requirements) == [
        (1, "requests>=2.32"),
        (2, "scapy"),
    ]


def test_repository_dependency_files_are_pinned():
    repository_root = Path(__file__).resolve().parents[1]

    assert main(
        [
            str(repository_root / "requirements.txt"),
            str(repository_root / "requirements-dev.txt"),
        ]
    ) == 0
