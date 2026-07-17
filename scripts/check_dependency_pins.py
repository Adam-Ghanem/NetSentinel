from __future__ import annotations

import re
import sys
from pathlib import Path

_REQUIREMENT = re.compile(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^\s;]+(?:\s*;.*)?$")


def find_unpinned_requirements(path: Path) -> list[tuple[int, str]]:
    """Return non-empty requirement lines that are not exact version pins."""

    findings: list[tuple[int, str]] = []
    for line_number, raw_line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if not _REQUIREMENT.fullmatch(line):
            findings.append((line_number, line))
    return findings


def main(argv: list[str] | None = None) -> int:
    paths = [Path(value) for value in (argv or ["requirements.txt", "requirements-dev.txt"])]
    failed = False

    for path in paths:
        if not path.is_file():
            print(f"{path}: missing requirements file")
            failed = True
            continue
        for line_number, requirement in find_unpinned_requirements(path):
            print(f"{path}:{line_number}: dependency is not exactly pinned: {requirement}")
            failed = True

    if failed:
        return 1

    print("Dependency pin check passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
