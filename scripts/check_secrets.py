from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from pathlib import Path

_SKIP_DIRECTORIES = {
    ".git",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".venv",
    "__pycache__",
    "node_modules",
    "venv",
}
_TEXT_SUFFIXES = {
    ".cfg",
    ".conf",
    ".env",
    ".ini",
    ".json",
    ".md",
    ".py",
    ".sh",
    ".toml",
    ".txt",
    ".yaml",
    ".yml",
}
_TEXT_FILENAMES = {"Dockerfile", "LICENSE", "Makefile", ".env.example", ".gitignore"}
_PLACEHOLDER_VALUES = {
    "changeme",
    "replace-me",
    "your_abuseipdb_key_here",
    "your_virustotal_key_here",
}
_HIGH_CONFIDENCE_PATTERNS = (
    (
        "private-key",
        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"),
    ),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b")),
    ("slack-token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b")),
)
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b(api[_-]?key|secret|token|password)\b\s*[:=]\s*[\"']([^\"']+)[\"']"
)
_ENV_ASSIGNMENT_PATTERN = re.compile(r"^([A-Za-z_][A-Za-z0-9_]*)=(.*)$")
_SENSITIVE_ENV_NAME = re.compile(r"(?i)(api[_-]?key|secret|token|password)")


@dataclass(frozen=True, slots=True)
class Finding:
    path: Path
    line: int
    rule: str

    def format(self) -> str:
        return f"{self.path}:{self.line}: potential secret detected ({self.rule})"


def iter_text_files(root: Path):
    """Yield repository text files while excluding generated and vendor paths."""

    for path in root.rglob("*"):
        if not path.is_file():
            continue
        if any(part in _SKIP_DIRECTORIES for part in path.parts):
            continue
        if path.name in _TEXT_FILENAMES or path.suffix.lower() in _TEXT_SUFFIXES:
            yield path


def scan_text(text: str, relative_path: Path) -> list[Finding]:
    """Scan one text document for high-confidence secret indicators."""

    findings: list[Finding] = []
    is_env_file = relative_path.name == ".env" or relative_path.name.startswith(".env.")

    for line_number, line in enumerate(text.splitlines(), start=1):
        for rule, pattern in _HIGH_CONFIDENCE_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(relative_path, line_number, rule))

        assignment = _ASSIGNMENT_PATTERN.search(line)
        if assignment:
            value = assignment.group(2).strip()
            if value.lower() in _PLACEHOLDER_VALUES or len(value) >= 16:
                findings.append(Finding(relative_path, line_number, "hardcoded-credential"))

        if is_env_file:
            env_assignment = _ENV_ASSIGNMENT_PATTERN.match(line.strip())
            if env_assignment and _SENSITIVE_ENV_NAME.search(env_assignment.group(1)):
                value = env_assignment.group(2).strip().strip("\"'")
                if value:
                    findings.append(Finding(relative_path, line_number, "non-empty-env-secret"))

    return findings


def scan_repository(root: Path) -> list[Finding]:
    """Scan supported repository files and return deterministic findings."""

    findings: list[Finding] = []
    root = root.resolve()

    for path in iter_text_files(root):
        relative_path = path.relative_to(root)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        findings.extend(scan_text(text, relative_path))

    return sorted(findings, key=lambda item: (str(item.path), item.line, item.rule))


def main(argv: list[str] | None = None) -> int:
    root = Path(argv[0] if argv else ".")
    findings = scan_repository(root)

    if findings:
        for finding in findings:
            print(finding.format())
        print(f"Secret hygiene check failed with {len(findings)} finding(s).")
        return 1

    print("Secret hygiene check passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
