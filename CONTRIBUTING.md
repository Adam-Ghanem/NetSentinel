# Contributing to NetSentinel

Thank you for helping improve NetSentinel. The project is an educational network-metadata monitoring prototype, so contributions should be useful for learning, defensive security, and reliable local operation.

## Before you start

Please read the [README](README.md), [SECURITY.md](SECURITY.md), and [ROADMAP.md](ROADMAP.md) before making a change. Use NetSentinel only in environments where you are authorized to monitor network traffic. Do not submit live packet captures, credentials, API keys, private keys, or other sensitive data.

For larger changes, open an issue or start a discussion first so the scope and design can be agreed before implementation. Small documentation, test, and bug-fix changes can usually be submitted directly as a pull request.

## Local development

NetSentinel supports Python 3.10 and newer. Create an isolated environment and install the development dependencies:

```bash
git clone https://github.com/Adam-Ghanem/NetSentinel.git
cd NetSentinel
python3 -m venv venv
source venv/bin/activate
pip install -r requirements-dev.txt
cp .env.example .env
```

Keep `.env` local. Use placeholder values in tests and documentation; never commit real service credentials.

## Validation before a pull request

Run the focused checks that match your change. The following baseline mirrors the repository’s documented local checks:

```bash
python -m ruff check \
  app/config.py app/enrichment.py app/parser.py \
  scripts/check_secrets.py tests/test_config.py \
  tests/test_parser.py tests/test_secret_scanner.py
python -m pytest \
  tests/test_config.py tests/test_parser.py tests/test_secret_scanner.py
python scripts/check_secrets.py .
```

The CI workflow runs additional targeted checks for database, migration, container, detection, and deployment changes. If your change affects one of those areas, run the corresponding tests locally as well. If a test cannot run in your environment, explain the limitation in the pull request rather than silently omitting the check.

## Branches and commits

Create a short-lived branch from `main` and keep each commit focused on one logical change:

```bash
git checkout main
git pull --ff-only origin main
git checkout -b docs/improve-contributor-guide
```

Use a concise imperative commit subject, such as `docs: clarify local contributor workflow`. Avoid unrelated formatting changes, generated files, and artificial commits that do not improve the project.

### GitHub attribution

For commits to appear on the intended GitHub profile, configure Git with an email address that is verified on that account, such as the account’s GitHub-provided `users.noreply.github.com` address:

```bash
git config user.name "Your GitHub name"
git config user.email "YOUR_ID+YOUR_USERNAME@users.noreply.github.com"
git config --get user.email
```

Check the author and email shown by `git log -1 --format=fuller` before pushing. If a commit was created with an unverified address, GitHub may show it in the repository history without attributing it to the profile’s contribution graph.

## Pull requests

A pull request should explain what changed, why it was needed, and how it was validated. Include the relevant test commands and describe any known limitations. For dashboard or workflow changes, include a short reproduction or verification path. For security-sensitive changes, follow the private reporting process described in [SECURITY.md](SECURITY.md) instead of disclosing a vulnerability in a public issue.

Maintainers may request changes to improve correctness, test coverage, documentation, or operational safety. Please keep follow-up commits focused and update the pull-request description when the scope changes.

## Documentation and detection rules

Documentation should distinguish implemented behavior from planned behavior. Detection-rule changes should include clear severity rationale, false-positive guidance, and tests for both matching and non-matching traffic where practical. Sample data must be synthetic or safely sanitized.

## Code of conduct

Be respectful, precise, and constructive. Contributions are expected to support defensive security education and responsible operation of the project.
