# Dependency Management

NetSentinel uses exact version pins for both runtime and development dependencies. This keeps local installs, CI, and container builds reproducible and makes dependency changes explicit during review.

## Policy

- Every active requirement must use an exact `==` version pin.
- Runtime packages belong in `requirements.txt`.
- Test, lint, audit, and SBOM tools belong in `requirements-dev.txt`.
- Dependency updates should be isolated in a focused pull request.
- Update one related package group at a time when practical.
- Never suppress a vulnerability finding without documenting the affected package, advisory, exposure analysis, compensating controls, and planned removal date.

## Local verification

```bash
python -m pip install --upgrade pip
python -m pip install -r requirements.txt -r requirements-dev.txt
python scripts/check_dependency_pins.py
python -m pip_audit --strict
cyclonedx-py environment --output-format JSON --output-file netsentinel-sbom.json
```

The generated `netsentinel-sbom.json` is a build artifact and should not be committed. CI publishes it as a short-lived artifact for review and release evidence.

## Updating dependencies

1. Review upstream release notes and Python-version support.
2. Change the exact pin in the appropriate requirements file.
3. Reinstall into a clean virtual environment.
4. Run lint, tests, the secret scanner, the dependency audit, and SBOM generation.
5. Document compatibility risks and security motivation in the pull request.
6. Merge only after the supported Python matrix and supply-chain workflow pass.

## Vulnerability response

When `pip-audit` reports a vulnerability:

1. Confirm the installed package and affected version.
2. Determine whether NetSentinel imports or exposes the vulnerable behavior.
3. Upgrade to the nearest compatible fixed version.
4. Run the full focused test suite and container checks.
5. If no fix exists, open a tracked issue with impact, temporary controls, and a review date. Do not silently ignore the advisory.
