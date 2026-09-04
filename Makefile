PYTHON ?= python3

FOCUSED_RUFF_FILES := \
	app/config.py app/enrichment.py app/parser.py \
	scripts/check_secrets.py tests/test_config.py \
	tests/test_parser.py tests/test_secret_scanner.py

FOCUSED_TESTS := \
	tests/test_config.py tests/test_parser.py tests/test_secret_scanner.py

API_RUFF_FILES := api.py tests/test_api_contracts.py tests/test_api_readiness.py \
	tests/test_api_versioning.py tests/test_api_stats.py \
	tests/test_api_dependency_injection.py tests/test_api_security_boundary.py

API_TESTS := tests/test_api_contracts.py tests/test_api_readiness.py \
	tests/test_api_versioning.py tests/test_api_stats.py \
	tests/test_api_dependency_injection.py tests/test_api_security_boundary.py

.PHONY: install lint test api-check security-scan check

install:
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt

lint:
	$(PYTHON) -m ruff check $(FOCUSED_RUFF_FILES)

test:
	$(PYTHON) -m pytest $(FOCUSED_TESTS)

api-check:
	$(PYTHON) -m ruff check $(API_RUFF_FILES)
	$(PYTHON) -m pytest $(API_TESTS)

security-scan:
	$(PYTHON) scripts/check_secrets.py .

check: lint test security-scan
