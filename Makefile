PYTHON ?= python3

FOCUSED_RUFF_FILES := \
	app/config.py app/enrichment.py app/parser.py \
	scripts/check_secrets.py tests/test_config.py \
	tests/test_parser.py tests/test_secret_scanner.py

FOCUSED_TESTS := \
	tests/test_config.py tests/test_parser.py tests/test_secret_scanner.py

.PHONY: install lint test security-scan check

install:
	$(PYTHON) -m pip install -r requirements.txt -r requirements-dev.txt

lint:
	$(PYTHON) -m ruff check $(FOCUSED_RUFF_FILES)

test:
	$(PYTHON) -m pytest $(FOCUSED_TESTS)

security-scan:
	$(PYTHON) scripts/check_secrets.py .

check: lint test security-scan
