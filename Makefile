.PHONY: test lint format check coverage clean help

VENV := .venv
BIN := $(VENV)/bin

# If .venv exists, use its binaries. Otherwise assume they are in PATH.
ifeq ($(wildcard $(BIN)/python),)
    BLACK := black
    ISORT := isort
    RUFF := ruff
    MYPY := mypy
    PYTEST := pytest
else
    BLACK := $(BIN)/black
    ISORT := $(BIN)/isort
    RUFF := $(BIN)/ruff
    MYPY := $(BIN)/mypy
    PYTEST := $(BIN)/pytest
endif

# Default target
help:
	@echo "Cyanide Honeypot Development Commands:"
	@echo "  make lint      Run CI-style linting (black, isort, ruff, mypy)"
	@echo "  make format    Auto-format code to match CI standards"
	@echo "  make test      Run all tests"
	@echo "  make coverage  Run tests with coverage report"
	@echo "  make check     Run all linters and tests (full CI check)"
	@echo "  make clean     Remove temporary files and caches"

lint:
	$(BLACK) --check src/
	$(ISORT) --check-only src/
	$(RUFF) check src/
	$(MYPY) src/

format:
	$(RUFF) check --fix src/
	$(ISORT) src/
	$(BLACK) src/

test:
	$(PYTEST)

coverage:
	$(PYTEST) --cov=cyanide --cov-report=term-missing --cov-report=xml

check: lint test coverage

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} +
	find . -type d -name ".pytest_cache" -exec rm -rf {} +
	find . -type d -name ".mypy_cache" -exec rm -rf {} +
	find . -type d -name ".ruff_cache" -exec rm -rf {} +
	rm -f .coverage
	rm -f coverage.xml
