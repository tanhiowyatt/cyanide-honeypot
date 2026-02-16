# Testing Guide

## 1. Prerequisites

Dependencies are managed via `pyproject.toml`.
For local testing, install the project in editable mode with dev dependencies:

```bash
pip install -e .[dev]
```

## 2. Running Tests

### Inside Docker (Recommended)
This ensures the environment matches production (Python version, OS libraries).

```bash
# Run all tests
docker exec -it cyanide pytest tests/

# Run specific test
docker exec -it cyanide pytest tests/integration/test_ssh_server.py
```

### Locally
```bash
pytest tests/
```

## 3. Test Structure

| Directory | Purpose |
|-----------|---------|
| `tests/unit/` | Isolated component tests (Shell, VFS, ML). |
| `tests/integration/` | End-to-end flows (SSH login, file download). |
| `tests/conftest.py` | Shared fixtures (`mock_fs`, `event_loop`). |

## 4. Continuous Integration
GitHub Actions workflows are defined in `.github/workflows/`:
- `tests.yml`: Runs `pytest` on push.
- `lint.yml`: Runs `ruff` linter.
