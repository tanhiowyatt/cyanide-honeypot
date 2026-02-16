# Developer Guide

This guide is intended for developers who want to contribute to the Cyanide Honeypot project.

---

## 🛠️ Development Environment

We use **Docker** for runtime consistency, but you should set up a local Python environment for IDE support (autocompletion, linting).

### 1. Local Setup
```bash
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies in editable mode
pip install -e .[dev]
```

### 2. Docker Workflow
The `docker-compose.yml` mounts the source code (`src/` and `configs/`) into the container, allowing hot-reloading for code changes (server restart is still required for most changes).

```bash
# Start container
docker-compose -f deployments/docker/docker-compose.yml up --build

# Run shell inside container
docker exec -it cyanide /bin/bash
```

---

## 🧪 Testing

We use `pytest` for unit and integration testing.

### Running Tests
It is recommended to run tests inside the container to match the production environment:

```bash
docker exec -it cyanide pytest tests/
```

Or locally if you have dependencies installed:
```bash
pytest tests/
```

### Writing Tests
*   **Location**: `tests/`
*   **Async**: Use `pytest-asyncio`.
*   **Mocks**: Heavily used for `asyncssh` and `FakeFilesystem`.

---

## 🏛️ Architecture

### Key Components

1.  **Entry Point**: `src/cyanide/main.py` -> `src/cyanide/core/server.py`
2.  **VFS (`src/cyanide/vfs`)**:
    *   `provider.py`: The `FakeFilesystem` class.
    *   `commands/*.py`: Emulated commands (ls, cd, wget).
3.  **ML Engine (`src/cyanide/ml`)**:
    *   `pipeline.py`: The hybrid detection pipeline.
    *   `autoencoder.py`: PyTorch anomaly detector.
4.  **Network (`src/cyanide/network`)**:
    *   `tcp_proxy.py`: Generic asyncio TCP forwarder.

### Directory Map
| Path | Component |
|------|-----------|
| `src/cyanide/core/` | Server orchestration, config loading. |
| `src/cyanide/vfs/` | Filesystem emulation and command logic. |
| `src/cyanide/ml/` | Machine Learning models and analytics. |
| `configs/profiles/` | YAML templates for OS emulation. |
| `deployments/docker/` | Dockerfile and Compose configurations. |

---

## 🧩 Extending Functionality

### Adding a New Command
To add a supported command (e.g., `git`):

1.  Create `src/cyanide/vfs/commands/git.py`.
2.  Inherit from `BaseCommand`.
3.  Implement `execute(self, args, ctx)`.
4.  Register it in `src/cyanide/vfs/commands/__init__.py`.

### Adding a New ML Feature
1.  Modify `src/cyanide/ml/pipeline.py`.
2.  Update the `analyze_command` method to include your new logic.

---

## 📦 Release
1.  Bump version in `pyproject.toml`.
2.  Update `CHANGELOG.md`.
3.  Build image: `docker build -f deployments/docker/Dockerfile .`
