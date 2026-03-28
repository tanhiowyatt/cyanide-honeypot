# Cyanide Stabilization & Logging Improvements

This document summarizes the major stabilization and architectural improvements implemented in the recent updates (March 2026).

## 1. Logging Determinism & Parity
We have unified the logging architecture to ensure that **global logs** (e.g., `cyanide-fs.json`) and **session-specific logs** (e.g., `audit.json` in TTY folders) are structurally identical.

### Key Changes:
- **Strict JSON Field Ordering**: All logs now follow a deterministic field order:
  1. `timestamp` (ISO-8601 UTC)
  2. `session` (Session ID)
  3. `eventid` (Event Type)
  4. `src_ip` (Source IP, if available)
  5. `...payload fields...` (Event-specific data)
  6. `geoip` (Enriched location data, if available)
- **Unified Routing**: Refactored `CyanideLogger.log_event` to use a single "preparation" pipeline, ensuring consistency across all output plugins and file mirrors.

---

## 2. Accurate SSH Fingerprinting
Resolved issues where SSH client fingerprints were incomplete or contained `null` values for key exchange algorithms.

### Implementation Details:
- **Algorithm Capture**: Since `asyncssh` clears internal KEX data after the handshake, we implemented a **monkey-patch** on `SSHServerConnection.set_extra_info`. This captures `kex_alg` and `host_key_alg` at the exact moment the handshake completes.
- **Improved Timing**: Moved client version and fingerprint logging to the `begin_auth` phase. This ensures the SSH banner exchange is fully finished and all connection metadata is available.
- **Security Compliance**: Added `usedforsecurity=False` to MD5 hashing calls (used for fingerprinting) to satisfy security scanners (Bandit/Semgrep) without compromising functionality.

---

## 3. Architectural Reliability & Maintainability
Substantial technical debt was resolved to improve the system's long-term stability and meet performance quality gates.

### Cognitive Complexity Reductions:
We refactored high-complexity functions (Complexity > 20) into smaller, testable units (Complexity < 15):
- **`AsyncLogger._worker`**: Extracted queue processing and I/O into helper methods.
- **`CyanideServer.stop`**: Centralized service shutdown logic into `_close_server`.
- **`CyanideLogger.log_event`**: Separated GeoIP resolution, entry preparation, and mirroring.
- **`AnalyticsService.log_geoip`**: Refactored threat identification into signature-based lookups.

### Exception & Task Handling:
- **Async Cancellation**: Implemented strict `asyncio.CancelledError` propagation. Background tasks no longer swallow cancellation signals, preventing "zombie" tasks during shutdown.
- **Redundant Exceptions**: Removed redundant `except (Subclass, Parent)` blocks (S5713) to comply with modern Python 3.11+ exception hierarchy.
- **Stale Parameters**: Cleaned up the `log_geoip` service API by removing unused `session_id` and `protocol` parameters.

### Detection & Alerting:
- **Configurable Honeytokens**: Replaced hardcoded alerting paths with a hierarchical lookup system (Global Config > OS Profile > Defaults). This allows distribution-specific alerts (e.g., `/etc/pacman.conf` for Arch Linux) without changing core code.

---

## 4. Developer Tools & CI/CD
- **Linting & Typing**: Fixed all `ruff` and `mypy` errors related to missing `Optional/Union` imports and queue typing.
- **Test Artifacts**: Added `MagicMock/` to `.gitignore` and updated tests to use proper temporary directory fixtures, preventing repository pollution.
