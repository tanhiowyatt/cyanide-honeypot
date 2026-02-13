# Changelog

All notable changes to this project will be documented in this file.

## [2.1.1] - 2026-02-13

### Security
- **DNS Rebinding Prevention**: Fixed a vulnerability in `validate_url` (used by `curl` and `wget`).
    - Now validates all IP addresses returned by DNS resolution.
    - Implemented a 60-second DNS cache to pin the resolved IP address for the duration of the request, preventing Time-of-Check Time-of-Use (TOCTOU) attacks.
    - Updated `curl` and `wget` to use the pinned IP address while preserving the original `Host` header.

### Changed
- **Metadata Loading Refactoring**: Consolidated OS-specific metadata (banners, kernel versions) into YAML configuration files.
    - Removed `src/cyanide/core/system_profiles.py` to eliminate code duplication.
    - Implemented a robust fallback mechanism in `yaml_fs.py` and `server.py` using `src/cyanide/core/defaults.py`.
    - Updated "random" profile selection to dynamically pick from available YAML files in `config/fs-config/`.
- **Smoke Test Cleanup**: Updated `tests/smoke_test.py` to use the `requests` library instead of `urllib.request` for better consistency and cleaner code.
- **Configurable DNS TTL**: Added `dns_cache_ttl` to `[honeypot]` section in `cyanide.cfg` (defaults to 60s).
- **DNS Metrics**: Added `cyanide_dns_cache_hits_total` and `cyanide_dns_cache_misses_total` Prometheus metrics.
- **Refined Health Check**: Improved `/health` endpoint to accurately check statuses of enabled services.
- **Observability Docs**: Created `docs/OBSERVABILITY.md` with Jaeger/Tracing setup instructions.

### Fixed
- Circular import between `server.py` and `yaml_fs.py` by moving profile constants to `src/cyanide/core/defaults.py`.

## [2.1.0] - 2026-02-12
### Added
- **Dependabot**: Integrated Dependabot for pip and Docker dependency management.
- **Enhanced Security**: Implemented nosemgrep comments audit and removed unnecessary security exceptions.
- **Improved Testing**: Expanded testing infrastructure and added Tox-based test automation.

### Changed
- **Logging Architecture**: Refactored logging to use a nested `logging.directory` structure for better organization.
- **Filesystem Persistence**: Migrated from `pickle` to `YAML` for the emulated filesystem, improving readability and manual editability.
- **CI/CD Overhaul**: Modernized the GitHub Actions workflow with multi-architecture Docker builds, CodeQL, and Semgrep.

### Fixed
- Standardized conditional assignments and suppressed deprecation warnings across core modules.

## [2.0.0] - 2026-02-10
### Added
- **Advanced Networking**: Implemented a functional `curl` command with network request simulation and quarantine integration.
- **Core Services**: Introduced new service layers for session management and quarantine handling.
- **Project Structure**: Rearchitected the project into the `src/cyanide` package structure for better modularity.

### Changed
- **Secure Deserialization**: Implemented `SafeUnpickler` with allow-listed classes to prevent insecure deserialization vulnerabilities.
- **Structured Logging**: Replaced standard print statements with structured JSON logging for all honeypot events.
- **ML Infrastructure**: Revamped Machine Learning training and logging, moving to a feature-vector-based detection system.

## [1.0.0] - 2026-02-05
### Added
- **AI/ML Integration**: Introduced initial anomaly detection capabilities for shell interactions.
- **Metrics Server**: Added a Prometheus metrics endpoint and a `stats` CLI tool for real-time monitoring.
- **Docker Support**: Initial implementation of Docker and Docker Compose deployment.
- **Fake FS Expansion**: Added root secrets, common Linux binaries, and enhanced `sudo`/`grep` functionality.

### Changed
- **Rearchitecture**: Moved from a flat structure to a package-based layout.
- **Async Implementation**: Converted core server logic and command execution to use `asyncio`.

## [0.1.0] - 2026-02-01
### Added
- **Initial Release**: First commitment of the Cyanide Honeypot core.
- **Basic Commands**: Implementation of `wget`, `ls`, `cd`, `pwd`, and basic shell logic.
- **Quarantine System**: Base implementation for isolating downloaded files.
