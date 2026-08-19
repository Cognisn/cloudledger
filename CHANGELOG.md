# Changelog

All notable changes to this project are documented in this file. The format follows Keep a Changelog (https://keepachangelog.com), and the project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Baseline codebase: multi-account AWS scanner, assessment engine, Prowler integration, SQLite storage, and MCP stdio server, packaged as `cloudledger` with `cloudledger` and `cloudledger-mcp` entry points and dynamic versioning from `src/cloudledger/version.txt`.
- konfig-backed settings, secrets, and run-scoped logging (`cognisn-konfig`); logging is stderr-safe for MCP stdio operation and stored in the platform log directory.

### Changed
- Constrained the mcp dependency to <2.0.0: the server targets the mcp 1.x API.
- `--database` is now optional for `scan`, `delete-scan`, and the MCP server: the path resolves from the CLI option, then the `database.path` setting, then the platform data directory default.
- Removed the bespoke logging module (`utils/logging_config.py`); modules use standard `logging.getLogger` with konfig-managed handlers.

## [0.1.0] - 2026-08-19

### Added
- Initial project scaffold.
