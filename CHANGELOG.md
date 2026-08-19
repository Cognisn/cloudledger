# Changelog

All notable changes to this project are documented in this file. The format follows Keep a Changelog (https://keepachangelog.com), and the project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Baseline codebase: multi-account AWS scanner, assessment engine, Prowler integration, SQLite storage, and MCP stdio server, packaged as `cloudledger` with `cloudledger` and `cloudledger-mcp` entry points and dynamic versioning from `src/cloudledger/version.txt`.
- konfig-backed settings, secrets, and run-scoped logging (`cognisn-konfig`); logging is stderr-safe for MCP stdio operation and stored in the platform log directory.
- `cloudledger setup`: interactive configuration of the database backend (SQLite or a server backend), with server credentials held securely in the operating system keyring.
- PostgreSQL, MySQL, and MSSQL storage support via the optional `[postgres]`, `[mysql]`, `[mssql]`, and `[all-db]` extras.
- Docker-backed opt-in integration tests (`pytest -m db`) exercising the postgres, mysql, and mssql backends against a `docker-compose.yml` service set.

### Changed
- Constrained the mcp dependency to <2.0.0: the server targets the mcp 1.x API.
- `--database` is now optional for `scan`, `delete-scan`, and the MCP server: the path resolves from the CLI option, then the `database.path` setting, then the platform data directory default.
- Removed the bespoke logging module (`utils/logging_config.py`); modules use standard `logging.getLogger` with konfig-managed handlers.
- Database layer rewritten onto SQLAlchemy Core: schema declared as table metadata with an equivalence harness against the legacy DDL, engine factory accepting paths or URLs, and all insert/query operations expressed as Core statements. Stored formats are unchanged; SQLite remains the only user-facing backend until the setup command lands.
- MCP query layer rewritten onto SQLAlchemy Core with a query-output equivalence harness proving unchanged behaviour; the transitional sqlite connection shim is removed, making the entire query layer dialect-portable.
- Assessment engine now runs on SQLAlchemy connections, completing dialect portability of the data layer.

## [0.1.0] - 2026-08-19

### Added
- Initial project scaffold.
