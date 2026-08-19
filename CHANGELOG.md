# Changelog

All notable changes to this project are documented in this file. The format follows Keep a Changelog (https://keepachangelog.com), and the project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Baseline codebase: multi-account AWS scanner, assessment engine, Prowler integration, SQLite storage, and MCP stdio server, packaged as `cloudledger` with `cloudledger` and `cloudledger-mcp` entry points and dynamic versioning from `src/cloudledger/version.txt`.
- konfig-backed settings, secrets, and run-scoped logging (`cognisn-konfig`); logging is stderr-safe for MCP stdio operation and stored in the platform log directory.
- `cloudledger setup`: interactive configuration of the database backend (SQLite or a server backend), with server credentials held securely in the operating system keyring.
- PostgreSQL, MySQL, and MSSQL storage support via the optional `[postgres]`, `[mysql]`, `[mssql]`, and `[all-db]` extras.
- Docker-backed opt-in integration tests (`pytest -m db`) exercising the postgres, mysql, and mssql backends against a `docker-compose.yml` service set.
- Scan tagging: apply tags at scan time (`scan --tag`, repeatable) or interactively, tag scans retrospectively via `tag add`/`tag remove`, list all tags with `tag list`, search the ledger by tag with `tag find`, and supply tags for CSV batch scans via a semicolon-separated `tags` column. Exposed through the MCP server as the `search_scans_by_tag` and `list_scan_tags` tools, and every scan response now carries its `tags`.
- Interactive AWS Organisation / control-tower flow: scans now capture organisation membership and the managing (control-tower) account, offer to scan the management account when the ledger has no record of it, queue that follow-up scan for after the current account completes, and dedupe repeat requests for the same management account. CSV batch scans can pre-declare the same organisation fields via four optional columns.

### Changed
- Constrained the mcp dependency to <2.0.0: the server targets the mcp 1.x API.
- `--database` is now optional for `scan`, `delete-scan`, and the MCP server: the path resolves from the CLI option, then the `database.path` setting, then the platform data directory default.
- Removed the bespoke logging module (`utils/logging_config.py`); modules use standard `logging.getLogger` with konfig-managed handlers.
- Database layer rewritten onto SQLAlchemy Core: schema declared as table metadata with an equivalence harness against the legacy DDL, engine factory accepting paths or URLs, and all insert/query operations expressed as Core statements. Stored formats are unchanged; SQLite remains the only user-facing backend until the setup command lands.
- MCP query layer rewritten onto SQLAlchemy Core with a query-output equivalence harness proving unchanged behaviour; the transitional sqlite connection shim is removed, making the entire query layer dialect-portable.
- Assessment engine now runs on SQLAlchemy connections, completing dialect portability of the data layer.
- All recorded date/times are UTC on every backend (client-side UTC stamps for bookkeeping columns; aware ISO 8601 serialisation for scan timestamps), and every MCP tool description states that timestamps are UTC.
- Distribution renamed to cognisn-cloudledger on PyPI (the import package and the cloudledger/cloudledger-mcp commands are unchanged).

### Fixed
- MySQL and MSSQL schema creation: bounded dialect-specific column types wherever those dialects forbid defaults or keys on unbounded text; timestamp bookkeeping columns are typed DATETIME on MySQL.

## [0.1.0] - 2026-08-19

### Added
- Initial project scaffold.
