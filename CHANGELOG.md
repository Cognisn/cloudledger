# Changelog

All notable changes to this project are documented in this file. The format follows Keep a Changelog (https://keepachangelog.com), and the project adheres to Semantic Versioning.

## [Unreleased]

### Added
- Baseline codebase: multi-account AWS scanner, assessment engine, Prowler integration, SQLite storage, and MCP stdio server, packaged as `cloudledger` with `cloudledger` and `cloudledger-mcp` entry points and dynamic versioning from `src/cloudledger/version.txt`.

### Changed
- Constrained the mcp dependency to <2.0.0: the server targets the mcp 1.x API.

## [0.1.0] - 2026-08-19

### Added
- Initial project scaffold.
