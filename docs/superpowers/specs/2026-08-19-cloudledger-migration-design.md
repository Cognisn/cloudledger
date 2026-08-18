# CloudLedger — Migration and Productionisation Design

**Date:** 2026-08-19
**Status:** Approved pending final review
**Source project:** `/Users/matthewwestwood-hill/Projects/digital-thought/dtAWSScannerMCP` (package `dt_aws_scanner`, v2.1.0a6)
**Target:** `Cognisn/cloudledger` — https://github.com/Cognisn/cloudledger

## 1. Purpose

CloudLedger is the productionised, Cognisn-branded successor to Digital Thought's
`dtAWSScannerMCP`: a multi-account AWS security scanning and infrastructure
documentation tool (Prowler-integrated) with an MCP stdio server for querying
historical scan data. This migration rebrands and repackages the project for PyPI
distribution under the new name, and adds four capabilities:

1. Scan tagging, searchable from both the CLI and the MCP tools.
2. An interactive AWS Organisation / control-tower awareness flow during scans.
3. Settings, secrets, and logging via the `cognisn-konfig` library.
4. Multi-backend database support (SQLite, PostgreSQL, MySQL, MSSQL) configured
   through a new `setup` command.

The original project is never modified and remains as a reference. Existing
`scanner.db` databases are **not** migrated (clean break): old data stays readable
via the old tool; CloudLedger starts with a fresh schema.

## 2. Identity and packaging

| Item | Value |
|---|---|
| PyPI package | `cloudledger` (confirmed free on PyPI) |
| Import package | `cloudledger` |
| CLI entry points | `cloudledger` (scanner CLI), `cloudledger-mcp` (MCP stdio server) |
| Initial version | `0.1.0` (pre-release builds `0.1.0a1`… on the release branch) |
| Python | `>=3.12,<3.13` (Prowler pins numpy 2.0.2 — no wheels beyond 3.12) |
| Build backend | hatchling; uv-managed with `uv.lock` committed |
| Licence | MIT, author Cognisn |
| Repository | `Cognisn/cloudledger` (public; created 2026-08-19) |

Prowler remains a **core dependency**, exactly as in the source project.

Runnable three ways:
- In-repo: `uv sync` then `uv run cloudledger …` / `uv run cloudledger-mcp`.
- From PyPI ad hoc: `uvx cloudledger …`.
- Installed: `uv tool install cloudledger`.

Package layout (carried over from the source, plus one new module):

```
src/cloudledger/
├── scanner/      # CLI, AWS collector, credential manager, CSV input, Prowler
├── assessment/   # built-in security checks
├── database/     # SQLAlchemy Core metadata, operations, engine factory
├── mcp/          # MCP stdio server, tools, queries
├── config/       # NEW — konfig wiring (AppContext factory, settings keys)
└── utils/        # helpers (bespoke logging module removed — konfig owns logging)
```

## 3. Phase 1 — migrated baseline (client-agnostic migration)

Use the `client-agnostic-migration` skill pipeline (non-destructive; writes only to
the target directory):

1. **Scan** the source for client-specific identifiers and confirm the rename
   inventory with the user. Expected mappings (casing-aware; the tool derives
   variants):
   - `dt_aws_scanner` / `dt-aws-scanner` / `dtAWSScannerMCP` → `cloudledger`
   - `Digital Thought` / `digital-thought` → `Cognisn` / `cognisn`
   - Entry points `aws-scanner` → `cloudledger`, `aws-scanner-mcp` → `cloudledger-mcp`
2. **Apply** into this directory. Excluded from the copy: `.git` history, caches,
   virtualenvs, build artefacts, logs, and all data files (`scanner.db`,
   `.database.db`, `accounts.csv`, `costs.csv`, `*.log`).
3. **Verify**: residual-term check, `py_compile` across the package, ported test
   suite passing, `pyproject.toml` carrying the new name/entry points. Review
   `MIGRATION_REPORT.md` and walk the manual follow-up list with the user.

The verified baseline is the **first code commit on `main`** (the committed design
spec precedes it). All subsequent work is feature branches.

## 4. konfig integration

Dependency: `cognisn-konfig` (import name `konfig`; published on PyPI).

- Both entry points run inside
  `AppContext(name="CloudLedger", env_prefix="CLOUDLEDGER", …)`; settings, secrets,
  and run-scoped logging all come from the context.
- The bespoke `utils/logging_config.py` is deleted. The MCP server uses konfig's
  stderr console mode — konfig never writes to stdout, which keeps the stdio
  JSON-RPC channel clean.
- **Settings** (konfig user settings file) hold non-secret configuration: database
  backend choice, host, port, database name, username, default regions, Prowler
  defaults. **Secrets** (OS keyring backend by default) hold the database password,
  referenced from settings as `secret://cloudledger.db.password`.
- The default SQLite database lives at `konfig.paths.data_dir("cloudledger")/cloudledger.db`.
  The `--database` CLI option still overrides the configured location for portable,
  per-engagement database files.

## 5. Database layer — SQLAlchemy Core, multi-backend

The source's raw `sqlite3` layer (~10,000 lines of hand-written SQL across
`database/schema.py`, `database/operations.py`, and `mcp/queries.py`) is rewritten
on **SQLAlchemy Core** (no ORM):

- One metadata module defines all tables with dialect-portable types. JSON payloads
  remain serialised into `Text` columns, matching current behaviour.
- All inserts and queries become Core expressions; bulk inserts use
  `executemany`-style Core constructs.
- A small **engine factory** builds the engine from konfig settings:
  `sqlite:///…`, `postgresql+psycopg://…`, `mysql+pymysql://…`, `mssql+pyodbc://…`.
- Backend drivers ship as extras: `cloudledger[postgres]`, `cloudledger[mysql]`,
  `cloudledger[mssql]`, `cloudledger[all-db]`. SQLite works with no extra.
- Schema versioning keeps the existing simple `schema_version` table approach.
  No Alembic at 0.1.0 — the schema is always created fresh (clean break).

### `cloudledger setup`

Interactive configuration command:

1. Choose backend: SQLite (default) or PostgreSQL / MySQL / MSSQL.
2. SQLite: confirm or override the konfig data-dir path.
   Server backends: prompt for host, port, database name, username, password.
3. Password is stored via konfig Secrets; everything else via konfig user settings.
4. Test the connection, then create the schema.
5. Re-running `setup` shows the current configuration and allows changes.

## 6. Scan tagging

- **Schema:** a single `scan_tags` join table (`scan_id`, `tag`), unique together,
  indexed both ways. Tags are free-form text, case-preserved on write, matched
  case-insensitively. A scan may have any number of tags.
- **CLI:**
  - `cloudledger scan --tag <t>` (repeatable); the interactive flow also prompts
    for tags; CSV batch mode gains an optional `tags` column (semicolon-separated).
  - `cloudledger tag add <scan-id> <tag>…` / `tag remove <scan-id> <tag>…`
  - `cloudledger tag list` — all tags with scan counts.
  - `cloudledger tag find <tag>` — matching scans with account, date/time, and
    their other tags.
- **MCP:** new tools `search_scans_by_tag` and `list_scan_tags`; existing
  scan-metadata responses gain a `tags` field.

## 7. AWS Organisation / control-tower flow

Runs in **interactive scan mode only**. CSV batch mode stays fully unattended;
optional CSV columns may pre-declare the same fields, with no prompting.

During interactive account entry, after credentials are gathered:

1. Ask whether the target account is a member of an AWS Organisation. If no, done.
2. If yes, ask whether it is the control-tower (management) account. If yes,
   record that.
3. If no, prompt for the management account's **name** and **account id**, then
   look the id up in the database:
   - **No scan found:** advise the user and ask whether they wish that account to
     be scanned. If yes, it is queued: once the current target's scan completes,
     prompt for the management account's credentials and scan it.
   - **Scan found:** report the date/time of the most recent scan and ask whether
     to rescan. If yes, queued identically.
4. A queued management-account scan is automatically recorded as the management
   account of the organisation; steps 1–3 are not re-asked for it.

Recorded on every scan: `org_member` (bool), `is_management_account` (bool),
`management_account_id`, `management_account_name` — enabling the ledger to link
member accounts to their management account.

Answers are prompt-driven. No AWS Organizations API calls at 0.1.0 (scan
credentials frequently lack `organizations:Describe*`); API pre-fill of the prompt
defaults is a possible later enhancement.

## 8. Testing

- The existing pytest suite is ported through the rename and must pass at baseline.
- New coverage: tag operations (database + CLI), the org prompt flow and scan
  queue (Click `CliRunner`), the `setup` command, the engine factory, and the
  MCP tag tools.
- Database tests run against SQLite by default. PostgreSQL, MySQL, and MSSQL get
  opt-in integration tests behind a `docker-compose.yml` with pytest markers that
  auto-skip when the containers are not running (the same pattern konfig uses for
  its LocalStack tests).

## 9. Versioning, branching, and release

- Baseline (renamed, verified) → first code commit on `main`.
- Feature branches: `feat/konfig-integration`, `feat/db-multibackend`,
  `feat/scan-tagging`, `feat/org-flow` (order matters: konfig, then the database
  layer, then the features that build on both).
- Release branch `release/v0.1.0` for alpha/beta testing (`0.1.0a1`, `0.1.0b1`…);
  merged to `main`, tagged `v0.1.0`, built and published to PyPI.
- Fresh `CHANGELOG.md` starting at 0.1.0. Australian English throughout. No AI
  co-authorship references in commits, changelogs, or release notes.

## 10. Out of scope

- Migration or import of existing `dtAWSScannerMCP` databases.
- Multi-cloud support (Azure/GCP) — the name allows for it later; not now.
- AWS Organizations API auto-detection in the org flow.
- Alembic migrations (revisit when the schema first changes after release).
- Making Prowler optional.
