# Changelog

All notable changes to Shuttle are documented here.

## [Unreleased]

### Changed (BREAKING)

- **Approval queue replaces confirm tokens** — `ssh_run` no longer accepts `confirm_token`; the AI can no longer approve its own commands. CONFIRM-level commands now create a durable approval (DB-backed, survives restarts) that a human decides in the web panel's new **Approvals** page. New `ssh_run` parameters: `approval_id` (re-poll a pending approval — re-send the command byte-for-byte) and `approval_wait` (synchronous wait budget; progress-capable MCP clients extend to the approval TTL automatically). Config: `SHUTTLE_APPROVAL_TTL` (default 900 s), `SHUTTLE_APPROVAL_WAIT` (default 20 s). ADR-0001 has the rationale.

### Added

- Approvals page in the web panel (pending queue with live countdown, reject-reason textarea shown to the AI verbatim, history with exit codes) and REST API: `GET /api/approvals`, `GET /api/approvals/{id}`, `POST /api/approvals/{id}/approve`, `POST /api/approvals/{id}/reject`.
- Audit trail: `command_logs.stderr` is now persisted (64 KB cap), `command_logs.approval_id` links log rows to approval decisions, and `bypassed` is only true for real bypass paths.

### Fixed

- **SSH config parser: quoted values** ([#7](https://github.com/enwaiax/shuttle/issues/7)) — `IdentityFile "~/.ssh/id_rsa"` kept its surrounding quotes, so `resolve_key()` failed to find the key and `shuttle node import` silently skipped the host. Single quotes and quoted paths containing spaces are handled too.
- **SSH config parser: `Key = Value` separator** — a spaced `=` left the `=` inside the value, e.g. `Port = 2222` raised `ValueError` and aborted the entire parse, so no hosts could be imported.

## [0.2.2] - 2026-03-22

### Added

- **`shuttle-mcp` console script** — same entry as `shuttle`, so `uvx shuttle-mcp` matches the PyPI package name without `--from … shuttle`.

### Changed

- User docs and examples: prefer `uv` / `uvx` over `pip` for install instructions; MCP config examples use `args: ["shuttle-mcp"]` with a short note for older wheels.

## [0.2.1] - 2026-03-21

### Changed

- Switch license from ISC to MIT
- Add pre-commit hooks (ruff, trailing-whitespace, uv-lock)
- Upgrade ruff rules (isort, pyupgrade, bugbear, comprehensions)
- Auto-fix 73 lint issues across codebase
- CLI: Rich table output for `node list` and `config show`
- CLI: `node add` supports non-interactive mode (`--name`, `--host`, etc.)
- CLI: Input validation — empty fields rejected, key file existence checked
- Node default status changed from `active` to `inactive` until test passes
- Replace mkdocs.yml with zensical.toml
- Fix CI Node.js 20 deprecation (upgrade to Node 22)
- Fix Codecov upload configuration

## [0.2.0] - 2026-03-21

### Added

- **Service mode** (`shuttle serve`) — MCP + Web UI on a single HTTP port
- **Web control panel** — React dark-theme UI with nodes, activity logs, rules, settings
- **9 MCP tools** — ssh_execute, ssh_upload, ssh_download, ssh_list_nodes, ssh_add_node, ssh_remove_node, ssh_session_start/end/list
- **4-level command security** — block, confirm, warn, allow with regex patterns
- **Connection pooling** — per-node SSH connection reuse with idle eviction
- **Session isolation** — stateful sessions with working directory tracking
- **Per-node security rules** — override global defaults per server
- **Jump host support** — connect through bastion servers
- **Credential encryption** — Fernet encryption for passwords and private keys at rest
- **18 REST API endpoints** — nodes, rules, sessions, logs, settings, stats
- **Auto-cleanup** — old logs and closed sessions cleaned up on startup
- **Database indexes** — optimized query performance for hot paths

### Infrastructure

- SQLAlchemy 2.0 async ORM with SQLite WAL mode
- FastMCP 2.0 with Context dependency injection
- Typer CLI with interactive and non-interactive modes
- GitHub Actions CI (test + frontend + build), docs deploy, release pipeline
- Codecov integration

## [0.1.0] - 2025-12-01

### Added

- Initial release — basic SSH MCP tools (execute, upload, download)
- FastMCP server with stdio transport
- Simple command whitelist/blacklist security
