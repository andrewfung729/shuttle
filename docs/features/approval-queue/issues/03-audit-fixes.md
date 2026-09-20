# 03 — Audit fixes (stderr, bypassed accuracy, approval linkage, stub removal)

Status: resolved
Blocked by: 02

## Context

Audit gaps found while analyzing the current implementation (`src/shuttle/mcp/tools.py`, `src/shuttle/core/session.py`). Fixed on top of the new approval flow to avoid conflicting edits.

## Tasks

- [ ] Persist stderr: `CommandLog.stderr` currently hardcoded `None` — store `_truncate(stderr, MAX_DB_OUTPUT_BYTES)`.
- [ ] `bypassed` accuracy: set `bypassed=True` iff the command matched a confirm/warn rule AND was permitted via an approval claim or a session bypass pattern. Never merely "a parameter was present".
- [ ] `CommandLog.approval_id`: new nullable String(36) column (plain string, no FK — same pattern as `security_rule_id`); add the idempotent column migration to `init_db` (both sqlite and information_schema branches, following the `latency_ms` precedent). Stamp it when executing under a claim.
- [ ] Back-fill `approval.exec_exit_code` after execution (best-effort; wrap in the existing try/except logging pattern).
- [ ] Delete dead stubs in `core/session.py`: `_persist_session`, `_persist_session_close`, `_persist_command_log`, and the unused `db_session_factory` constructor plumbing + its call sites (`server.py` / `cli.py` wiring).
- [ ] Document the invariant in `session.py`'s module docstring: `_execute_command_logic` is the single audit point — no execution path may bypass it.
- [ ] Normalize one loguru call: `logger.warning("Failed to persist command log for {cmd}", cmd=...)` → f-string. **Style consistency only — the kwargs form is valid loguru** (the WARN-branch call in the same `tools.py` already uses it); do not describe this as a bug fix in the PR.

## Acceptance criteria

- Tests: failed command's stderr lands in the log row (truncated at 64 KB); `bypassed` false for plain allow-level runs even when `approval_id` is passed; true for a claim-executed confirm run; `approval_id` + `exec_exit_code` present on the log row and approval row respectively; `SessionManager` constructs without `db_session_factory` everywhere.

## Notes

- Column migration must keep existing DBs working (PRAGMA `table_info` check pattern already in `init_db`).

## Comments

Implemented: stderr persisted (64 KB truncate), bypassed=True only via approval claim or session-bypass regex hit (`_session_bypass_matched`), `command_logs.approval_id` column with idempotent PRAGMA/information_schema migrations, `exec_exit_code` back-fill best-effort, dead `_persist_*` stubs and `db_session_factory` plumbing deleted, single-audit-point invariant documented in the session.py docstring, loguru call normalized to f-string (style only, as the ticket notes).
