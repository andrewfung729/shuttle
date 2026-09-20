# 02 — `ssh_run` approval flow (hybrid wait, atomic claim, token removal)

Status: resolved
Blocked by: 01

## Context

Rewires the confirm path in `_execute_command_logic` (`src/shuttle/mcp/tools.py`) from AI-relayed confirm tokens to the panel approval queue. This is the breaking API change recorded in ADR-0001.

## Tasks

- [ ] **Pre-implementation measurement**: record real MCP tool-call request timeouts for Claude Code and Cursor against a slow `ssh_run` (e.g. sleep-injected), and whether each client attaches a `progressToken`; paste results into this ticket. Only the server default may ever be raised above 20 s, and only on this evidence.
- [ ] `ssh_run` signature: remove `confirm_token`; add `approval_id: str | None`, `approval_wait: float | None = None`. Clamp per-call `approval_wait` to `[0, 300]`; `None` → `settings.approval_wait` (default 20.0).
- [ ] Persist `bypass_scope` from the requesting call onto the created approval row (drives the panel notice).
- [ ] CONFIRM branch rewrite:
  - No `approval_id` → create `pending_approvals` row (TTL `settings.approval_ttl`), enter wait loop.
  - `approval_id` given → load row; validate byte-exact `command` + `node_id` match; branch on status (`rejected` / `expired` / `executed` / `approved` / `pending`) per spec §Execution flow.
  - Wait loop: poll every 2 s up to `min(approval_wait, time-to-expiry)`; when the caller's ctx carries a `progressToken`, each tick also `ctx.report_progress(...)` and the deadline extends automatically to `time-to-expiry` (client timeout resets on every heartbeat — the human gets full TTL thinking time); approved → claim → execute; rejected → return immediately (incl. `reject_reason`); expiry → mark expired + return; timeout → pending message containing `approval_id` and the exact re-call recipe.
- [ ] Atomic claim before execution via `ApprovalRepo.claim`; loser of the race reports "already used".
- [ ] `bypass_scope="session"`: on successful claim, add the matched rule pattern to `session_obj.bypass_patterns` (unchanged semantics, new anchor point).
- [ ] Remove `ConfirmTokenStore` usage from `tools.py` and `server.py` wiring; delete the class from `core/security.py` and its tests.
- [ ] Block-level behavior untouched: rejected before any approval logic.

## Acceptance criteria

- Tests (`tests/test_mcp/`), asyncio auto mode, `-W error` clean:
  - confirm match creates a pending approval (with `bypass_scope` persisted) and (with `approval_wait=0`) returns the pending message including `approval_id`, unquoted command line, and the byte-for-byte re-call instruction
  - pre-approved row → claim → command executes exactly once
  - rejected call returns the rejection message including `reject_reason` (or the "no reason given" fallback); expired / replayed / wrong-command / wrong-node calls each return distinct clear errors and never execute
  - hybrid wait: decision injected mid-wait → executes without a second call; no decision → timeout message
  - progress path: fake ctx with a `progressToken` receives one heartbeat per poll tick and the wait passes the 20 s floor; ctx without a token returns at the floor
  - `bypass_scope="session"` adds the pattern only after a successful claim
  - BLOCK rejects even with a valid approved `approval_id`

## Notes

- Keep the pending message format exactly as spec'd (it's the AI's only instruction manual).
- `ssh_upload` / `ssh_download` do not go through the guard today — out of scope here, but note the asymmetry in the PR description.

## Comments

Implemented. Flow per spec: create-or-recheck, byte-exact (command, node_id) binding, branch on status, hybrid wait (2 s poll; progressToken → deadline extends to TTL, `approval_wait=0` returns immediately even with a progressToken — the explicit "return immediately" contract wins), atomic claim before execution, loser reports "already used", bypass_scope persisted on the row and applied to the session at claim time. ConfirmTokenStore deleted from core + wiring. Note: FastMCP's in-memory test client attaches a progressToken to every call_tool — this surfaced the wait=0 edge, now covered by tests.

**Still open (manual):** the pre-implementation client-timeout measurements for Claude Code / Cursor (real MCP tool-call request timeouts + whether they attach a progressToken) were not captured in this environment. Nothing may be raised above the 20 s floor without that evidence — the implementation keeps the floor as spec'd.
