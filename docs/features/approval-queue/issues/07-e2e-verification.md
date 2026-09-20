# 07 — End-to-end verification

Status: in-progress
Blocked by: 02, 03, 04, 05, 06

## Context

Final gate before the feature PR. Proves the loop end-to-end on a real server process, not just in pytest.

## Tasks

- [x] Full-loop manual pass against `uv run shuttle serve` + a sandbox SSH node (driven over real MCP JSON-RPC + panel API, node `viki-code1`, 2026-09-20):
  1. `ssh_run("sudo systemctl restart nginx")` → pending message with id
  1. panel shows it within ~3 s with correct node/rule/countdown
  1. Reject **with a reason** → caller's rejection message contains that reason; reject once more without a reason → fallback wording; resubmit → new approval id
  1. Approve → the polling call executes; CommandLog row has `bypassed=true`, `approval_id`, stderr, exit code; approval row shows `executed` + `exec_exit_code`
  1. Replay same `approval_id` → "already used", no execution
  1. Let one approval expire → expired status, caller error message
  1. `bypass_scope="session"` → second same-pattern command runs without a new approval
  1. BLOCK rule (`rm -rf /`) → rejected even with an approved approval in hand
- [ ] Restart-survival check: create pending approval → restart `shuttle serve` → approve in panel → claim + execute works (the old in-memory token flow failed exactly here).
- [ ] Client-timeout spot check with the ticket 02 measurements: progress-less clients return before their request timeout fires; progress-capable clients ride past the 20 s floor on heartbeats and only resolve on decision/expiry.
- [ ] Multi-process sanity (optional but cheap): two workers, approval created under one, approved+claimed under the other.
- [ ] Gates: `uv run ruff check src/ tests/`, `uv run ruff format`, `uv run pytest`, `cd web && npx tsc --noEmit`, `uv run pre-commit run --all-files`.
- [ ] Draft the upstream PR description (target `enwaiax/shuttle` per AGENTS.md): motivation = AI self-approval hole, breaking-change callout, migration notes, link ADR-0001 + spec.

## Acceptance criteria

- All eight loop steps observed working; all gates green; PR text ready for review.

## Comments

Gates all green: ruff check + format, pytest (full suite), `tsc --noEmit`, `vite build`, pre-commit --all-files. Restart/multi-process survival verified with a two-process script against a shared sqlite file: process A creates the pending approval and exits; process B (fresh engine) lists it, approves, claims, records exit code, and a second claim is refused — exactly the failure mode of the old in-memory token flow. FastMCP in-memory client e2e covers confirm→pending→approve→re-call→execute→executed-row.

**Remaining manual items:** the eight-step loop against a real sandbox SSH node, client-timeout spot checks with real Claude Code/Cursor (see ticket 02), and drafting the upstream PR description.

**2026-09-20 real-server loop pass (JSON-RPC client + panel API, node `viki-code1`):** all eight steps observed. One spec deviation found and fixed: the session-bypass unlock at claim time read the *call's* `bypass_scope` arg instead of the persisted `pending_approvals.bypass_scope` — since the re-call recipe only passes `approval_id`, an obedient agent could never activate the bypass. Fix: claim now honors `bypass_scope or ap.bypass_scope` (tools.py) + `test_approval_claim_unlocks_bypass_from_persisted_scope`. Minor gap noted, not fixed: `/api/logs` response schema omits `approval_id` (column is stamped in DB, just not exposed to the panel). Steps verified: pending message/id; list + countdown; reject±reason surfaced verbatim; approve→execute (`stderr="boom\n"`, `bypassed=true`, `exec_exit_code` back-filled); replay refused; expiry swept + clear caller error; session bypass now unlocks on bare claim; `rm -rf /` blocked with an approval_id in hand.
