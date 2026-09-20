# 01 — `pending_approvals` model + ApprovalRepo

Status: resolved
Blocked by: —

## Context

Foundation ticket for the approval queue (see `docs/features/approval-queue/spec.md`). Adds the durable, multi-process-safe store that replaces `ConfirmTokenStore`.

## Tasks

- [ ] `PendingApproval` model in `src/shuttle/db/models.py` per the spec's table (status values: `pending / approved / rejected / expired / executed`; `rule_id` plain string without FK; `decided_by` reserved, always NULL today; `bypass_scope` String(20) nullable; `reject_reason` Text nullable).
- [ ] `ApprovalRepo` in `src/shuttle/db/repository.py`:
  - `create(node_id, session_id, command, rule_id, rule_description, bypass_scope, expires_at) -> PendingApproval`
  - `get(approval_id)`
  - `list(status: str | None, limit)` — resolves nothing itself; node names handled at the route layer like `logs.py`
  - `decide(approval_id, decision: "approved" | "rejected", reason: str | None = None) -> bool` — conditional update `WHERE status='pending' AND expires_at > now`, stores `reject_reason` on reject, returns rowcount == 1
  - `claim(approval_id) -> bool` — conditional update `pending→executed`? **No**: claim is `approved→executed` (`SET status='executed', executed_at=now WHERE id=:id AND status='approved' AND expires_at > :now`), returns rowcount == 1. The `expires_at` predicate belongs in the SQL — not just in the caller's pre-claim check — so the read→claim TOCTOU window cannot exist.
  - `sweep_expired() -> int` — `pending` rows past `expires_at` → `expired`
  - `set_exec_result(approval_id, exit_code)` — back-fill `exec_exit_code`
- [ ] Add `ix_pending_approvals_status (status, expires_at)` to the idempotent index list in `src/shuttle/db/engine.py::init_db` (new table itself comes free via `create_all`).

## Acceptance criteria

- Repo unit tests (`tests/test_db/`): pending defaults on create; `decide` happy path; `decide` on already-decided or expired row returns False; `decide("rejected", reason=...)` stores the reason; `claim` race — two sequential claims, second returns False; `sweep_expired` flips only stale pending rows; approved-but-unconsumed row past TTL refuses to claim **and the refusal comes from the SQL predicate** (assert by setting `expires_at` in the past directly on an approved row).

## Notes

- Use `datetime.now(UTC)` consistent with existing models.
- Follow existing repo style in `repository.py` (async, SQLAlchemy 2.0 select/update).

## Comments

Implemented in commit `feat(mcp): replace confirm tokens...` (branch af/20260826). All acceptance tests in `tests/test_db/test_repository_approvals.py`: pending defaults, decide happy/409/expired/unknown, reject stores reason, claim race (second loses), claim refuses expired approved row via SQL predicate, sweep flips only stale pending, set_exec_result, list filter. Implementation note: conditional UPDATEs use `synchronize_session=False` and `get()` uses `populate_existing` so re-reads never see stale identity-map rows.
