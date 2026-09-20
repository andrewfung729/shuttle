# 04 — Approvals web API

Status: resolved
Blocked by: 01

## Context

The human half of the approval flow: REST endpoints under the existing Bearer-token guard (`src/shuttle/web/`). The panel UI (ticket 05) consumes these.

## Tasks

- [ ] `src/shuttle/web/routes/approvals.py`:
  - `GET /api/approvals?status=pending&limit=50` — sweep expired pending rows first (`ApprovalRepo.sweep_expired`), then list; resolve node names via the shared batch helper
  - `GET /api/approvals/{id}` — detail incl. rule description snapshot, `bypass_scope`, `reject_reason`
  - `POST /api/approvals/{id}/approve` — `ApprovalRepo.decide(..., "approved")`; 409 when not claimable (already decided / expired), 404 when unknown id
  - `POST /api/approvals/{id}/reject` — accepts optional JSON body `{"reason": str}` (400/422 over 2000 chars); `ApprovalRepo.decide(..., "rejected", reason=...)`; same 404/409 contract
  - **404 vs 409**: a bare conditional UPDATE cannot tell "unknown id" from "not pending anymore" — `get()` first (404 if None), then `decide()` (409 if False)
- [ ] Extract `_batch_node_names` into a shared routes helper (e.g. `src/shuttle/web/routes/_helpers.py`) — it currently lives as a private duplicate in BOTH `logs.py` and `sessions.py`; import it from there in all three routers instead of pasting a third copy.
- [ ] Response schemas in `src/shuttle/web/schemas.py` (mirror the model columns the panel needs: id, command, node name, rule description, bypass_scope, reject_reason, status, requested_at, expires_at, decided_at, exec_exit_code).
- [ ] Register the router in `web/app.py`.

## Acceptance criteria

- Tests (`tests/test_web/`): list returns pending rows sorted by `requested_at`; sweep flips stale rows before listing; approve/reject happy paths set `decided_at`; reject stores `reject_reason` (and rejection without a body still works); reason over 2000 chars → 400/422; double-decide → 409; decide on expired → 409; 404 for unknown id (distinct from 409); all endpoints 401 when `api_token` configured and no/incorrect Bearer passed (follow existing route test setup).

## Notes

- No background sweeper task in v1 — read-time sweep only (spec §Web API).
- `decided_by` stays NULL; per-user identity is a tracked follow-up, not this ticket.

## Comments

Implemented in `web/routes/approvals.py`. List sweeps first then resolves node names via the new shared `routes/_helpers.py::batch_node_names` (logs.py/sessions.py now import it — no third copy). 404 vs 409 via get-then-decide. Reject body optional, reason ≤2000 (422 via pydantic + explicit 400). Tests cover all acceptance criteria incl. 401 when api_token is set.
