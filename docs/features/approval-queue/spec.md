# Approval Queue — panel-enforced command approval

Status: implemented (backend + web + docs); ticket 07 manual e2e items pending

## Problem

The current confirm flow (`ConfirmTokenStore`, `src/shuttle/core/security.py`) has three structural flaws:

1. **AI self-approval.** The confirm token is returned *to the AI*, which can re-submit it immediately. Nothing technical requires a human to have seen the command.
1. **Single-process state.** Tokens live in an in-memory dict: lost on restart, broken under multiple server processes.
1. **Thin audit.** A consumed token leaves no durable record of who decided what, when.

## Goals

- The approval decision is made **outside the AI's control** — in the web panel, by a human.
- Approvals are **durable and multi-process safe** (DB-backed).
- Every decision (approve/reject/expiry) is **auditable** with timestamps.
- AI-side UX stays simple: one tool (`ssh_run`), hybrid wait, poll via `approval_id`.
- Fix the audit gaps found in the current implementation along the way.

## Non-goals (follow-ups, not this effort)

- Notification channels (Slack / email / ntfy) for pending approvals.
- CLI approval commands (`shuttle approvals approve <id>`).
- Multi-user panel auth with per-user `decided_by` identity.
- Approval of `warn`-level commands (warn executes; only confirm-level enters the queue).

## Design

### Data model: `pending_approvals`

New table (created by `Base.metadata.create_all` — no hand migration needed for a new table):

| Column             | Type                                    | Notes                                                                                                                                          |
| ------------------ | --------------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| `id`               | String(36) PK                           | uuid4                                                                                                                                          |
| `node_id`          | String(36), FK nodes.id, NOT NULL       | target node                                                                                                                                    |
| `session_id`       | String(36), nullable                    | informational; session may close before decision                                                                                               |
| `command`          | Text, NOT NULL                          | exact command string, binding for execution                                                                                                    |
| `rule_id`          | String(36), nullable                    | plain string, no FK (matches `CommandLog.security_rule_id` pattern; rules may be deleted later)                                                |
| `rule_description` | Text, nullable                          | snapshot at request time, shown in panel                                                                                                       |
| `bypass_scope`     | String(20), nullable                    | records that the requesting call passed `bypass_scope="session"`; drives the panel notice and persists independently of when the claim happens |
| `status`           | String(20), NOT NULL, default `pending` | `pending / approved / rejected / expired / executed`                                                                                           |
| `requested_at`     | DateTime(tz), NOT NULL                  |                                                                                                                                                |
| `expires_at`       | DateTime(tz), NOT NULL                  | `requested_at + approval_ttl`                                                                                                                  |
| `decided_at`       | DateTime(tz), nullable                  | set on approve/reject                                                                                                                          |
| `decided_by`       | String(100), nullable                   | reserved for future panel identity; always NULL today                                                                                          |
| `reject_reason`    | Text, nullable                          | operator-supplied reason surfaced to the AI on rejection (capped at 2000 chars server-side); lets the agent understand why and how to revise   |
| `executed_at`      | DateTime(tz), nullable                  | set when the approval is claimed for execution                                                                                                 |
| `exec_exit_code`   | Integer, nullable                       | filled after execution, links to CommandLog                                                                                                    |

Indexes: `ix_pending_approvals_status (status, expires_at)` — added to the idempotent index list in `init_db`.

State machine:

```
pending ──approve──► approved ──claim (atomic)──► executed
   │
   ├──reject───► rejected                (claim = status flip + executed_at,
   │                                       done BEFORE the command runs)
   └──expire───► expired

expiry: any row still `pending` past `expires_at` → `expired` (swept on read)
note: an `approved` row past `expires_at` also refuses to be claimed
```

### `ssh_run` API (breaking change)

```python
ssh_run(
    command: str,
    node: str | None = None,
    timeout: float = 30.0,
    approval_id: str | None = None,   # replaces confirm_token
    approval_wait: float | None = None,  # seconds to wait for a decision;
                                        # None → server default (20.0)
                                        # 0 → return immediately
    bypass_scope: str | None = None,  # unchanged: "session" adds the matched
                                      # rule pattern to the session bypass set
)
```

`confirm_token` is **removed**. The level name `confirm` in security rules is unchanged — it now means "requires an Approval".

Waiting semantics: the wait deadline is `min(approval_wait, time-to-expiry)`, where the 20 s default is only the **floor for clients without MCP progress support**. When the client's request carries a `progressToken`, each 2 s poll tick also emits `notifications/progress` — the client resets its request timeout, and the wait extends automatically up to the remaining approval TTL. The human gets the full 15 minutes to actually think; the agent experiences one long tool call. Clients that don't send a `progressToken` return after the 20 s floor and re-poll via `approval_id` — same row, both paths.

### Execution flow (hybrid wait)

```
ssh_run(command, ...)
  1. resolve node + auto-session            (unchanged)
  2. CommandGuard.evaluate (session bypass)  (unchanged)
  3. BLOCK  → ⛔ reject                      (unchanged, never bypassable)
  4. CONFIRM
       a. approval_id given?
            • load row; mismatches of command/node → error
            • rejected            → report rejection incl. `reject_reason`, stop
            • expired / past TTL  → report expiry, suggest resubmit
            • executed            → report "already used", stop (replay guard)
            • approved            → atomic claim (see below) → execute
            • pending             → fall through to wait loop
       b. no approval_id → INSERT row (pending, expires_at = now + ttl)
       c. wait loop: poll every 2 s up to min(approval_wait, time-to-expiry);
            if ctx has a progressToken, each tick emits notifications/progress
            and the deadline extends automatically to time-to-expiry
            • approved → atomic claim → execute
            • rejected → return immediately
            • expiry passes → mark expired, return
            • wait elapsed → return pending message with approval_id
  5. WARN → log and continue                 (unchanged)
  6. execute via session                     (unchanged)
  7. write CommandLog (with audit fixes) + stamp approval.exec_exit_code
```

Pending message returned to the AI (must be self-explanatory). The command is shown on its own unquoted line and the recipe does **not** embed the command in quotes — the old flow had a latent bug where a command containing double quotes produced a broken re-call snippet. The AI is expected to re-send the command byte-for-byte:

```
⏳ Approval required (id: <approval_id>)
Command: <command>
Node: <node>  Rule: <description>
A human must approve this in the Shuttle web panel (Approvals page).
To check the decision, re-call ssh_run with the SAME command byte-for-byte
(do not reformat or re-quote) plus: approval_id="<approval_id>"
```

Rejection message (includes the operator's reason so the agent can revise):

```
❌ Approval rejected (id: <approval_id>)
Command: <command>
Node: <node>  Rule: <description>
Reason: <reject_reason, or "no reason given">
Ask the operator for clarification, or revise the command and resubmit —
a resubmission always creates a NEW approval_id.
```

### Atomic claim & replay prevention

Claiming an approved approval flips it to `executed` **before** execution, guarded by a conditional update:

```sql
UPDATE pending_approvals
SET status='executed', executed_at=:now
WHERE id=:id AND status='approved' AND expires_at > :now  -- rowcount 1 = we own it; expires_at here, not pre-check: kills read→claim TOCTOU
```

- Two concurrent `ssh_run` calls with the same `approval_id`: exactly one wins the claim; the loser re-reads status and reports "already used".
- If the execution itself fails, the approval stays `executed` (with `exec_exit_code` recorded): one decision = one execution *attempt*.
- SQLite WAL + single-writer makes the claim race-free without extra locking.

### Panel claim (`bypass_scope="session"`)

When the claiming call passes `bypass_scope="session"`, the matched rule pattern is added to the session's bypass set at claim time (same semantics as today's token flow, re-anchored to approvals). The `bypass_scope` seen by the *initial* call is persisted in the `pending_approvals.bypass_scope` column, so the panel approval dialog can show the notice regardless of when and by whom the claim is later made.

### Web API

All under the existing Bearer-token guard (`verify_token`):

| Method | Path                            | Behavior                                                                                                                                       |
| ------ | ------------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------- |
| GET    | `/api/approvals?status=pending` | list; resolves node names; sweeps expired pending rows first                                                                                   |
| GET    | `/api/approvals/{id}`           | detail (incl. `bypass_scope`, `reject_reason`)                                                                                                 |
| POST   | `/api/approvals/{id}/approve`   | conditional update `pending→approved` (+`decided_at`); 409 if not claimable (already decided / expired)                                        |
| POST   | `/api/approvals/{id}/reject`    | body `{reason?: string}` (optional, ≤ 2000 chars server-enforced); conditional update `pending→rejected` storing `reject_reason`; 409 likewise |

Notes:

- 404 vs 409 needs a read before the conditional update: unknown id → 404, known-but-not-pending → 409. A pure conditional UPDATE cannot distinguish the two.
- `_batch_node_names` currently exists as a private copy in **both** `logs.py` and `sessions.py` — this effort extracts it into a shared routes helper instead of pasting a third copy.

No background sweeper task in v1 — expiry is computed on read (list endpoint + guard flow). A periodic sweep can be added later if the table grows.

### Panel UI

New **Approvals** page (`web/src/pages/`):

- Pending queue: command (monospace), node, matched rule, requested-at, live countdown to expiry, **Approve / Reject** buttons with a confirm dialog that displays the full command.
- The reject dialog carries a **reason textarea** (optional but encouraged — placeholder explains it will be shown to the AI verbatim). Approving requires no reason.
- History tab: recent decided/expired/executed rows with decided-at, exit code, and the reject reason where present.
- TanStack Query with `refetchInterval` (~3 s) on the pending list.
- Notice inside the dialog when `bypass_scope="session"` is set on the row.

### Config (`ShuttleConfig`)

| Field           | Default                   | Meaning                                                                                                                          |
| --------------- | ------------------------- | -------------------------------------------------------------------------------------------------------------------------------- |
| `approval_ttl`  | `900`                     | seconds a pending approval stays decidable                                                                                       |
| `approval_wait` | `20.0`                    | server-default synchronous wait — the floor for progress-less clients; progress-capable clients auto-extend to the remaining TTL |
| (constant)      | `2.0`                     | poll interval inside the wait loop                                                                                               |
| (validation)    | `0 ≤ approval_wait ≤ 300` | per-call values clamped to this range                                                                                            |

## Audit fixes (in scope, this effort)

1. **stderr persisted** — `CommandLog.stderr` is currently hardcoded `None`; store truncated stderr (same 64 KB cap as stdout).
1. **`bypassed` accuracy** — currently `bypassed=confirm_token is not None`, which flags any call that carried a token (even allow-level). New rule: `bypassed=True` iff the command matched a confirm/warn rule *and* was permitted via an approval claim or a session bypass pattern.
1. **`CommandLog.approval_id`** — new nullable column (plain string, no FK) for traceability from log row to approval decision.
1. **Remove dead logging placeholders** — `SessionManager._persist_session`, `_persist_session_close`, `_persist_command_log` are empty stubs. Delete them and the unused `db_session_factory` plumbing; document the invariant that `_execute_command_logic` is the single audit point for command execution.
1. **Normalize the loguru call** — `logger.warning("Failed to persist command log for {cmd}", cmd=...)` → f-string, for consistency (kwargs form is valid loguru — cf. this file's WARN call); not a bug fix.

## Security analysis

- **Self-approval eliminated**: the AI never receives a capability-bearing secret; it can only observe state and re-poll.
- **Binding**: an approval authorizes exactly `(command, node_id)`; the claiming call must match both, byte-exact.
- **Replay**: single-use via atomic claim; `executed` rows refuse re-claim.
- **Block rules** remain unreachable by approvals (guard rejects before any approval logic).
- **Panel auth dependency**: approvals API sits behind the existing optional Bearer guard. If `api_token` is unset, anyone with network access to the panel can approve. Documentation must call this out; real panel auth is a tracked follow-up, not in scope.
- **TTL**: `expires_at` gates both deciding (panel) and claiming (executor); an approved-but-unconsumed approval dies with the same TTL.

## Compatibility & migration

- New table via `create_all` — no hand-written migration. The `approval_id` column on `command_logs` and the status index go through the existing idempotent column-add / `CREATE INDEX IF NOT EXISTS` paths in `init_db`.
- Breaking MCP change (`confirm_token` removed). Document in `docs/` tool references; version bump handled by the release process, not this effort.
- Upstream-first: feature PRs target `enwaiax/shuttle` (per AGENTS.md).

## Test plan

- **DB/repo**: create → pending defaults; conditional approve/reject (happy + 409 paths); reject stores `reject_reason`; claim race (two claims, one wins); claim refuses expired approved rows via the SQL predicate itself; expiry sweep.
- **MCP flow**: confirm match creates approval; hybrid wait times out → pending message; approve → claim → executes; reject → error includes `reject_reason` (or the "no reason given" fallback); expired → clear error; wrong command / wrong node with `approval_id` → error; replay → "already used"; `bypass_scope="session"` persisted on the row and adds bypass at claim; block rules unaffected by any approval state.
- **Web API**: list + sweep, approve/reject, reject with/without reason, reason > 2000 chars rejected (422/400), 404 vs 409 distinction, auth enforced when `api_token` set.
- **Audit**: stderr persisted and truncated; `bypassed` true only on real bypass paths; `approval_id` stamped on CommandLog and `exec_exit_code` back-filled.

## Tickets

| #   | Ticket                                                     | Blocked by |
| --- | ---------------------------------------------------------- | ---------- |
| 01  | `pending_approvals` model + ApprovalRepo                   | —          |
| 02  | `ssh_run` approval flow (hybrid wait, claim, remove token) | 01         |
| 03  | Audit fixes (stderr, bypassed, approval_id, stub removal)  | 02         |
| 04  | Approvals web API                                          | 01         |
| 05  | Approvals panel UI                                         | 04         |
| 06  | Docs + prompts update                                      | 02, 04     |
| 07  | End-to-end verification                                    | 02–06      |

## Open questions

1. Should the panel show a browser notification / sound on new pending approvals? (cheap UX win, defer to implementation)
1. Default `approval_ttl` 15 min — long enough for a human to notice without notifications? Revisit after first real use.
