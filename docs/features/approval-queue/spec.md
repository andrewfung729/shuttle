# LLM gate replaces human Approval Queue

Status: implemented

Supersedes the implemented panel Approval Queue (ADR-0001 human-approve path). The old `issues/01`–`07` tickets documenting that system are deleted, not archived — git history is the archaeology.

## Problem Statement

Confirm-level commands still require a human in the web panel for every match. Coarse Security Rules (for example `sudo .*`) flood the queue with routine work, slow agents down, and fail when no operator is watching. At the same time, the agent that submitted the command may be compromised or prompt-injected: any protocol that returns an `approval_id`, retry recipe, or rich denial reason is an information channel the attacker can use. The current four-level model (`block` / `confirm` / `warn` / `allow`) plus session Bypass Patterns plus the Approval claim loop is more machinery than the threat model needs.

## Solution

Replace human-in-the-loop Approvals with a short gate:

1. Security Rules only use three Security Levels: `block`, `review`, `allow`.
1. `block` denies immediately. `allow` runs. `review` is scored by a decision model via OpenRouter's System One API (default model `typesafe/jev-1.13`; any TypeSafe System One–compatible endpoint works): a single `is_safe` boolean question returning a calibrated probability.
1. `p ≥ SAFE_THRESHOLD` → execute. Below threshold → deny that command and log it. Gate errors, timeouts, disabled gate, or missing key → same: deny the command, log the reason. Denial is always command-local — nothing else changes state.
1. The agent receives one fixed error string — `Error: denied by policy` — for every denial path. No scores, rule text, or retry instructions.
1. Delete the Approval Queue protocol end-to-end (`approval_id`, hybrid wait, claim, bypass, warn, Approvals API/UI, `pending_approvals`). No backward compatibility.

Operators configure `openrouter_api_key`, `gate_enabled`, and `gate_safe_instructions`. With gate off or no key, `review` denies the command (so local dev without a key behaves identically, minus gate calls).

There is deliberately **no automatic node freeze** in v1: a compromised agent's review-level commands are each denied and logged; the operator sees the denials and can disable the node or tighten rules manually. Auto-quarantine is a documented v2 candidate.

## User Stories

1. As an operator, I want routine review-level commands auto-allowed when the gate scores them safe, so that I am not paged for every `sudo` match.
1. As an operator, I want clearly unsafe review-level commands denied without my being online at that second, so that a runaway agent cannot execute them.
1. As an operator, I want every denial recorded in the command log with command, Node, matched rule id/description snapshot, gate score (if any), reason (`unsafe` / `error` / `disabled`), and timestamp, so that audits and rule tuning have the data they need.
1. As an operator, I want a denied log row to offer a "create allow rule" shortcut that opens the Rules form pre-filled with the command, so that fixing a false positive is one explicit policy change — never an execute-and-return-output back to the agent.
1. As an operator, I want block-level Security Rules to hard-deny without calling the gate, so that known-destructive patterns never depend on a model or network.
1. As an operator, I want allow-level commands to skip the gate, so that cheap read-only work stays fast and cheap.
1. As an operator, I want existing confirm-level seed rules migrated to review, so that privileged patterns still enter the LLM gate.
1. As an operator, I want warn-level rules removed, so that unused severity does not clutter policy.
1. As an operator, I want session Bypass Patterns removed, so that no trusted-session hole undermines the gate.
1. As an agent (MCP client), I want `ssh_run` to simply run or return a fixed denial, so that I do not implement approval polling.
1. As an agent, when a command is denied by policy, I want the error `Error: denied by policy`, so that I get no actionable detail to attack with.
1. As an agent, I want no `approval_id`, `approval_wait`, `confirm_token`, or `bypass_scope` parameters, so that the tool surface stays small.
1. As an operator, I want `SHUTTLE_OPENROUTER_API_KEY` (or equivalent settings field) to enable gate calls, so that credentials live in config not code.
1. As an operator, I want `SHUTTLE_GATE_ENABLED` to turn the gate on or off, so that I can disable model calls without deleting rules.
1. As an operator, when the gate is disabled or the API key is missing, I want review matches to deny the command, so that developer laptops without OpenRouter access still fail closed.
1. As an operator, I want `SHUTTLE_GATE_SAFE_INSTRUCTIONS` to override the judge instructions text, so that I can tune what "safe" means without a code change.
1. As an operator, I want the safe-score threshold to be a code constant, so that security posture is not an ops freestyle dial.
1. As an operator, I want gate timeouts and transport errors to deny the command under enforce, so that fail-open is impossible when the gate is on.
1. As an operator, I want CommandLog rows for denied and executed commands to remain the system of record, so that no parallel audit store is needed.
1. As an operator, I want the Security Rules UI to offer only block/review/allow, so that policy language matches the new model.
1. As a deployer, I want a breaking release with no compatibility shims for old approval rows, MCP params, or `confirm`/`warn` level strings in code paths, so that the old protocol cannot linger.
1. As a deployer, I want seed data and docs updated in the same change, so that a fresh install only knows block/review/allow.
1. As a security reviewer, I want the judge model to see only command text plus Node name in state (no session history, secrets, or full rule corpus), so that the model input stays minimal.
1. As a security reviewer, I want the agent to never observe gate probabilities, so that scores cannot be used as a search signal.
1. As a developer, I want the gate client injected behind a narrow port, so that tests never call the real endpoint.
1. As a developer, I want unit/integration tests at the `ssh_run` orchestration seam covering the block/review/allow/deny matrix, so that regressions in the gate are caught without UI tests.
1. As an agent author reading prompts/docs, I want MCP prompts and tool descriptions to stop teaching approval polling, so that agents do not look for a dead protocol.
1. As a maintainer, I want CONTEXT.md and security docs to replace Approval / Bypass vocabulary with review level and LLM Gate, so that agents working in-repo use the new language.

## Implementation Decisions

### Domain model (glossary impact)

- **Security Level** values become: `block`, `review`, `allow` only. Remove `confirm` and `warn` from the enum, seeds, API validation, and UI.
- **Approval** and **Approval Queue** are removed as live domain concepts. Historical ADR-0001 remains as history; this feature supersedes its runtime behavior. A follow-up ADR should record the replacement (not blocking for implementation).
- **Bypass Pattern** is removed.
- **LLM Gate**: the review-level branch that calls the gate and maps the calibrated score to execute or deny.
- There is no Hold Event or Node Quarantine concept in v1 — gate denials are ordinary command-log rows.

### Command path

Single orchestration path (existing `ssh_run` / execute-command logic):

```
decision = CommandGuard.evaluate(command, node)  # no bypass_patterns
if decision.block → log denial; return "Error: denied by policy"
if decision.allow → execute (log)
if decision.review:
  if not gate_enabled or no api key:
    log denial (reason=disabled); return "Error: denied by policy"
  try:
    score = GatePort.is_safe(state=command+node_name, instructions=config)
  except gate error / timeout:
    log denial (reason=error); return "Error: denied by policy"
  if score >= SAFE_THRESHOLD:
    execute (log)
  else:
    log denial (score, reason=unsafe); return "Error: denied by policy"
```

One agent-visible string only: `Error: denied by policy`. Retrying a denied command is harmless — every attempt re-runs the same path, and an operator-side rule change makes a later retry pass.

### Gate port

- One method: given state + instructions → probability in `[0,1]` or error.

- Implementation: `typesafe-sdk` (`uv add typesafe-sdk` — new dependency, replaces hand-rolled HTTP and parsing). Use `AsyncTypeSafeClient`, constructed once at startup and closed on shutdown. Point it at OpenRouter via `base_url` — the SDK appends `/v1/systemone`; OpenRouter proxies TypeSafe's Jev. TypeSafe direct also works (default base URL, model `jev-1.13.0`).

  ```python
  client = AsyncTypeSafeClient(
      api_key=config.openrouter_api_key,
      base_url=config.gate_base_url,   # https://openrouter.ai/api
      model=config.gate_model,
      timeout=GATE_TIMEOUT,
      retry=RetryPolicy(max_retries=0),  # fail fast on the command hot path
  )
  result = await client.system_one(
      # attacker-controlled text goes in state, never in instructions
      state={"command": command, "node": node_name},
      questions={"is_safe": Noul(instructions=config.gate_safe_instructions)},
  )
  score = result.nouls["is_safe"].noul  # calibrated P(safe) in [0,1]
  ```

- Pass `api_key`/`base_url` from `ShuttleConfig` explicitly; the SDK also reads `TYPESAFE_API_KEY`/`TYPESAFE_BASE_URL` env vars, but Shuttle config stays the single source under the `SHUTTLE_` prefix.

- `gate_model` is config (code default: `typesafe/jev-1.13` — pin the versioned id, not the `~typesafe/jev-latest` alias, so a security gate does not silently move to a new release). Jev is a decision-only model (no text generation) returning calibrated probabilities (RLCD training), so `SAFE_THRESHOLD` is a calibrated bound, not a heuristic over self-reported text.

- **Injection caveat**: the command string is attacker-controlled input to the judge. Keep it inside `state`; the verdict criteria live in `instructions`. Jev cannot emit off-schema output or prose — there is no text channel to hijack — but an attacker can still craft commands that merely look safe; the calibrated probability is the only signal. Document this.

- Any SDK exception (`TypeSafeError` subclasses: transport, timeout, non-2xx), or malformed/missing answer → treat as not safe.

- `SAFE_THRESHOLD` and `GATE_TIMEOUT` are code constants (timeout on the order of ~2s — this sits on the command hot path; Jev's own latency is ~70–500ms). `SAFE_THRESHOLD` should be high (~0.9): measured scores are polarized (benign reads ≈0.99, destructive ≈0.01) but context-dependent commands like `usermod -aG sudo` land at 0.5–0.7 under permissive instructions — a 0.5 threshold would let privilege escalation through. With no quarantine, a false-positive deny is cheap (one refused command, logged), so erring high is fine. See `examples/try_jev_gate.py` for the measurement.

- No streaming, no multi-call rubric in v1, no session history in state.

### Config (`ShuttleConfig`)

- Add: `openrouter_api_key` (secret string, optional), `gate_enabled` (bool, default false), `gate_safe_instructions` (string, non-empty default in code — becomes the `is_safe` question's `instructions`), `gate_model` (string, code default `typesafe/jev-1.13`), `gate_base_url` (string, default `https://openrouter.ai/api`).
- Remove: `approval_ttl`, `approval_wait`.
- Env prefix remains `SHUTTLE_`.

### Schema

- **CommandLog**: add `gate_score` (float, nullable) and `gate_reason` (string, nullable: `unsafe`|`error`|`disabled`); denied commands are logged, not only executed ones. Remove `approval_id` and `bypassed` — do not keep dead columns "for compatibility."
- **Delete** `pending_approvals` model, repo, routes, schemas, UI, and tests. No migration of old rows; drop table.
- SecurityRule.level check/validation: only `block`|`review`|`allow`.
- Seeds: former confirm patterns → `review`; warn seeds deleted; block seeds unchanged.
- No runtime mapping of legacy `confirm`/`warn` strings — data must be updated as part of the change (seed rewrite + document that existing DBs need level updates or re-seed). Prefer startup: reject/disable unknown levels rather than silent reinterpretation.

### MCP / tools

- `ssh_run`: drop `approval_id`, `approval_wait`, `bypass_scope` (and any residual confirm token).
- Pending/rejection/approval helper messages deleted.
- Prompts and tool descriptions updated; no teaching of panel approval.

### Web

- Approvals API and panel page are deleted outright; no replacement surface is needed — gate denials are rows in the existing command-log view (show `gate_score`/`gate_reason` there).
- Optional: a denied log row links to the Rules form pre-filled with the command, so a false positive becomes an explicit allow rule authored by a human.
- Rules UI: level dropdown only block/review/allow.

### CommandGuard

- Remove `bypass_patterns` parameter and bypass skip logic.
- Recognize only block/review/allow; unknown level in DB → skip invalid rule with log (consistent with invalid regex skip today).

### Docs

- Update security-rules docs, MCP setup, web panel docs, CONTEXT.md glossary (remove Approval Queue / Bypass; add review level and LLM Gate).

### Testing seams (agreed shape)

Primary seam: **command orchestration** (`ssh_run` / execute-command logic) with injected Gate port and DB.

Secondary: CommandGuard unit tests; CommandLog gate-metadata repo tests.

Do not test OpenRouter network or UI pixels.

## Testing Decisions

- Test **external behavior**: given command + rules + Gate port stub → executed result or exact error string, and the resulting CommandLog row.
- Good tests do not assert internal helper names, SQL text, or HTTP payload cosmetics beyond the Gate port contract.
- Cover at least:
  - block → denied by policy, no gate call
  - allow → executes
  - review + score ≥ threshold → executes
  - review + score < threshold → denied by policy, log row with score + `unsafe`
  - review + gate error/timeout → denied by policy, log row `error`
  - review + gate_enabled false / no key → denied by policy, log row `disabled`
  - MCP tool signature rejects/removes old params (or simply does not accept them)
  - Guard: review level matches; bypass parameter gone; warn/confirm not valid
- Prior art: `tests/test_mcp/test_tools.py`, `test_execute_logic_more.py`, `tests/test_core/test_security.py`, `tests/test_web/test_approvals_api.py`, `tests/test_db/test_repository_approvals.py` — rewrite or replace these; do not keep approval claim tests alive.

## Out of Scope

- **Node quarantine / auto-freeze on unsafe verdicts** — the v2 candidate. Denials are already logged; an operator watching the log can disable the node or tighten rules. If v2 lands, `gate_reason` + score history is exactly the data a freeze policy would need.
- Notification channels for gate denials.
- Server-side execute-after-human-approve and return stdout to the agent. "Approving" a denied command means changing policy so a later agent retry passes — shuttle never pushes work back to the agent over MCP.
- Panel action to add a block Security Rule from a log row (the allow-direction shortcut only pre-fills the Rules form — a human still authors the rule).
- Multi-question judge rubrics, session-history state, per-node thresholds.
- `shadow` / three-mode rollout flags (only `gate_enabled` bool).
- Multi-user panel identity (`decided_by`).
- Automatic re-seed of existing production DBs beyond what `init_db` already does for empty rule tables; operators with live DBs must update levels (document the break).
- Replacing block regex rules with a model.
- New ADR file can land in the same PR or follow immediately; not required before code passes tests.

## Further Notes

- This is intentionally a **breaking** MCP and schema change. Ship as such; no dual-stack.
- Threat model: the MCP agent is untrusted after submission; the panel operator is trusted; the gate model is trusted-but-fail-closed when enabled. v1 contains the agent per-command (every review-level attempt denied + logged); automatic containment of a compromised agent's *other* commands is the deferred quarantine work.
- Old tickets `issues/01`–`07` are deleted with this change; the new `issues/01`–`03` decompose the replacement work. Git history preserves the Approval Queue design if needed.
- Feature slug kept as `approval-queue` so history and links remain; title and status reflect the replacement.
