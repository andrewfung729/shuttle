# ADR-0002: LLM gate replaces the panel Approval Queue

- **Status**: Accepted
- **Date**: 2026-03-24
- **Supersedes**: [ADR-0001](0001-panel-approval-queue-for-confirm-commands.md) (runtime behavior; ADR-0001 remains as history)

## Context

ADR-0001 routed CONFIRM-level commands through a human Approval Queue in the web panel. In practice, coarse rules like `sudo .*` flooded the queue with routine work, slowed agents down, and failed whenever no operator was watching. At the same time, the protocol itself was an attack surface: `approval_id`s, retry recipes, and rich rejection reasons are information channels a prompt-injected agent can exploit. Four security levels, session Bypass Patterns, a durable claim loop, and a pending-approvals table added up to more machinery than the threat model needed.

## Decision

Replace the human-in-the-loop path with a short, fail-closed LLM gate:

1. Rule levels are `block` and `allow` only. `confirm`, `warn`, and `review` (as a rule level) are removed from API validation and UI. Legacy DB rows with those levels are skipped at evaluation, never reinterpreted. The unmatched disposition is `gate` (logged on CommandLog, not authored as a rule).
1. `block` denies immediately without any model or network dependency. `allow` runs only when an explicit allow rule matches. Unmatched commands are scored by a decision model (default `typesafe/jev-1.13` via OpenRouter's System One API) through a narrow `GatePort`: one `is_safe` question returning a calibrated probability, with only command text and node name in state. Fail closed — never silent allow.
1. Score ≥ `SAFE_THRESHOLD` (code constant, 0.9) executes; below threshold, gate error/timeout, disabled gate, or missing key denies. Denial is command-local — no node quarantine in v1.
1. The agent receives one fixed string for every denial path: `Error: denied by policy`. Scores, rule text, and retry instructions never reach the caller; they land in CommandLog (`gate_score`, `gate_reason`) for operators.
1. The Approval Queue protocol is deleted end-to-end: `approval_id` / `approval_wait` / `bypass_scope` MCP params, the `pending_approvals` table (dropped at startup), the Approvals API and panel page, and session Bypass Patterns. Operators fix false positives by authoring an allow rule from the denied log row — policy change, never execute-and-return-output.

## Consequences

- Routine privileged work no longer pages a human; clearly unsafe work is denied without one.
- The gate is trusted-but-fail-closed: a compromised agent's unmatched commands are each denied and logged, but the agent is not otherwise contained — automatic quarantine is the documented v2 candidate, and `gate_reason` + score history is exactly the data a freeze policy would need.
- The command string is attacker-controlled input to the judge; it travels in `state`, verdict criteria in `instructions`. Jev is decision-only (no text channel), but crafted safe-looking commands can still score high — the calibrated probability is the only signal, hence the deliberately high threshold.
- Breaking schema/MCP change: existing databases should drop legacy `review`/`confirm`/`warn` rule rows or re-seed; unknown levels are skipped, never reinterpreted. CommandLog may still contain historical `security_level=review` rows.
