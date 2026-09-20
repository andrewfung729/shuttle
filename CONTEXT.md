# Shuttle

Shuttle is a secure SSH gateway for AI assistants: MCP clients run commands on remote servers under a rule-based security regime with an LLM gate for review-level commands and a full audit trail.

## Language

### Security

**Security Rule**:
A regex pattern plus a security level that decides how a matching command is treated.
_Avoid_: policy, filter

**Security Level**:
The action a matched rule triggers: `block`, `review`, or `allow`.
_Avoid_: severity, confirm, warn

**Command Guard**:
The evaluator that matches a command against security rules and produces a decision.
_Avoid_: checker, validator

**Review Level**:
The level that routes a matched command to the LLM Gate instead of executing or denying outright.
_Avoid_: confirm level, confirmation

**LLM Gate**:
The review-level decision path: a decision model (default `typesafe/jev-1.13` via OpenRouter's System One API) scores a single `is_safe` question about the command; scores at or above `SAFE_THRESHOLD` (a code constant, 0.9) execute, everything else denies. Fail-closed: gate errors, timeouts, disabled gate, or missing key all deny.
_Avoid_: approval, judge service, moderator

**Denial**:
The fixed agent-visible string `Error: denied by policy`, logged as a CommandLog row with the matched rule and gate metadata (score, reason `unsafe`/`error`/`disabled`). No scores, rule text, or retry instructions reach the agent.
_Avoid_: rejection reason, block message
