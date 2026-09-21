# Shuttle

Shuttle is a secure SSH gateway for AI assistants: MCP clients run commands on remote servers under a rule-based security regime (block/allow rules, LLM gate default) and a full audit trail.

## Language

### Security

**Security Rule**:
A regex pattern plus a security level that decides how a matching command is treated.
_Avoid_: policy, filter

**Security Level**:
Rule levels are only `block` or `allow`. The unmatched disposition is `gate` (not a rule you author).
_Avoid_: severity, confirm, warn, review (as a rule level)

**Command Guard**:
The evaluator that matches a command against security rules and produces a decision (`block` / `allow` / `gate`).
_Avoid_: checker, validator

**Gate Disposition**:
Default when no block/allow rule matches: route the command to the LLM Gate.
_Avoid_: review level, confirm level

**LLM Gate**:
Default decision path for unmatched commands: a decision model (default `typesafe/jev-1.13` via OpenRouter's System One API) scores a single `is_safe` question about the command; scores at or above `SAFE_THRESHOLD` (a code constant, 0.9) execute, everything else denies. Fail-closed: gate errors, timeouts, disabled gate, or missing key all deny.
_Avoid_: approval, judge service, moderator

**Denial**:
The fixed agent-visible string `Error: denied by policy`, logged as a CommandLog row with the matched rule and gate metadata (score, reason `unsafe`/`error`/`disabled`). No scores, rule text, or retry instructions reach the agent.
_Avoid_: rejection reason, block message
