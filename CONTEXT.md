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
Default decision path for unmatched commands: a decision model (default `typesafe/jev-1.13` via OpenRouter's System One API) scores a single `is_safe` question about the command. Bands are code constants: scores at or above `SAFE_THRESHOLD` (0.9) execute; scores from `HOLD_FLOOR` (0.3) up to that threshold park a Hold; scores below the floor deny. Fail-closed: gate errors, timeouts, disabled gate, or missing key all deny without a Hold.
_Avoid_: approval, judge service, moderator

**Hold**:
A parked exact command in the uncertain band, bound to the server-derived conversation that requested it, waiting for one Operator decision. The requesting agent never receives its id, score, band, or rule text — only the fixed awaiting string.
_Avoid_: approval, pending approval, request

**Operator**:
The human using the web panel who decides a Hold. The requesting agent is not an Operator.
_Avoid_: approver, reviewer

**Denial Note**:
Optional free text an Operator attaches when denying a Hold, returned to the agent appended to the fixed denial string. It is the only operator-authored text the agent receives; machine-derived signals never do.
_Avoid_: rejection reason, block message, error detail

**Denial**:
The fixed agent-visible string `Error: denied by policy`, logged as a CommandLog row with the matched rule and gate metadata. A denial may carry an Operator's Denial Note as `Error: denied by policy: <note>`. Scores, band names, rule text, and Hold ids never reach the agent.
_Avoid_: rejection reason, block message
