# Shuttle

Shuttle is a secure SSH gateway for AI assistants: MCP clients run commands on remote servers under a rule-based approval regime with a full audit trail.

## Language

### Security

**Security Rule**:
A regex pattern plus a security level that decides how a matching command is treated.
_Avoid_: policy, filter

**Security Level**:
The action a matched rule triggers: `block`, `confirm`, `warn`, or `allow`.
_Avoid_: severity

**Command Guard**:
The evaluator that matches a command against security rules and produces a decision.
_Avoid_: checker, validator

**Approval**:
A human decision (approve or reject) that authorizes exactly one execution attempt of one specific command on one specific node.
_Avoid_: confirmation, confirm token, sign-off

**Approval Queue**:
The set of commands that matched confirm-level rules and are waiting for an Approval.
_Avoid_: pending list, token store

**Bypass Pattern**:
A rule pattern recorded on a session so matching commands skip confirm/warn handling for that session only. Block rules are never bypassed.
_Avoid_: allowlist (implies global scope), exception
