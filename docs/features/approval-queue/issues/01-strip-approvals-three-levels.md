# 01: Strip Approvals; three Security Levels only

**What to build:** The human Approval Queue is gone. Agents call `ssh_run` with no approval or bypass parameters. Security Rules only use `block`, `review`, and `allow`. Block still hard-denies; allow still runs; review always returns `Error: denied by policy` and does not quarantine the Node (the gate is not wired yet—this matches the “gate off” behavior). Approvals API, Approvals panel entry points, and durable approval rows are removed so nothing teaches or serves the old protocol. Seed rules that were confirm become review; warn seeds are deleted.

**Blocked by:** None (can start immediately)

**Status:** resolved

- [x] MCP `ssh_run` no longer accepts `approval_id`, `approval_wait`, or `bypass_scope` (or any residual confirm token)
- [x] Matching a `block` rule returns exactly `Error: denied by policy` and does not execute
- [x] Matching a `review` rule returns exactly `Error: denied by policy`, does not execute, and does not quarantine the Node
- [x] Matching no rule / `allow` still executes when the Node is healthy
- [x] Command Guard has no bypass-pattern path; Security Level enum/validation/seeds only allow `block` | `review` | `allow`
- [x] `pending_approvals` storage, Approval repo/API/UI routes, and approval-oriented MCP prompts/docs references used by the runtime path are removed (no dual-stack)
- [x] Config no longer exposes approval TTL/wait knobs
- [x] Tests that encoded the old approval claim/wait protocol are rewritten or deleted; new/adjusted tests cover the block/review/allow matrix above
