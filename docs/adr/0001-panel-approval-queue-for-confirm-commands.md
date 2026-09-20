# Panel approval queue replaces AI-relayed confirm tokens

Confirm-level commands used to return a one-time token directly to the AI assistant, which could re-submit it without a human ever seeing the command — "human approval" was a convention, not an enforcement point — and the in-memory token store broke under restarts and multi-process deployments. We decided to replace the token flow with a DB-backed `pending_approvals` queue: `ssh_run` parks a confirm-level command, a human approves or rejects it in the web panel, and the AI consumes the decision by re-calling `ssh_run` with `approval_id` (hybrid wait: a short synchronous poll first, then poll-later).

## Considered Options

- **Out-of-band token** (token displayed only in the panel, human pastes it back to the AI): smallest change, but keeps in-memory state and adds copy-paste friction.
- **Pure synchronous blocking** (`ssh_run` hangs until decided): simplest AI contract, but tool calls hang indefinitely when no operator is watching.
- **Keep tokens, document the risk**: rejected — AI self-approval is the core problem, not a documentation gap.

## Consequences

- Breaking change to the MCP tool surface: `ssh_run` loses `confirm_token`, gains `approval_id` and `approval_wait`.
- Approvals survive restarts and are safe across processes (SQLite WAL + atomic single-row claim).
- An approval is single-use: claiming it flips it to `executed` *before* the command runs, so one human decision authorizes exactly one execution attempt.
- The approval decision now lives in the web panel; panel auth (optional Bearer token) becomes security-relevant — deployments exposing the panel must set `api_token`.
