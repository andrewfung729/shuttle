# ADR-0003: Uncertain-band Hold returns a bounded human decision to the LLM gate

- **Status**: Accepted
- **Date**: 2026-09-27
- **Supersedes in part**: [ADR-0002](0002-llm-gate-replaces-approval-queue.md) (the single fixed denial string and its ban on retry instructions; the ban on execute-and-return)
- **Partially adopts**: [ADR-0001](0001-panel-approval-queue-for-confirm-commands.md) (synchronous blocking, in bounded form)

## Context

ADR-0002 replaced the human-in-the-loop path with a fail-closed LLM gate: unmatched commands scoring at or above `SAFE_THRESHOLD` (0.9) execute; everything else denies with one fixed string, `Error: denied by policy`. That is right for the confident and for the destructive, but it denies the uncertain band — scores a human should still judge — and gives the agent no way to tell "replan" from "a human may still allow this". A cooperating agent either mutates the command to probe or gives up. ADR-0001's queue had the opposite failure: it paged a human for every coarse rule match and handed the agent an id it could poll.

The scope here is **coverage only**: put a human back at the one place the model is worse than a human, and nowhere else. Multi-use, task-scoped authorization ("Grant"), operator-authored patterns, promote, and burst limiting are deliberately not part of this decision.

## Decision

1. **Bands, as code constants.** Score ≥ `SAFE_THRESHOLD` (0.9) executes. Score ≥ `HOLD_FLOOR` (0.3) and below the threshold parks a **Hold**. Score below the floor denies (`unsafe`). Gate errors, timeouts, a disabled gate, or a missing key deny (`error` / `disabled`) with no Hold.

1. **A Hold is an exact command**, bound to the server-derived conversation that requested it and matching on raw command bytes. The requesting agent never receives its id, score, band, or rule text.

1. **Bounded hold.** `ssh_run` parks the Hold and waits at most `HOLD_WAIT` (20s) for a decision, then returns `Error: awaiting operator`. This partially adopts the pure synchronous blocking ADR-0001 rejected, bounded so an unwatched tool call cannot hang: the wait must stay comfortably below the MCP client's tool timeout.

1. **The decision triggers execution.** An operator's *run once* executes the command exactly once, in a server-owned task, and stores the output on the Hold; *deny* resolves the Hold. There is no approval id, no consume window, and no poll loop. A waiter collects the result inline; a caller that already returned collects it by retrying the identical command.

1. **Agent-visible contract.** `ssh_run` returns command stdout, `Error: denied by policy`, or `Error: awaiting operator`. A denial may carry an operator-authored **Denial Note** as `Error: denied by policy: <note>`. Machine-derived signals (score, band, rule text, Hold id) still never reach the agent; the Denial Note is the one, deliberate, operator-authored exception, and it is optional, single-line, and length-capped.

1. **Deleted.** Burst limiting and the `unbound` path. Operator-authored patterns, promote, and the conversation Grant are not introduced. Security levels stay `block` / `allow`; the unmatched disposition stays `gate`.

## Consequences

- The gate is no longer purely autonomous: a human decision can return stdout to a requester that may be prompt-injected. The panel must make the node, command, and requesting conversation obvious.
- A held tool call is bounded by `HOLD_WAIT`; a client with a shorter tool timeout simply shrinks the inline window and falls back to the awaiting-and-retry path. Correctness does not depend on the client timeout.
- Executing at decision time means a command can run even after the requester has disconnected. The output is durable and is picked up on retry; a retry never re-runs an `executed` command.
- The Denial Note is a trusted operator-to-agent channel. A compromised panel can inject instructions through it; that is the same exposure as a compromised panel generally and is not separately defended.
- ADR-0002's deletion of approval ids, confirm tokens, bypass scope, the `pending_approvals` table, and the Approvals page still stands. ADR-0001 remains history; its token and single-row-claim lessons are reused, its protocol is not.
- Deferred on purpose: multi-use task-scoped authorization, lasting exceptions (use the rules page), and burst limiting. If repeated paging across a deploy proves painful, that is the signal to revisit a Grant.
