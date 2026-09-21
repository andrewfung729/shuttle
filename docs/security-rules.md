# Security Rules

Shuttle evaluates every command against a rule engine before execution. Rules use regex patterns and two security levels; anything that does not match a rule is scored by an LLM gate. This guide covers how rules work, the built-in defaults, per-node overrides, and the gate.

> **Removed:** the human Approval Queue, session Bypass Patterns, and the `confirm` / `warn` / `review` *rule* levels. The LLM gate is the default disposition for unmatched commands — not a rule you author. Existing databases with legacy `review`/`confirm`/`warn` rows skip those rules at evaluation (never reinterpreted); re-seed or delete them.

## Security Levels

Rules only use two levels. Unmatched commands take the **gate** disposition (not a rule level).

| Level / disposition | Behavior | When to use |
| --- | --- | --- |
| **block** (rule) | Denied immediately. Never calls the gate. | Destructive, unrecoverable operations (wipe disk, fork bomb). |
| **allow** (rule) | Executes normally. Never calls the gate. | Explicit allowlist — known-safe patterns you trust without a score. |
| **gate** (default) | Scored by the LLM gate: executes when calibrated safety score ≥ 0.9, else denied. | Everything that is neither blocked nor explicitly allowed. |

Rules are evaluated in **priority order** (lowest number first). The first matching **block** or **allow** rule wins. If no rule matches, the command is **gated** (fail closed).

Every denial — block rule, unsafe gate score, gate failure, or gate disabled — returns the same fixed string to the agent: `Error: denied by policy`. No scores, rule text, or retry instructions are exposed; the details live in the command log for operators (`security_level` is `block` or `gate`).

## The LLM Gate

When the disposition is `gate` (no block/allow match):

1. If the gate is disabled (`SHUTTLE_GATE_ENABLED=false`, the default) or no API key is set, the command is denied (reason `disabled`). This makes local development behave identically, minus gate calls.
1. Otherwise the gate asks a decision model (default `typesafe/jev-1.13` via OpenRouter's System One API) a single `is_safe` question about the command and node name. The model sees only that — no session history, secrets, or rule corpus.
1. A calibrated probability ≥ `SAFE_THRESHOLD` (code constant, 0.9) executes the command; anything below denies it (reason `unsafe`). Gate errors and timeouts deny too (reason `error`) — fail-open is impossible.

Operators configure the gate with environment variables:

| Variable                         | Default                     | Purpose                                       |
| -------------------------------- | --------------------------- | --------------------------------------------- |
| `SHUTTLE_GATE_ENABLED`           | `false`                     | Turn gate calls on/off without touching rules |
| `SHUTTLE_OPENROUTER_API_KEY`     | —                           | API key for the gate endpoint                 |
| `SHUTTLE_GATE_MODEL`             | `typesafe/jev-1.13`         | Decision model (version-pinned)               |
| `SHUTTLE_GATE_BASE_URL`          | `https://openrouter.ai/api` | TypeSafe System One–compatible endpoint       |
| `SHUTTLE_GATE_SAFE_INSTRUCTIONS` | built-in ops policy         | What the judge should treat as safe           |

The threshold and timeout are code constants on purpose: security posture is not an ops dial.

**Injection caveat:** the command string is attacker-controlled input to the judge. It travels in the request's `state`; the verdict criteria live in `instructions`. Jev is decision-only (calibrated probability, no text channel to hijack), but an attacker can still craft commands that merely look safe — the calibrated probability is the only signal, which is why the threshold stays high. See `examples/try_jev_gate.py` for a scored corpus.

**Fixing a false positive:** a denied row in the Activity log offers a "create allow rule" shortcut that opens the Rules form pre-filled with the command. Approving a denied command always means changing policy so a later retry passes — Shuttle never executes a held command and returns its output to the agent.

## Regex Pattern Syntax

Rule patterns are Python-compatible regular expressions matched with `re.search()` (not `re.match()`), so they can match anywhere in the command string.

### Examples

| Pattern              | Matches                           | Does not match            |
| -------------------- | --------------------------------- | ------------------------- |
| `^rm -rf /$`         | `rm -rf /` (exact)                | `rm -rf /tmp`             |
| `sudo .*`            | `sudo apt update`, `sudo reboot`  | `visudo`                  |
| `rm -rf `            | `rm -rf /tmp`, `rm -rf ~`         | `rm file.txt`             |
| `mkfs\.`             | `mkfs.ext4 /dev/sda1`             | `mkfsomething`            |
| `curl .* \| bash`    | `curl http://x.com/setup \| bash` | `curl http://x.com/setup` |
| `chmod 777`          | `chmod 777 /var/www`              | `chmod 755 /var/www`      |
| `:\(\)\{.*:\|:&\};:` | Fork bomb pattern                 | Normal commands           |

Patterns are capped at 500 characters to prevent ReDoS attacks. Invalid regex patterns are silently skipped, as are rules with unknown levels (e.g. legacy `review`/`confirm`/`warn` rows).

## Built-in Default Rules

These rules are seeded into the database on first startup (only if no rules exist yet). They provide a sensible baseline of **block** rules for catastrophic ops. Everything else is gated unless you add **allow** rules.

See `src/shuttle/db/seeds.py` for the current seed list (operator-maintained).

## Per-Node Rule Overrides

Rules can be **global** (apply to all nodes) or **node-specific** (apply to a single node).

### How Inheritance Works

1. Global rules have `node_id = NULL`. They apply to every node.
1. Node-specific rules have a `node_id` set. They apply only to that node.
1. When a node-specific rule has the **same pattern** as a global rule, the node-specific rule **overrides** the global one for that node.
1. Rules are sorted by priority (lowest first). The first match wins.

### Example Scenario

```
Global rules:
  ^rm -rf /$  → block  (priority 1)

GPU Server overrides:
  ^apt  → allow   (priority 20)  ← known-safe package installs on this node

Prod Server overrides:
  DROP TABLE → block (priority 5)   ← adds new rule for this node
```

Result:

- **GPU Server**: `apt install foo` is allowed (node override). `cat /etc/passwd` is gated (no match).
- **Prod Server**: `DROP TABLE users` is blocked. Routine reads are gated.
- **Other nodes**: Only the global block list applies; everything else is gated.

### Creating Node Overrides

In the web panel, navigate to **Rules**, select a node, and add a rule with the same pattern but a different level. The `source_rule_id` field can optionally reference the global rule being overridden for traceability.

## Best Practices

1. **Start with block for catastrophe, allow for hot paths.** Unmatched work already goes through the gate — you do not need a "review" rule for `sudo`.

1. **Use block sparingly.** Block rules never reach the gate. Reserve them for truly catastrophic commands (disk wipe, fork bomb).

1. **Allowlist what must be fast/cheap.** High-frequency read-only patterns (`^ls `, `^cat `, `^docker ps`) can be allow rules so they skip Jev latency and cost.

1. **Tighten prod, loosen dev.** Use per-node allow overrides on development servers; keep prod on gate + block only.

1. **Be specific with patterns.** `rm -rf /` (with anchor) is better than `rm` (too broad). Test your regex against expected commands before deploying.

1. **Use priority to control ordering.** Lower numbers are evaluated first. Place block rules at low priorities (1--9); allow rules can sit higher.

1. **Watch the denied rows.** The Activity log shows every denial with the gate score and reason (`unsafe` / `error` / `disabled`). A flood of `disabled` means the gate is off; recurring `unsafe` false positives are your cue to add an allow rule via the shortcut.

1. **Disable rather than delete.** Each rule has an `enabled` flag. Disable a rule to stop it from matching without losing the configuration.
