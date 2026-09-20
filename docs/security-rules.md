# Security Rules

Shuttle evaluates every command against a rule engine before execution. Rules use regex patterns and three security levels; review-level matches are scored by an LLM gate. This guide covers how rules work, the built-in defaults, per-node overrides, and the gate.

> **Removed in v3 (breaking):** the human Approval Queue (`approval_id`, claim loop, panel Approvals page), session Bypass Patterns, and the `confirm`/`warn` levels are gone. The LLM gate replaces the human-approve path. Existing databases must update rule levels (`confirm` → `review`; `warn` rules delete) or re-seed — unknown levels are skipped at evaluation, never reinterpreted.

## Security Levels

Every rule has one of three levels. When a command matches a rule, Shuttle takes the corresponding action:

| Level      | Behavior                                                                              | When to use                                                                     |
| ---------- | ------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------- |
| **block**  | Denied immediately. Never calls the gate.                                             | Destructive, unrecoverable operations (wipe disk, fork bomb).                   |
| **review** | Scored by the LLM gate: executes when the calibrated safety score ≥ 0.9, else denied. | Privileged or risky operations where routine matches are fine but abuse is not. |
| **allow**  | Executes normally.                                                                    | The default — any command that does not match a higher-level rule.              |

Rules are evaluated in **priority order** (lowest number first). The first matching rule determines the outcome. If no rule matches, the command is allowed.

Every denial — block rule, unsafe gate score, gate failure, or gate disabled — returns the same fixed string to the agent: `Error: denied by policy`. No scores, rule text, or retry instructions are exposed; the details live in the command log for operators.

## The LLM Gate

When a `review`-level rule matches:

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

Patterns are capped at 500 characters to prevent ReDoS attacks. Invalid regex patterns are silently skipped, as are rules with unknown levels (e.g. legacy `confirm`/`warn` rows).

## Built-in Default Rules

These rules are seeded into the database on first startup (only if no rules exist yet). They provide a sensible baseline.

### Block (priority 1--4)

| Priority | Pattern              | Description            |
| -------- | -------------------- | ---------------------- |
| 1        | `^rm -rf /$`         | Remove root filesystem |
| 2        | `mkfs\.`             | Format filesystem      |
| 3        | `dd if=.* of=/dev/`  | Raw disk write         |
| 4        | `:\(\)\{.*:\|:&\};:` | Fork bomb              |

### Review (priority 10--15)

| Priority | Pattern     | Description                |
| -------- | ----------- | -------------------------- |
| 10       | `sudo .*`   | Sudo commands              |
| 11       | `rm -rf `   | Recursive force delete     |
| 12       | `chmod 777` | World-writable permissions |
| 13       | `shutdown`  | System shutdown            |
| 14       | `reboot`    | System reboot              |
| 15       | `kill -9`   | Force kill process         |

You can add, edit, disable, or delete these rules through the web panel or directly in the `security_rules` database table.

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
  sudo .*  → review  (priority 10)
  rm -rf   → review  (priority 11)

GPU Server overrides:
  sudo .*  → allow   (priority 10)  ← overrides global for this node

Prod Server overrides:
  DROP TABLE → block (priority 5)   ← adds new rule for this node
```

Result:

- **GPU Server**: `sudo apt update` is allowed (node override). `rm -rf /tmp` still goes through the gate (global rule, no override).
- **Prod Server**: `DROP TABLE users` is blocked (node-specific rule). `sudo service restart` goes through the gate (global rule).
- **Other nodes**: Both `sudo` and `rm -rf` go through the gate (global rules only).

### Creating Node Overrides

In the web panel, navigate to **Rules**, select a node, and add a rule with the same pattern but a different level. The `source_rule_id` field can optionally reference the global rule being overridden for traceability.

## Best Practices

1. **Start with the defaults.** The built-in rules cover the most common dangerous operations. Add rules as you discover patterns specific to your environment.

1. **Use block sparingly.** Block rules never reach the gate. Reserve them for truly catastrophic commands (disk wipe, fork bomb). For risky-but-routine commands, review is a better choice — the gate sorts routine from abuse.

1. **Tighten prod, loosen dev.** Use per-node overrides to allow `sudo` on development servers while keeping it at review on production.

1. **Be specific with patterns.** `rm -rf /` (with anchor) is better than `rm` (too broad). Test your regex against expected commands before deploying.

1. **Use priority to control ordering.** Lower numbers are evaluated first. Place block rules at low priorities (1--9) and review rules in the middle (10--19).

1. **Watch the denied rows.** The Activity log shows every denial with the gate score and reason (`unsafe` / `error` / `disabled`). A flood of `disabled` means the gate is off; recurring `unsafe` false positives are your cue to add an allow rule via the shortcut.

1. **Disable rather than delete.** Each rule has an `enabled` flag. Disable a rule to stop it from matching without losing the configuration.
