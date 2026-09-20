# MCP API Reference

Shuttle exposes 4 MCP tools and 6 MCP resources. Tools are actions the AI calls; resources are read-only runtime state the AI reads for context. This page documents every tool's parameters, return format, and usage examples.

## ssh_run

Run a shell command on a remote SSH node. Sessions are managed automatically: working directory is preserved across calls to the same node. 4-level security checks are applied before execution.

| Parameter       | Type   | Required | Default               | Description                                                                                                                 |
| --------------- | ------ | -------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------- |
| `command`       | string | yes      | —                     | Shell command to execute                                                                                                    |
| `node`          | string | no       | —                     | Node name (auto-selected if only one node exists)                                                                           |
| `timeout`       | float  | no       | 30.0                  | Command timeout in seconds                                                                                                  |
| `approval_id`   | string | no       | —                     | Existing approval to check (from a pending response)                                                                        |
| `approval_wait` | float  | no       | server default (20.0) | Seconds to wait synchronously for a decision; `0` returns immediately; progress-capable clients wait up to the approval TTL |
| `bypass_scope`  | string | no       | —                     | Bypass scope for session commands                                                                                           |

**Returns:** Command output (stdout), or an error/security message.

**Session management:** Sessions are implicit. The first call to a node auto-creates a session; subsequent calls reuse it, preserving the working directory.

**Security flow:**

1. Command is evaluated against security rules
1. `block` → rejected immediately
1. `confirm` → creates a durable approval and waits; the human decides in the web panel. The pending message includes an `approval_id` — re-call with the SAME command byte-for-byte plus that `approval_id` to pick up the decision (approved → executes; rejected → error with the operator's reason; expired/already-used → clear error)
1. `warn` → executes with warning logged
1. `allow` → executes normally

**Example:**

```
AI → ssh_run(node="gpu-server", command="nvidia-smi")
AI ← "Fri Mar 21 17:07:21 2026\n+---------------------+\n| NVIDIA-SMI 580.105 ..."

AI → ssh_run(node="gpu-server", command="cd /workspace && pwd")
AI ← "/workspace"   # working directory preserved for next call
```

______________________________________________________________________

## ssh_upload

Upload a file to a remote node via SFTP.

| Parameter     | Type   | Required | Description             |
| ------------- | ------ | -------- | ----------------------- |
| `node`        | string | yes      | Node name               |
| `local_path`  | string | yes      | Local file path         |
| `remote_path` | string | yes      | Remote destination path |

**Returns:** Confirmation or error message.

```
Uploaded /tmp/model.pt -> gpu-server:/workspace/model.pt
```

______________________________________________________________________

## ssh_download

Download a file from a remote node via SFTP.

| Parameter     | Type   | Required | Description            |
| ------------- | ------ | -------- | ---------------------- |
| `node`        | string | yes      | Node name              |
| `remote_path` | string | yes      | Remote file path       |
| `local_path`  | string | yes      | Local destination path |

**Returns:** Confirmation or error message.

______________________________________________________________________

## ssh_add_node

Add a new SSH node to the Shuttle configuration. The node is registered in the database and connection pool.

| Parameter     | Type         | Required | Default | Description                                  |
| ------------- | ------------ | -------- | ------- | -------------------------------------------- |
| `name`        | string       | yes      | —       | Unique node name                             |
| `host`        | string       | yes      | —       | Hostname or IP                               |
| `port`        | int          | no       | 22      | SSH port                                     |
| `username`         | string      | no       | ""      | SSH username                                 |
| `private_key_path` | string      | yes      | —       | Path to a private key file on the Shuttle server; read locally so the key content never appears in the agent conversation |
| `jump_host`        | string      | no       | —       | Name of an existing node to use as jump host |
| `tags`             | list[string] | no      | —       | Tags for categorization                      |

Inline secrets (`password`, `private_key`) are not accepted — key auth only, read server-side from `private_key_path`. Credentials are encrypted at rest. Password nodes can be added via the CLI (`shuttle node add`) or web panel instead.

**Returns:** Confirmation with node ID.

______________________________________________________________________

# MCP Resources

Resources are read-only views of Shuttle's live runtime state. AI assistants read them for context without executing commands. Client support varies — some clients (e.g. Claude Code) surface them as `read_*` tools.

## shuttle://nodes

All configured SSH nodes with connection details and status.

**Returns:** JSON — `{"nodes": [...], "total": N}`, each node with `name`, `host`, `port`, `username`, `status`, `auth_type`, `tags`, `last_seen_at`.

## shuttle://nodes/{name}

Detailed information for one node, including its connection pool state.

**Returns:** JSON — node fields as above, plus `pool` (`active_connections`, `idle_connections`, `registered`) and `created_at`/`updated_at`. Returns `{"error": "Node '...' not found"}` for unknown names.

## shuttle://security-rules

All security rules governing command execution, grouped by level.

**Returns:** JSON — `{"rules": [...], "total": N, "by_level": {"BLOCK": n, "CONFIRM": n, ...}}`, each rule with `id`, `pattern`, `level`, `description`, `priority`, `enabled`, `node_id`. Read this before running commands that might be blocked or need approval.

## shuttle://sessions

Currently active SSH sessions.

**Returns:** JSON — each session with `session_id`, `node_id`, `working_directory`, `bypass_patterns`, `env_vars`. Useful to check which node has an existing session (and its cwd) before calling `ssh_run`.

## shuttle://pool-status

Connection pool health.

**Returns:** JSON — `config` (`max_per_node`, `max_total`, `idle_timeout_s`, `max_lifetime_s`), `global_active`, `registered_nodes`, and per-node `active`/`idle` counts. Use to diagnose connection exhaustion.

## shuttle://logs/{node_name}/recent

Recent command execution history for a node (last 20 commands).

**Returns:** JSON — each log with `command`, `exit_code`, `security_level`, `bypassed`, `duration_ms`, `executed_at`. Returns `{"error": "Node '...' not found"}` for unknown names.
