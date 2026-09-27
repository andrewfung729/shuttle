# Shuttle MCP — SSH Gateway for AI Assistants

Use this skill when the user wants to execute commands on remote SSH servers, manage SSH nodes, or work with the Shuttle MCP tools.

## What is Shuttle

Shuttle is a secure SSH gateway that lets AI assistants operate remote servers through the MCP protocol. It provides connection pooling, implicit sessions, block/allow security rules, an LLM gate, and a web panel.

## Available MCP Tools

| Tool           | Purpose                                        | Key Parameters                                      |
| -------------- | ---------------------------------------------- | --------------------------------------------------- |
| `ssh_run`      | Run a command on a remote node                 | `command`, `node` (name), `timeout`                 |
| `ssh_add_node` | Add a new SSH node (key path only, never inline secrets) | `name`, `host`, `private_key_path`, `username` |
| `ssh_upload`   | Upload a file via SFTP                         | `node`, `local_path`, `remote_path`                 |
| `ssh_download` | Download a file via SFTP                       | `node`, `remote_path`, `local_path`                 |

Nodes, rules, sessions, pool status, and recent logs are read-only resources (`shuttle://nodes` and others), not tools. Sessions are implicit: the working directory is preserved across `ssh_run` calls to the same node. There is no `ssh_execute`, `session_id`, `confirm_token`, or `approval_id`.

## How to Use

```
ssh_run(command="nvidia-smi", node="gpu-server")
ssh_run(command="cd /opt/project && python train.py", node="gpu-server")
```

## Security

Rules are `block` or `allow` only. Anything unmatched is scored by the LLM gate.

| Disposition | What `ssh_run` returns                         | What to do                                      |
| ----------- | ---------------------------------------------- | ----------------------------------------------- |
| ran         | command output                                 | continue                                        |
| denied      | `Error: denied by policy`                      | replan; do not probe with command variants      |
| held        | `Error: awaiting operator`                     | retry the identical command later               |

A denial may append an operator note: `Error: denied by policy: <note>`. Scores, rule text, and Hold ids are never returned. Do not invent an approval id or a confirm token.

## Best Practices

1. **Preserve directory with `cd &&`** — sessions keep the working directory, but a single call should still be explicit.
2. **Name nodes descriptively** — `gpu-prod-a100` not `server1`.
3. **Read `shuttle://nodes` first** if unsure which nodes exist.
4. **Set reasonable timeouts** — default is 30s; increase for long-running commands (`timeout=300`).
5. **On denial, change the approach** — a block or an unsafe score will not pass on retry.
