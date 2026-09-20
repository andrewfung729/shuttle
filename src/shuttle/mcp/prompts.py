"""MCP prompt registrations for Shuttle.

Provides ``register_prompts()`` which adds reusable prompt templates that
leverage Shuttle's runtime state to give AI assistants actionable context.
"""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from typing import Any

from shuttle.core.session import SessionManager


def register_prompts(
    mcp: Any,
    session_mgr: SessionManager,
    pool: Any,
    db_session_ctx: Callable[..., AsyncIterator],
    node_repo_factory: Callable,
) -> None:
    """Register all Shuttle MCP prompts on the given FastMCP instance."""

    @mcp.prompt()
    async def safe_command_check(command: str, node: str | None = None) -> str:
        """Check if a command is safe to run before executing it.

        Evaluates the command against all active security rules and returns
        a detailed assessment — which rules match, what security level applies,
        and whether the command will run.
        """
        from shuttle.db.repository import RuleRepo

        async with db_session_ctx() as db_sess:
            rule_repo = RuleRepo(db_sess)
            rules = await rule_repo.list_all(node_id=None)

        # If node specified, also get node-specific rules
        node_rules = []
        if node:
            async with db_session_ctx() as db_sess:
                repo = node_repo_factory(db_sess)
                node_obj = await repo.get_by_name(node)
            if node_obj:
                async with db_session_ctx() as db_sess:
                    rule_repo = RuleRepo(db_sess)
                    node_rules = await rule_repo.list_all(node_id=node_obj.id)

        all_rules = rules + node_rules
        enabled_rules = [r for r in all_rules if r.enabled]

        import re

        matching = []
        for r in enabled_rules:
            try:
                if re.search(r.pattern, command):
                    matching.append(r)
            except re.error:
                pass

        if not matching:
            return (
                f"## Command Safety Check\n\n"
                f"**Command**: `{command}`\n"
                f"**Node**: {node or '(auto-select)'}\n"
                f"**Result**: ✅ ALLOW — no security rules matched.\n\n"
                "You can proceed with `ssh_run(command=...)`."
            )

        lines = []
        highest_level = "ALLOW"
        level_order = {"BLOCK": 3, "REVIEW": 2, "ALLOW": 0}
        for r in matching:
            lines.append(
                f"  • [{r.level}] pattern=`{r.pattern}` — {r.description or 'no description'}"
            )
            if level_order.get(r.level, 0) > level_order.get(highest_level, 0):
                highest_level = r.level

        icon = {"BLOCK": "⛔", "REVIEW": "⚖️"}.get(highest_level, "✅")

        advice = {
            "BLOCK": "This command will be denied. Rephrase or use an alternative approach.",
            "REVIEW": (
                "This command is gated: it executes only when the LLM gate scores "
                "it safe. If it is denied you will see a fixed policy error — ask "
                "the operator to adjust the Security Rules if it was a false positive."
            ),
        }.get(highest_level, "Proceed normally.")

        return (
            f"## Command Safety Check\n\n"
            f"**Command**: `{command}`\n"
            f"**Node**: {node or '(auto-select)'}\n"
            f"**Result**: {icon} {highest_level}\n\n"
            f"### Matched Rules ({len(matching)})\n"
            + "\n".join(lines)
            + f"\n\n### Recommendation\n{advice}"
        )

    @mcp.prompt()
    async def node_context(node: str) -> str:
        """Get full operational context for a specific node.

        Returns the node's configuration, its active session state (including
        current working directory), applicable security rules, and recent
        command history — ready for the AI to operate on this node.
        """
        from shuttle.db.repository import LogRepo, RuleRepo

        # Node info
        async with db_session_ctx() as db_sess:
            repo = node_repo_factory(db_sess)
            node_obj = await repo.get_by_name(node)

        if not node_obj:
            return f"Node **{node}** not found. Read the `shuttle://nodes` resource to see available nodes."

        # Active session
        active = session_mgr.list_active()
        node_session = next((s for s in active if s.node_id == node), None)

        session_info = (
            f"  Session ID: {node_session.session_id}\n"
            f"  Working directory: {node_session.working_directory}"
            if node_session
            else "  No active session (will be auto-created on first ssh_run)"
        )

        # Node-specific security rules
        async with db_session_ctx() as db_sess:
            rule_repo = RuleRepo(db_sess)
            all_rules = await rule_repo.list_all()
            node_rules = await rule_repo.list_all(node_id=node_obj.id)

        global_rules = [r for r in all_rules if r.node_id is None and r.enabled]
        specific_rules = [r for r in node_rules if r.enabled]

        rule_lines = []
        for r in (specific_rules + global_rules)[:15]:
            scope = "node-specific" if r.node_id else "global"
            rule_lines.append(f"  [{r.level}] `{r.pattern}` ({scope})")

        rules_section = "\n".join(rule_lines) if rule_lines else "  (no rules)"

        # Recent command logs
        async with db_session_ctx() as db_sess:
            log_repo = LogRepo(db_sess)
            logs = await log_repo.list_by_node(node_id=node_obj.id, limit=10)

        log_lines = []
        for log in logs:
            icon = "✅" if log.exit_code == 0 else "❌"
            cmd_short = log.command[:60] + ("..." if len(log.command) > 60 else "")
            duration = f"{log.duration_ms}ms" if log.duration_ms else "?"
            log_lines.append(
                f"  {icon} `{cmd_short}` (exit={log.exit_code}, {duration})"
            )

        logs_section = "\n".join(log_lines) if log_lines else "  (no recent commands)"

        # Pool state
        pool_idle = len(pool._idle.get(node, []))
        pool_active = pool._active.get(node, 0)

        return (
            f"# Node: {node}\n\n"
            f"## Connection\n"
            f"  Host: {node_obj.host}:{node_obj.port}\n"
            f"  User: {node_obj.username}\n"
            f"  Auth: {node_obj.auth_type}\n"
            f"  Status: {node_obj.status}\n"
            f"  Tags: {node_obj.tags or []}\n"
            f"  Pool: {pool_active} active, {pool_idle} idle connections\n\n"
            f"## Current Session\n{session_info}\n\n"
            f"## Security Rules (top {len(rule_lines)})\n{rules_section}\n\n"
            f"## Recent Commands (last {len(log_lines)})\n{logs_section}\n\n"
            f"Ready to operate. Use `ssh_run(command=..., node='{node}')` to execute."
        )
