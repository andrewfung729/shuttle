"""MCP tool registrations for the Shuttle SSH gateway.

Provides ``register_tools()`` which wires up four tools on a FastMCP instance:
ssh_run, ssh_upload, ssh_download, ssh_add_node. (Node listing is exposed
via the ``shuttle://nodes`` resource, not a tool.)

Sessions are managed implicitly: ``ssh_run`` auto-creates or reuses a session
per node so that working directory context is preserved across calls.
"""

from __future__ import annotations

import asyncio
import re
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from fastmcp import Context
from loguru import logger

from shuttle.core.security import CommandGuard, SecurityLevel
from shuttle.core.session import SessionManager

# Truncation limits
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB for caller output
MAX_DB_OUTPUT_BYTES = 64 * 1024  # 64 KB for DB storage


def _truncate(text: str, limit: int) -> str:
    """Truncate *text* to *limit* bytes (UTF-8), appending a marker if truncated."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="replace") + "\n... [truncated]"


# ---------------------------------------------------------------------------
# Approval wait loop (hybrid wait)
# ---------------------------------------------------------------------------

APPROVAL_POLL_INTERVAL = 2.0  # seconds between status polls
APPROVAL_WAIT_CLAMP = (0.0, 300.0)


def _utc(dt: datetime) -> datetime:
    """SQLite returns naive datetimes — re-attach UTC when missing."""
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def _effective_wait(approval_wait: float | None, settings: Any) -> float:
    wait = settings.approval_wait if approval_wait is None else approval_wait
    return max(APPROVAL_WAIT_CLAMP[0], min(APPROVAL_WAIT_CLAMP[1], float(wait)))


def _has_progress_token(ctx: Any) -> bool:
    """True when the caller's MCP request carries a progressToken.

    Progress-capable clients reset their request timeout on every
    notifications/progress heartbeat, so the wait may extend to the full
    approval TTL instead of the 20 s floor.
    """
    if ctx is None:
        return False
    try:
        meta = ctx.request_context.meta
        return bool(meta and getattr(meta, "progressToken", None))
    except Exception:
        return False


def _already_used_message(approval_id: str) -> str:
    return (
        f"Error: approval '{approval_id}' was already used (single-use). "
        f"Resubmit the command without approval_id to create a new approval."
    )


def _expired_message(approval_id: str) -> str:
    return (
        f"Error: approval '{approval_id}' expired before a decision was made. "
        f"Resubmit the command without approval_id to create a new approval."
    )


def _rejection_message(ap, command: str, node_name: str, rule_description: str) -> str:
    return (
        f"❌ Approval rejected (id: {ap.id})\n"
        f"Command: {command}\n"
        f"Node: {node_name}  Rule: {rule_description}\n"
        f"Reason: {ap.reject_reason or 'no reason given'}\n"
        f"Ask the operator for clarification, or revise the command and resubmit — "
        f"a resubmission always creates a NEW approval_id."
    )


def _pending_message(ap, command: str, node_name: str, rule_description: str) -> str:
    return (
        f"⏳ Approval required (id: {ap.id})\n"
        f"Command: {command}\n"
        f"Node: {node_name}  Rule: {rule_description}\n"
        f"A human must approve this in the Shuttle web panel (Approvals page).\n"
        f"To check the decision, re-call ssh_run with the SAME command byte-for-byte "
        f'(do not reformat or re-quote) plus: approval_id="{ap.id}"'
    )


async def _wait_for_decision(
    repo: Any,
    approval,
    effective_wait: float,
    ctx: Any,
    rule_description: str,
) -> tuple[str, Any]:
    """Poll an approval until a terminal outcome or the wait budget runs out.

    Returns (outcome, approval_row) where outcome is one of:
    "approved" (claimed — caller may execute), "rejected", "expired",
    "already_used", "timeout".

    Deadline: min(effective_wait, time-to-expiry) for progress-less clients;
    progress-capable clients (progressToken in the request) get heartbeats
    every tick and the deadline extends to time-to-expiry automatically.
    """
    progress = _has_progress_token(ctx)
    start = time.monotonic()
    if effective_wait <= 0:
        return "timeout", approval  # explicit "return immediately"
    while True:
        approval = await repo.get(approval.id)
        now = datetime.now(UTC)
        expired = _utc(approval.expires_at) <= now

        if approval.status == "approved":
            if await repo.claim(approval.id):
                return "approved", approval
            # Lost the claim race — another caller consumed it.
            approval = await repo.get(approval.id)
            if approval.status == "executed":
                return "already_used", approval
            if _utc(approval.expires_at) <= datetime.now(UTC):
                return "expired", approval
            continue  # status changed underneath us; re-evaluate next tick

        if approval.status == "rejected":
            return "rejected", approval
        if approval.status == "executed":
            return "already_used", approval
        if approval.status == "expired" or expired:
            if approval.status == "pending":
                await repo.sweep_expired()
            return "expired", approval

        # Still pending.
        waited = time.monotonic() - start
        if not progress and waited >= effective_wait:
            return "timeout", approval
        if progress and ctx is not None:
            try:
                await ctx.report_progress(
                    progress=round(waited, 1),
                    message="Waiting for approval decision in the Shuttle panel",
                )
            except Exception:
                pass  # progress notification is best-effort
        await asyncio.sleep(APPROVAL_POLL_INTERVAL)


# ---------------------------------------------------------------------------
# Core execution logic (extracted for testability)
# ---------------------------------------------------------------------------


def _session_bypass_matched(command: str, bypass_patterns: list[str]) -> bool:
    """True when one of the session's bypass patterns matches the command.

    Bypass patterns are only ever added from matched confirm/warn rules, so a
    regex hit here means a confirm/warn rule was skipped via session bypass.
    """
    for pattern in bypass_patterns:
        try:
            if len(pattern) <= 500 and re.search(pattern, command):
                return True
        except re.error:
            continue
    return False


async def _execute_command_logic(
    *,
    command: str,
    node: str | None,
    timeout: float,
    approval_id: str | None,
    approval_wait: float | None,
    bypass_scope: str | None,
    pool: Any,
    guard: CommandGuard,
    session_mgr: SessionManager,
    db_session_ctx: Callable[..., AsyncIterator],
    node_repo_factory: Callable,
    approval_repo_factory: Callable,
    settings: Any,
    ctx: Any = None,
) -> str:
    """Execute a command with security checks, node resolution, and DB logging.

    Sessions are implicit: if an active session exists for the resolved node it
    is reused; otherwise a new session is created automatically.

    CONFIRM-level commands go through the durable approval queue: a pending
    row is created in the DB, a human decides in the web panel, and the
    caller either waits (hybrid wait) or re-polls via ``approval_id``.

    Parameters
    ----------
    command : str
        The shell command to run.
    node : str | None
        Named node to target.  Auto-selected when only one node exists.
    timeout : float
        Command timeout in seconds.
    approval_id : str | None
        Existing approval to re-check (from a previous pending response).
    approval_wait : float | None
        Seconds to wait for a decision; None → settings.approval_wait,
        0 → return immediately. Clamped to [0, 300].
    bypass_scope : str | None
        If "session", add the matched rule pattern to the session's bypass
        list when the approval claim succeeds.
    pool : ConnectionPool
        SSH connection pool.
    guard : CommandGuard
        Security rule evaluator.
    session_mgr : SessionManager
        Session manager for session-based execution.
    db_session_ctx : callable
        Async context manager factory yielding a DB session.
    node_repo_factory : callable
        Factory that accepts a DB session and returns a NodeRepo.
    approval_repo_factory : callable
        Factory that accepts a DB session and returns an ApprovalRepo.
    settings : ShuttleConfig
        Runtime config (approval_ttl, approval_wait).
    ctx : Any
        Optional FastMCP Context — used to emit progress notifications while
        waiting for a decision.

    Returns
    -------
    str
        Command output or a security/error message.
    """
    # -- 1. Resolve target node -----------------------------------------------
    resolved_node: str | None = node

    if resolved_node is None:
        # Auto-select: if exactly one node is registered, use it
        async with db_session_ctx() as db_sess:
            repo = node_repo_factory(db_sess)
            all_nodes = await repo.list_all()
        if len(all_nodes) == 1:
            resolved_node = all_nodes[0].name
        else:
            return (
                "Error: no node specified and cannot auto-select "
                f"(found {len(all_nodes)} nodes). "
                "Provide 'node'."
            )

    # -- 2. Resolve node UUID (needed for approval binding + logging) --------
    node_obj = None
    async with db_session_ctx() as db_sess:
        repo = node_repo_factory(db_sess)
        node_obj = await repo.get_by_name(resolved_node)
    if node_obj is None:
        return f"Error: node '{resolved_node}' not found."
    node_uuid = node_obj.id

    # -- 3. Auto-session: find existing or create -------------------------
    active_sessions = session_mgr.list_active()
    node_session = next(
        (s for s in active_sessions if s.node_id == resolved_node), None
    )
    if node_session:
        session_id = node_session.session_id
        session_obj = node_session
    else:
        try:
            new_session = await session_mgr.create(resolved_node)
            session_id = new_session.session_id
            session_obj = new_session
        except Exception as exc:
            return f"Error: failed to auto-create session — {exc}"

    # -- 4. Security check ----------------------------------------------------
    bypass_patterns = list(session_obj.bypass_patterns) if session_obj else []
    async with db_session_ctx() as db_sess:
        decision = await guard.evaluate(
            command, resolved_node, db_sess, bypass_patterns
        )

    if decision.level == SecurityLevel.BLOCK:
        return f"⛔ Blocked: {decision.message}"

    approval_id_for_log: str | None = None

    if decision.level == SecurityLevel.CONFIRM:
        rule_desc = decision.message
        wait = _effective_wait(approval_wait, settings)

        async with db_session_ctx() as db_sess:
            approval_repo = approval_repo_factory(db_sess)

            if approval_id is None:
                # Create a pending approval and wait (hybrid wait).
                ap = await approval_repo.create(
                    node_id=node_uuid,
                    command=command,
                    session_id=session_id,
                    rule_id=decision.matched_rule,
                    rule_description=rule_desc or None,
                    bypass_scope=bypass_scope,
                    expires_at=datetime.now(UTC)
                    + timedelta(seconds=settings.approval_ttl),
                )
                outcome, ap = await _wait_for_decision(
                    approval_repo, ap, wait, ctx, rule_desc
                )
            else:
                ap = await approval_repo.get(approval_id)
                if ap is None:
                    return f"Error: unknown approval_id '{approval_id}'."
                # Binding: an approval authorizes exactly (command, node_id), byte-exact.
                if ap.command != command:
                    return (
                        f"Error: approval_id '{approval_id}' is bound to a different "
                        f"command. Re-send the original command byte-for-byte, or "
                        f"omit approval_id to create a new approval."
                    )
                if ap.node_id != node_uuid:
                    return (
                        f"Error: approval_id '{approval_id}' is bound to a different "
                        f"node. Omit approval_id to create a new approval."
                    )

                if ap.status == "rejected":
                    return _rejection_message(
                        ap, command, resolved_node, ap.rule_description or rule_desc
                    )
                if ap.status == "executed":
                    return _already_used_message(ap.id)
                if ap.status == "expired" or _utc(ap.expires_at) <= datetime.now(UTC):
                    if ap.status == "pending":
                        await approval_repo.sweep_expired()
                    return _expired_message(ap.id)

                if ap.status == "approved":
                    if not await approval_repo.claim(ap.id):
                        ap = await approval_repo.get(ap.id)
                        if ap.status == "executed":
                            return _already_used_message(ap.id)
                        return _expired_message(ap.id)
                    outcome = "approved"
                else:  # pending
                    outcome, ap = await _wait_for_decision(
                        approval_repo, ap, wait, ctx, rule_desc
                    )

        if outcome == "approved":
            approval_id_for_log = ap.id
        elif outcome == "rejected":
            return _rejection_message(
                ap, command, resolved_node, ap.rule_description or rule_desc
            )
        elif outcome == "already_used":
            return _already_used_message(ap.id)
        elif outcome == "expired":
            return _expired_message(ap.id)
        else:  # timeout — hand the decision back to the AI with a re-call recipe
            return _pending_message(
                ap, command, resolved_node, ap.rule_description or rule_desc
            )

        # Claim succeeded — optionally unlock the pattern for this session.
        # Honor the persisted scope too: the re-call recipe only passes
        # approval_id, so the claim call usually omits bypass_scope.
        effective_scope = bypass_scope or ap.bypass_scope
        if effective_scope == "session" and session_obj and decision.matched_rule:
            async with db_session_ctx() as db_sess:
                from shuttle.db.repository import RuleRepo

                rule_repo = RuleRepo(db_sess)
                matched = await rule_repo.get_by_id(decision.matched_rule)
                if matched:
                    session_obj.bypass_patterns.add(matched.pattern)

    if decision.level == SecurityLevel.WARN:
        logger.warning(
            "WARN rule matched: rule={rule} command={cmd} node={node}",
            rule=decision.matched_rule,
            cmd=command,
            node=resolved_node,
        )

    # -- 6. Execute via session -----------------------------------------------
    t0 = time.monotonic()
    try:
        result = await session_mgr.execute(session_id, command, timeout=timeout)
        stdout = result.get("stdout", "")
        exit_status = result.get("exit_status")
    except Exception as exc:
        stdout = f"[ERROR] {exc}"
        exit_status = -1
        result = {"stdout": stdout, "exit_status": exit_status}
    duration_ms = int((time.monotonic() - t0) * 1000)

    # -- 7. Persist command log to DB -----------------------------------------
    # Single audit point: every execution path records its log here.
    try:
        db_stdout = _truncate(stdout, MAX_DB_OUTPUT_BYTES) if stdout else None
        db_stderr = _truncate(result.get("stderr", ""), MAX_DB_OUTPUT_BYTES) or None
        # bypassed=True only for real bypass paths: an approval claim or a
        # session bypass pattern that let a confirm/warn match through.
        bypassed = approval_id_for_log is not None or _session_bypass_matched(
            command, bypass_patterns
        )
        async with db_session_ctx() as db_sess:
            from shuttle.db.repository import LogRepo

            log_repo = LogRepo(db_sess)
            await log_repo.create(
                node_id=node_uuid,
                session_id=session_id,
                command=command,
                exit_code=exit_status,
                stdout=db_stdout,
                stderr=db_stderr,
                security_level=decision.level.value if decision else None,
                security_rule_id=decision.matched_rule if decision else None,
                bypassed=bypassed,
                duration_ms=duration_ms,
                approval_id=approval_id_for_log,
            )

        # Back-fill the approval's exit code (best-effort).
        if approval_id_for_log is not None:
            async with db_session_ctx() as db_sess:
                approval_repo = approval_repo_factory(db_sess)
                await approval_repo.set_exec_result(approval_id_for_log, exit_status)

        # Update node last_seen_at
        async with db_session_ctx() as db_sess:
            repo = node_repo_factory(db_sess)
            await repo.update(
                node_obj.id,
                last_seen_at=datetime.now(UTC),
                status="active",
            )
    except Exception:
        logger.warning(f"Failed to persist command log for {command[:80]}")

    return stdout


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_tools(
    mcp: Any,
    pool: Any,
    guard: CommandGuard,
    session_mgr: SessionManager,
    db_session_ctx: Callable,
    node_repo_factory: Callable,
    approval_repo_factory: Callable,
    settings: Any,
    cred_mgr: Any = None,
) -> None:
    """Register all Shuttle MCP tools on the given FastMCP instance.

    Parameters
    ----------
    mcp : FastMCP
        The FastMCP server to register tools on.
    pool : ConnectionPool
        SSH connection pool.
    guard : CommandGuard
        Security evaluator.
    session_mgr : SessionManager
        Session manager.
    db_session_ctx : callable
        Async context manager factory yielding a DB AsyncSession.
    node_repo_factory : callable
        Factory accepting a DB session and returning a NodeRepo.
    approval_repo_factory : callable
        Factory accepting a DB session and returning an ApprovalRepo.
    settings : ShuttleConfig
        Runtime configuration (approval TTL / wait defaults).
    cred_mgr : CredentialManager | None
        Credential manager for encrypting node credentials.
    """

    # -- ssh_run --------------------------------------------------------------
    @mcp.tool()
    async def ssh_run(
        command: str,
        node: str | None = None,
        timeout: float = 30.0,
        approval_id: str | None = None,
        approval_wait: float | None = None,
        bypass_scope: str | None = None,
        ctx: Context = None,
    ) -> str:
        """Execute a shell command on a remote SSH node.

        Sessions are managed automatically: working directory is preserved
        across calls to the same node. Security checks (BLOCK / CONFIRM /
        WARN / ALLOW) are applied before execution.

        CONFIRM-level commands require human approval in the Shuttle web
        panel: the first call returns a pending message with an approval_id;
        re-call with the SAME command byte-for-byte plus that approval_id to
        pick up the decision. approval_wait caps the synchronous wait in
        seconds (0 returns immediately; progress-capable clients wait up to
        the approval TTL).
        """
        return await _execute_command_logic(
            command=command,
            node=node,
            timeout=timeout,
            approval_id=approval_id,
            approval_wait=approval_wait,
            bypass_scope=bypass_scope,
            pool=pool,
            guard=guard,
            session_mgr=session_mgr,
            db_session_ctx=db_session_ctx,
            node_repo_factory=node_repo_factory,
            approval_repo_factory=approval_repo_factory,
            settings=settings,
            ctx=ctx,
        )

    # -- ssh_upload -----------------------------------------------------------
    @mcp.tool()
    async def ssh_upload(
        node: str,
        local_path: str,
        remote_path: str,
    ) -> str:
        """Upload a file to a remote node via SFTP."""
        try:
            async with pool.connection(node) as pc:
                async with pc.conn.start_sftp_client() as sftp:
                    await sftp.put(local_path, remote_path)
            return f"OK: {local_path} → {node}:{remote_path}"
        except Exception as exc:
            return f"Error: {exc}"

    # -- ssh_download ---------------------------------------------------------
    @mcp.tool()
    async def ssh_download(
        node: str,
        remote_path: str,
        local_path: str,
    ) -> str:
        """Download a file from a remote node via SFTP."""
        try:
            async with pool.connection(node) as pc:
                async with pc.conn.start_sftp_client() as sftp:
                    await sftp.get(remote_path, local_path)
            return f"OK: {node}:{remote_path} → {local_path}"
        except Exception as exc:
            return f"Error: {exc}"

    # -- ssh_add_node ---------------------------------------------------------
    @mcp.tool()
    async def ssh_add_node(
        name: str,
        host: str,
        private_key_path: str,
        port: int = 22,
        username: str = "",
        jump_host: str | None = None,
        tags: list[str] | None = None,
    ) -> str:
        """Add a new SSH node to the Shuttle configuration (key auth only).

        Inline secrets are not accepted: private_key_path must point to a key
        file on the machine running Shuttle (e.g. ~/.ssh/id_ed25519). Shuttle
        reads it locally, so key material never appears in this conversation.
        """
        from shuttle.core.proxy import NodeConnectInfo

        if cred_mgr is None:
            return (
                "Error: credential manager not available — cannot encrypt credentials."
            )

        # Read the key locally so the agent never handles key content.
        key_file = Path(private_key_path).expanduser()
        if not key_file.is_file():
            return f"Error: key file not found: {key_file}"
        plaintext = key_file.read_text()
        if "PRIVATE KEY-----" not in plaintext:
            return f"Error: {key_file} does not look like an SSH private key"
        encrypted = cred_mgr.encrypt(plaintext)

        # Resolve jump_host name to UUID if provided
        jump_host_id: str | None = None
        if jump_host is not None:
            async with db_session_ctx() as db_sess:
                repo = node_repo_factory(db_sess)
                jh = await repo.get_by_name(jump_host)
            if jh is None:
                return f"Error: jump host '{jump_host}' not found."
            jump_host_id = jh.id

        # Check for duplicate name
        async with db_session_ctx() as db_sess:
            repo = node_repo_factory(db_sess)
            existing = await repo.get_by_name(name)
        if existing is not None:
            return f"Error: node '{name}' already exists."

        # Create node in DB
        async with db_session_ctx() as db_sess:
            repo = node_repo_factory(db_sess)
            await repo.create(
                name=name,
                host=host,
                port=port,
                username=username,
                auth_type="key",
                encrypted_credential=encrypted,
                jump_host_id=jump_host_id,
                tags=tags,
            )

        # Resolve jump host connection info if present
        jump_host_info: NodeConnectInfo | None = None
        if jump_host_id is not None:
            async with db_session_ctx() as db_sess:
                repo = node_repo_factory(db_sess)
                jh_node = await repo.get_by_id(jump_host_id)
            if jh_node is not None and jh_node.encrypted_credential and cred_mgr:
                jh_decrypted = cred_mgr.decrypt(jh_node.encrypted_credential)
                jump_host_info = NodeConnectInfo(
                    node_id=jh_node.name,
                    hostname=jh_node.host,
                    port=jh_node.port,
                    username=jh_node.username,
                    password=jh_decrypted if jh_node.auth_type == "password" else None,
                    private_key=jh_decrypted if jh_node.auth_type == "key" else None,
                )

        # Register in connection pool
        info = NodeConnectInfo(
            node_id=name,
            hostname=host,
            port=port,
            username=username,
            password=None,
            private_key=plaintext,
            jump_host=jump_host_info,
        )
        pool.register_node(info)

        return f"OK: node '{name}' added ({host}:{port}, user={username})"
