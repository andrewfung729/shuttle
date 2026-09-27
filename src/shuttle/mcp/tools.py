"""MCP tool registrations for the Shuttle SSH gateway.

Provides ``register_tools()`` which wires up four tools on a FastMCP instance:
ssh_run, ssh_upload, ssh_download, ssh_add_node. (Node listing is exposed
via the ``shuttle://nodes`` resource, not a tool.)

Sessions are managed implicitly: ``ssh_run`` auto-creates or reuses a session
per node so that working directory context is preserved across calls.

Every command runs through CommandGuard first. ``block`` denies, ``allow``
executes, and unmatched commands go to the LLM gate: confident-safe scores
execute, clearly-unsafe scores deny, and the uncertain band parks a Hold
(see ``shuttle.core.holds``) for one Operator decision. The caller receives
one of three strings — stdout, ``Error: denied by policy`` (replan), or
``Error: awaiting operator`` (retry the identical command). Scores, band
names, rule text, and Hold ids never reach the caller.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from fastmcp import Context
from loguru import logger

from shuttle.core.gate import GatePort
from shuttle.core.holds import (
    AWAITING_MESSAGE,
    DEFAULT_COMMAND_TIMEOUT,
    DENIED_MESSAGE,
    Execution,
    HoldManager,
    client_id,
    conversation_key,
    truncate_output,
)
from shuttle.core.security import CommandGuard, SecurityLevel
from shuttle.core.session import SessionManager

__all__ = [
    "AWAITING_MESSAGE",
    "DENIED_MESSAGE",
    "build_hold_executor",
    "register_tools",
]

# Truncation limits
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB for caller output
MAX_DB_OUTPUT_BYTES = 64 * 1024  # 64 KB for DB storage


# ---------------------------------------------------------------------------
# Core execution logic (extracted for testability)
# ---------------------------------------------------------------------------


async def _log_denial(
    db_session_ctx: Callable[..., AsyncIterator],
    *,
    node_uuid: str,
    session_id: str | None,
    command: str,
    decision: Any,
    gate_score: float | None,
    gate_reason: str | None,
    conversation_key: str | None = None,
) -> None:
    """Persist a denial row (best-effort — a logging failure never changes
    the denial itself)."""
    try:
        async with db_session_ctx() as db_sess:
            from shuttle.db.repository import LogRepo

            await LogRepo(db_sess).create(
                node_id=node_uuid,
                session_id=session_id,
                command=command,
                exit_code=None,
                security_level=decision.level.value,
                security_rule_id=decision.matched_rule,
                conversation_key=conversation_key,
                gate_score=gate_score,
                gate_reason=gate_reason,
            )
    except Exception:
        logger.warning("Failed to persist denial log for {cmd}", cmd=command[:80])


async def _persist_execution_log(
    db_session_ctx: Callable[..., AsyncIterator],
    *,
    node_id: str,
    session_id: str | None,
    command: str,
    exit_code: int | None,
    stdout: str,
    stderr: str,
    security_level: str | None,
    security_rule_id: str | None,
    conversation_key: str | None,
    gate_score: float | None,
    gate_reason: str | None,
    duration_ms: int,
) -> None:
    """Write exactly one execution audit row (best-effort).

    Used by every execution path, including a failed session attempt, so the
    ledger records the disposition even when the command never ran.
    """
    try:
        db_stdout = truncate_output(stdout, MAX_DB_OUTPUT_BYTES) if stdout else None
        db_stderr = truncate_output(stderr, MAX_DB_OUTPUT_BYTES) if stderr else None
        async with db_session_ctx() as db_sess:
            from shuttle.db.repository import LogRepo

            await LogRepo(db_sess).create(
                node_id=node_id,
                session_id=session_id,
                command=command,
                exit_code=exit_code,
                stdout=db_stdout,
                stderr=db_stderr,
                security_level=security_level,
                security_rule_id=security_rule_id,
                conversation_key=conversation_key,
                gate_score=gate_score,
                gate_reason=gate_reason,
                duration_ms=duration_ms,
            )
    except Exception:
        logger.warning("Failed to persist command log for {cmd}", cmd=command[:80])


async def _run_and_log(
    *,
    node: str,
    node_id: str,
    command: str,
    timeout: float,
    security_level: str | None,
    security_rule_id: str | None,
    gate_score: float | None,
    gate_reason: str | None,
    conversation_key: str | None,
    session_mgr: SessionManager,
    db_session_ctx: Callable[..., AsyncIterator],
    node_repo_factory: Callable,
) -> Execution:
    """Run one command via an SSH session and record exactly one audit row.

    Reuses the node's active session when present, else creates one. Returns
    the stdout (or the existing ``[ERROR]`` text) plus exit code.
    """
    t0 = time.monotonic()

    active_sessions = session_mgr.list_active()
    node_session = next((s for s in active_sessions if s.node_id == node), None)
    if node_session is not None:
        session_id = node_session.session_id
    else:
        session_id = None
        try:
            new_session = await session_mgr.create(node)
            session_id = new_session.session_id
        except Exception as exc:
            # The attempt is still audited, and the node is *not* marked seen.
            stdout = f"Error: failed to auto-create session — {exc}"
            await _persist_execution_log(
                db_session_ctx,
                node_id=node_id,
                session_id=None,
                command=command,
                exit_code=-1,
                stdout=stdout,
                stderr=str(exc),
                security_level=security_level,
                security_rule_id=security_rule_id,
                conversation_key=conversation_key,
                gate_score=gate_score,
                gate_reason=gate_reason,
                duration_ms=int((time.monotonic() - t0) * 1000),
            )
            return Execution(stdout=stdout, exit_code=-1)

    try:
        result = await session_mgr.execute(session_id, command, timeout=timeout)
        stdout = result.get("stdout", "")
        stderr = result.get("stderr", "")
        exit_status = result.get("exit_status")
    except Exception as exc:
        stdout = f"[ERROR] {exc}"
        stderr = str(exc)
        exit_status = -1
    duration_ms = int((time.monotonic() - t0) * 1000)

    # Single audit point: every execution path records its log here.
    await _persist_execution_log(
        db_session_ctx,
        node_id=node_id,
        session_id=session_id,
        command=command,
        exit_code=exit_status,
        stdout=stdout,
        stderr=stderr,
        security_level=security_level,
        security_rule_id=security_rule_id,
        conversation_key=conversation_key,
        gate_score=gate_score,
        gate_reason=gate_reason,
        duration_ms=duration_ms,
    )

    # A session that opened and ran marks the node seen; a failed attempt does not.
    try:
        async with db_session_ctx() as db_sess:
            repo = node_repo_factory(db_sess)
            await repo.update(
                node_id,
                last_seen_at=datetime.now(UTC),
                status="active",
            )
    except Exception:
        logger.warning("Failed to update node last_seen_at for {node}", node=node)

    return Execution(stdout=stdout, exit_code=exit_status)


def build_hold_executor(
    *,
    session_mgr: SessionManager,
    db_session_ctx: Callable[..., AsyncIterator],
    node_repo_factory: Callable,
    timeout: float = DEFAULT_COMMAND_TIMEOUT,
) -> Callable[..., Any]:
    """Build the server-owned executor used for a run-once Hold decision.

    Resolves the node id back to a name, runs the exact command, and records
    the execution in CommandLog with ``gate_reason="once"``.
    """

    async def _execute_once(
        *,
        node_id: str,
        command: str,
        gate_score: float | None = None,
        conversation_key: str | None = None,
    ) -> Execution:
        async with db_session_ctx() as db_sess:
            node = await node_repo_factory(db_sess).get_by_id(node_id)
        node_name = node.name if node is not None else node_id
        return await _run_and_log(
            node=node_name,
            node_id=node_id,
            command=command,
            timeout=timeout,
            security_level=SecurityLevel.GATE.value,
            security_rule_id=None,
            gate_score=gate_score,
            gate_reason="once",
            conversation_key=conversation_key,
            session_mgr=session_mgr,
            db_session_ctx=db_session_ctx,
            node_repo_factory=node_repo_factory,
        )

    return _execute_once


async def _execute_command_logic(
    *,
    command: str,
    node: str | None,
    timeout: float,
    guard: CommandGuard,
    holds: HoldManager,
    session_mgr: SessionManager,
    db_session_ctx: Callable[..., AsyncIterator],
    node_repo_factory: Callable,
    conversation_key: str,
    client_id: str | None = None,
) -> str:
    """Execute a command with security checks, node resolution, and DB logging.

    Block rules deny; allow rules execute; unmatched commands go to the Hold
    seam, which scores with the LLM gate and either lets the caller execute,
    denies, or parks/waits on a Hold. Security comes before any session work:
    a denied command never opens an SSH session.

    Returns the command output or one of the fixed agent-visible strings.
    """
    # -- 1. Resolve target node ------------------------------------------------
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

    # -- 2. Resolve node UUID (needed for logging) ------------------------------
    async with db_session_ctx() as db_sess:
        repo = node_repo_factory(db_sess)
        node_obj = await repo.get_by_name(resolved_node)
    if node_obj is None:
        return f"Error: node '{resolved_node}' not found."
    node_uuid = node_obj.id

    # -- 3. Resolve the session without opening one ------------------------------
    # Denied commands never create SSH sessions; reuse an existing one for
    # the audit trail when present.
    active_sessions = session_mgr.list_active()
    node_session = next(
        (s for s in active_sessions if s.node_id == resolved_node), None
    )
    session_id = node_session.session_id if node_session else None

    # -- 4. Security check ---------------------------------------------------------
    async with db_session_ctx() as db_sess:
        decision = await guard.evaluate(command, resolved_node, db_sess)

    if decision.level == SecurityLevel.BLOCK:
        await _log_denial(
            db_session_ctx,
            node_uuid=node_uuid,
            session_id=session_id,
            command=command,
            decision=decision,
            gate_score=None,
            gate_reason=None,
            conversation_key=conversation_key,
        )
        return DENIED_MESSAGE

    if decision.level == SecurityLevel.ALLOW:
        execution = await _run_and_log(
            node=resolved_node,
            node_id=node_uuid,
            command=command,
            timeout=timeout,
            security_level=SecurityLevel.ALLOW.value,
            security_rule_id=decision.matched_rule,
            gate_score=None,
            gate_reason=None,
            conversation_key=conversation_key,
            session_mgr=session_mgr,
            db_session_ctx=db_session_ctx,
            node_repo_factory=node_repo_factory,
        )
        return execution.stdout

    # -- 5. Unmatched: Hold seam (gate + bands + bounded wait) --------------------
    outcome = await holds.triage(
        command=command,
        node=resolved_node,
        node_id=node_uuid,
        conversation_key=conversation_key,
        client_id=client_id,
        session_id=session_id,
        matched_rule=decision.matched_rule,
    )
    if not outcome.execute:
        return outcome.text if outcome.text is not None else DENIED_MESSAGE

    execution = await _run_and_log(
        node=resolved_node,
        node_id=node_uuid,
        command=command,
        timeout=timeout,
        security_level=SecurityLevel.GATE.value,
        security_rule_id=decision.matched_rule,
        gate_score=outcome.gate_score,
        gate_reason=None,
        conversation_key=conversation_key,
        session_mgr=session_mgr,
        db_session_ctx=db_session_ctx,
        node_repo_factory=node_repo_factory,
    )
    return execution.stdout


# ---------------------------------------------------------------------------
# Tool registration
# ---------------------------------------------------------------------------


def register_tools(
    mcp: Any,
    pool: Any,
    guard: CommandGuard,
    gate: GatePort | None,
    session_mgr: SessionManager,
    db_session_ctx: Callable,
    node_repo_factory: Callable,
    settings: Any = None,
    cred_mgr: Any = None,
    holds: HoldManager | None = None,
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
    gate : GatePort | None
        LLM gate for unmatched commands (None denies as disabled).
    session_mgr : SessionManager
        Session manager.
    db_session_ctx : callable
        Async context manager factory yielding a DB AsyncSession.
    node_repo_factory : callable
        Factory accepting a DB session and returning a NodeRepo.
    settings : ShuttleConfig
        Runtime configuration (gate_enabled, openrouter_api_key,
        gate_safe_instructions).
    cred_mgr : CredentialManager | None
        Credential manager for encrypting node credentials.
    holds : HoldManager | None
        The Hold seam. Built from the other arguments when omitted.
    """
    if holds is None:
        holds = HoldManager(
            db_session_ctx=db_session_ctx,
            gate=gate,
            settings=settings,
            executor=build_hold_executor(
                session_mgr=session_mgr,
                db_session_ctx=db_session_ctx,
                node_repo_factory=node_repo_factory,
            ),
        )

    # -- ssh_run --------------------------------------------------------------
    @mcp.tool()
    async def ssh_run(
        command: str,
        node: str | None = None,
        timeout: float = DEFAULT_COMMAND_TIMEOUT,
        ctx: Context | None = None,
    ) -> str:
        """Execute a shell command on a remote SSH node.

        Sessions are managed automatically: working directory is preserved
        across calls to the same node. Every command is checked against
        Security Rules first.

        The result is one of three shapes. Command output means it ran.
        ``Error: denied by policy`` means the command was refused — replan,
        and do not probe with variants. ``Error: awaiting operator`` means an
        operator may still allow this exact command — retry the identical
        command later. A denial may add an operator note after the prefix.
        """
        return await _execute_command_logic(
            command=command,
            node=node,
            timeout=timeout,
            guard=guard,
            holds=holds,
            session_mgr=session_mgr,
            db_session_ctx=db_session_ctx,
            node_repo_factory=node_repo_factory,
            conversation_key=conversation_key(ctx),
            client_id=client_id(ctx),
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
