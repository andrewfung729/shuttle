"""MCP tool registrations for the Shuttle SSH gateway.

Provides ``register_tools()`` which wires up four tools on a FastMCP instance:
ssh_run, ssh_upload, ssh_download, ssh_add_node. (Node listing is exposed
via the ``shuttle://nodes`` resource, not a tool.)

Sessions are managed implicitly: ``ssh_run`` auto-creates or reuses a session
per node so that working directory context is preserved across calls.

Every command runs through CommandGuard first. ``block`` and ``review``
matches are denied with one fixed error string — no scores, rule text, or
retry instructions ever reach the caller.
"""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from loguru import logger

from shuttle.core.gate import SAFE_THRESHOLD, GatePort
from shuttle.core.security import CommandGuard, SecurityLevel
from shuttle.core.session import SessionManager

# Truncation limits
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB for caller output
MAX_DB_OUTPUT_BYTES = 64 * 1024  # 64 KB for DB storage

# The only agent-visible denial string. Every denial path (block rule, gate
# verdict, gate error, gate disabled) returns exactly this.
DENIED_MESSAGE = "Error: denied by policy"


def _truncate(text: str, limit: int) -> str:
    """Truncate *text* to *limit* bytes (UTF-8), appending a marker if truncated."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="replace") + "\n... [truncated]"


# ---------------------------------------------------------------------------
# Core execution logic (extracted for testability)
# ---------------------------------------------------------------------------


def _gate_ready(gate: GatePort | None, settings: Any) -> bool:
    """True when the gate is wired, enabled, and has an API key.

    Call-time twin of server._build_gate's construction-time predicate —
    keep the two in sync: the server skips constructing a gate when the
    config is off/unkeyed, this re-checks at the seam so a stub or a
    config flip can never enable a call by accident.
    """
    return (
        gate is not None
        and bool(getattr(settings, "gate_enabled", False))
        and bool(getattr(settings, "openrouter_api_key", None))
    )


async def _log_denial(
    db_session_ctx: Callable[..., AsyncIterator],
    *,
    node_uuid: str,
    session_id: str | None,
    command: str,
    decision: Any,
    gate_score: float | None,
    gate_reason: str | None,
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
                gate_score=gate_score,
                gate_reason=gate_reason,
            )
    except Exception:
        logger.warning("Failed to persist denial log for {cmd}", cmd=command[:80])


async def _execute_command_logic(
    *,
    command: str,
    node: str | None,
    timeout: float,
    guard: CommandGuard,
    gate: GatePort | None,
    session_mgr: SessionManager,
    db_session_ctx: Callable[..., AsyncIterator],
    node_repo_factory: Callable,
    settings: Any = None,
) -> str:
    """Execute a command with security checks, node resolution, and DB logging.

    Security comes before any session work: a denied command never opens an
    SSH session. Review-level commands are scored by the injected gate when
    it is enabled; scores at or above ``SAFE_THRESHOLD`` execute, everything
    else (below threshold, gate failure, disabled gate) is denied and logged.

    Returns the command output or a security/error message. Every security
    denial is the fixed string ``DENIED_MESSAGE``.
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

    gate_score: float | None = None
    gate_reason: str | None = None

    if decision.level == SecurityLevel.REVIEW and _gate_ready(gate, settings):
        try:
            gate_score = await gate.is_safe(
                state={"command": command, "node": resolved_node},
                instructions=settings.gate_safe_instructions,
            )
        except Exception:
            gate_score = None
            gate_reason = "error"
        else:
            if gate_score < SAFE_THRESHOLD:
                gate_reason = "unsafe"
    elif decision.level == SecurityLevel.REVIEW:
        gate_reason = "disabled"

    if decision.level == SecurityLevel.BLOCK or gate_reason is not None:
        await _log_denial(
            db_session_ctx,
            node_uuid=node_uuid,
            session_id=session_id,
            command=command,
            decision=decision,
            gate_score=gate_score,
            gate_reason=gate_reason,
        )
        return DENIED_MESSAGE

    # -- 5. Execute via session ---------------------------------------------------
    if node_session:
        session_id = node_session.session_id
    else:
        try:
            new_session = await session_mgr.create(resolved_node)
            session_id = new_session.session_id
        except Exception as exc:
            return f"Error: failed to auto-create session — {exc}"

    # -- 5. Execute via session ---------------------------------------------------
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

    # -- 6. Persist command log to DB ---------------------------------------------
    # Single audit point: every execution path records its log here.
    try:
        db_stdout = _truncate(stdout, MAX_DB_OUTPUT_BYTES) if stdout else None
        db_stderr = _truncate(result.get("stderr", ""), MAX_DB_OUTPUT_BYTES) or None
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
                gate_score=gate_score,
                duration_ms=duration_ms,
            )

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
    gate: GatePort | None,
    session_mgr: SessionManager,
    db_session_ctx: Callable,
    node_repo_factory: Callable,
    settings: Any = None,
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
    gate : GatePort | None
        LLM gate for review-level commands (None denies review as disabled).
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
    """

    # -- ssh_run --------------------------------------------------------------
    @mcp.tool()
    async def ssh_run(
        command: str,
        node: str | None = None,
        timeout: float = 30.0,
    ) -> str:
        """Execute a shell command on a remote SSH node.

        Sessions are managed automatically: working directory is preserved
        across calls to the same node. Every command is checked against
        Security Rules first; commands that do not pass are denied with a
        fixed error string and never execute.
        """
        return await _execute_command_logic(
            command=command,
            node=node,
            timeout=timeout,
            guard=guard,
            gate=gate,
            session_mgr=session_mgr,
            db_session_ctx=db_session_ctx,
            node_repo_factory=node_repo_factory,
            settings=settings,
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
