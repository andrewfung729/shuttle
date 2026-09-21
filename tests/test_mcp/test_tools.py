"""Tests for shuttle.mcp.tools — _execute_command_logic unit tests.

Covers the block / gate / allow decision matrix at the command
orchestration seam — including the LLM-gate branches — auto-session
handling, DB logging, and error paths. The gate is always a stub: tests
never hit the real endpoint.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from shuttle.core.security import CommandGuard, SecurityDecision, SecurityLevel
from shuttle.core.session import SessionManager, SSHSession
from shuttle.mcp.tools import DENIED_MESSAGE, _execute_command_logic

SAFE_THRESHOLD = 0.9  # mirrored from shuttle.core.gate


class StubGate:
    """In-memory GatePort stub."""

    def __init__(self, score=None, error=None):
        self.score = score
        self.error = error
        self.calls: list[dict] = []

    async def is_safe(self, state, instructions):
        self.calls.append({"state": state, "instructions": instructions})
        if self.error is not None:
            raise self.error
        return self.score


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_guard(level: SecurityLevel, message: str = "", rule: str = "test-rule"):
    """Return a CommandGuard mock that always returns the given decision."""
    guard = MagicMock(spec=CommandGuard)
    guard.evaluate = AsyncMock(
        return_value=SecurityDecision(level=level, matched_rule=rule, message=message)
    )
    return guard


def _make_session_mgr(session: SSHSession | None = None, execute_result=None):
    mgr = MagicMock(spec=SessionManager)
    mgr.get.return_value = session
    if execute_result is not None:
        mgr.execute = AsyncMock(return_value=execute_result)
    else:
        mgr.execute = AsyncMock(
            return_value={
                "stdout": "ok",
                "exit_status": 0,
                "working_directory": "/home/user",
            }
        )
    # Return the session in list_active so auto-session finds it
    mgr.list_active.return_value = [session] if session else []
    mgr.create = AsyncMock(return_value=session)
    return mgr


@asynccontextmanager
async def _noop_db_session():
    yield MagicMock()


def _node_repo_factory(db_sess):
    repo = MagicMock()
    _node = MagicMock()
    _node.id = "fake-uuid-0001"
    _node.name = "n1"
    repo.get_by_name = AsyncMock(return_value=_node)
    repo.list_all = AsyncMock(return_value=[])
    repo.update = AsyncMock()
    return repo


async def _run(
    guard,
    session_mgr,
    *,
    command="echo hi",
    node="n1",
    node_repo_factory=_node_repo_factory,
    timeout=10,
    gate=None,
    settings=None,
):
    return await _execute_command_logic(
        command=command,
        node=node,
        timeout=timeout,
        guard=guard,
        gate=gate,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=node_repo_factory,
        settings=settings,
    )


# ---------------------------------------------------------------------------
# Decision matrix
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allowed_command_executes():
    """When guard returns ALLOW, the command executes via session_mgr."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    session_mgr = _make_session_mgr(
        session,
        execute_result={
            "stdout": "hello world",
            "exit_status": 0,
            "working_directory": "/tmp",
        },
    )

    result = await _run(guard, session_mgr, command="echo hello")

    assert result == "hello world"
    session_mgr.execute.assert_awaited_once_with("s1", "echo hello", timeout=10)


@pytest.mark.asyncio
async def test_no_rule_match_defaults_to_gate_and_needs_gate():
    """Unmatched commands are GATE: execute only when the gate scores safe."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE, message="", rule=None)
    session_mgr = _make_session_mgr(session)
    gate = StubGate(score=0.99)

    result = await _run(
        guard,
        session_mgr,
        command="uptime",
        gate=gate,
        settings=_gate_settings(),
    )

    assert result == "ok"
    assert len(gate.calls) == 1


@pytest.mark.asyncio
async def test_blocked_command_returns_fixed_denial():
    """BLOCK: exact fixed string, no execution, no rule detail leaked."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.BLOCK, message="rm is forbidden")
    session_mgr = _make_session_mgr(session)
    gate = StubGate(score=0.99)

    result = await _run(
        guard, session_mgr, command="rm -rf /", gate=gate, settings=_gate_settings()
    )

    assert result == "Error: denied by policy"
    assert result == DENIED_MESSAGE
    assert gate.calls == []  # block rules never depend on the gate
    session_mgr.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_gate_command_returns_fixed_denial():
    """GATE without a gate: exact fixed string, no execution."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE, message="sudo")
    session_mgr = _make_session_mgr(session)

    result = await _run(guard, session_mgr, command="sudo ls")

    assert result == "Error: denied by policy"
    session_mgr.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# LLM gate matrix (gated commands)
# ---------------------------------------------------------------------------


def _gate_settings(enabled=True, key="sk-or-test"):
    return SimpleNamespace(
        gate_enabled=enabled,
        openrouter_api_key=key,
        gate_safe_instructions="Decide if the command is safe.",
    )


@pytest.mark.asyncio
async def test_gate_safe_score_executes():
    """gate disposition + gate on + score >= threshold -> executes."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(session)
    gate = StubGate(score=SAFE_THRESHOLD)

    result = await _run(
        guard,
        mgr,
        command="sudo systemctl status nginx",
        gate=gate,
        settings=_gate_settings(),
    )

    assert result == "ok"
    assert len(gate.calls) == 1
    assert gate.calls[0]["state"] == {
        "command": "sudo systemctl status nginx",
        "node": "n1",
    }
    assert gate.calls[0]["instructions"] == "Decide if the command is safe."


@pytest.mark.asyncio
async def test_gate_unsafe_score_denies_and_logs():
    """gate + score < threshold -> fixed denial, log row with score + unsafe."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(session)
    gate = StubGate(score=0.42)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(
            guard, mgr, command="sudo rm -rf /var", gate=gate, settings=_gate_settings()
        )

    assert result == DENIED_MESSAGE
    mgr.execute.assert_not_awaited()
    mock_log_repo.create.assert_awaited_once()
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["gate_score"] == 0.42
    assert kwargs["gate_reason"] == "unsafe"
    assert kwargs["security_level"] == "gate"
    assert kwargs["exit_code"] is None


@pytest.mark.asyncio
async def test_gate_error_denies_and_logs_error():
    """Gate exception/timeout -> fixed denial, log row reason=error, no score."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(error=TimeoutError("gate timed out"))

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(guard, mgr, gate=gate, settings=_gate_settings())

    assert result == DENIED_MESSAGE
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["gate_score"] is None
    assert kwargs["gate_reason"] == "error"


@pytest.mark.asyncio
async def test_gate_disabled_denies_and_logs_disabled():
    """gate_enabled=false -> fixed denial, log row reason=disabled, no gate call."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.99)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(
            guard, mgr, gate=gate, settings=_gate_settings(enabled=False)
        )

    assert result == DENIED_MESSAGE
    assert gate.calls == []  # never called
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["gate_reason"] == "disabled"
    assert kwargs["gate_score"] is None


@pytest.mark.asyncio
async def test_gate_missing_key_denies():
    """Enabled gate but no API key -> disabled denial (fail closed)."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.99)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(guard, mgr, gate=gate, settings=_gate_settings(key=None))

    assert result == DENIED_MESSAGE
    assert gate.calls == []
    assert mock_log_repo.create.call_args.kwargs["gate_reason"] == "disabled"


@pytest.mark.asyncio
async def test_gate_none_denies_disabled():
    """No gate wired at all (server construction skipped it) -> disabled."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(guard, mgr, gate=None, settings=_gate_settings())

    assert result == DENIED_MESSAGE
    assert mock_log_repo.create.call_args.kwargs["gate_reason"] == "disabled"


@pytest.mark.asyncio
async def test_block_denies_and_logs_without_gate_call():
    """block -> fixed denial + log row; the gate is never consulted."""
    guard = _make_guard(SecurityLevel.BLOCK)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.99)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(guard, mgr, gate=gate, settings=_gate_settings())

    assert result == DENIED_MESSAGE
    assert gate.calls == []
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["security_level"] == "block"
    assert kwargs["gate_reason"] is None
    assert kwargs["gate_score"] is None


@pytest.mark.asyncio
async def test_gate_safe_logs_score_on_executed_row():
    """An executed gated command records its passing gate score."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(session)
    gate = StubGate(score=0.97)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        await _run(guard, mgr, gate=gate, settings=_gate_settings())

    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["gate_score"] == 0.97
    assert kwargs.get("gate_reason") is None
    assert kwargs["exit_code"] == 0


@pytest.mark.asyncio
async def test_denial_still_returned_when_denial_log_fails():
    """A denial-log DB failure must not turn a denial into anything else."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.1)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock(side_effect=RuntimeError("DB down"))

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(guard, mgr, gate=gate, settings=_gate_settings())

    assert result == DENIED_MESSAGE


@pytest.mark.asyncio
async def test_denial_does_not_create_session():
    """A denied command must not open an SSH session just to be refused."""
    guard = _make_guard(SecurityLevel.GATE)
    session_mgr = _make_session_mgr(None)

    await _run(guard, session_mgr, command="sudo ls")

    session_mgr.create.assert_not_awaited()
    session_mgr.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# Node resolution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_no_node_and_multiple_nodes_errors():
    guard = _make_guard(SecurityLevel.ALLOW)
    repo = MagicMock()
    n1, n2 = MagicMock(), MagicMock()
    repo.list_all = AsyncMock(return_value=[n1, n2])

    out = await _run(
        guard, _make_session_mgr(), node=None, node_repo_factory=lambda _s: repo
    )
    assert "cannot auto-select" in out


@pytest.mark.asyncio
async def test_unknown_node_errors():
    guard = _make_guard(SecurityLevel.ALLOW)
    repo = MagicMock()
    repo.get_by_name = AsyncMock(return_value=None)
    repo.list_all = AsyncMock(return_value=[])

    out = await _run(
        guard, _make_session_mgr(), node="ghost", node_repo_factory=lambda _s: repo
    )
    assert "not found" in out


# ---------------------------------------------------------------------------
# Auto-session handling
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_implicit_session_created_when_none_exists():
    new_session = SSHSession(session_id="auto-1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    session_mgr = MagicMock(spec=SessionManager)
    session_mgr.list_active.return_value = []
    session_mgr.create = AsyncMock(return_value=new_session)
    session_mgr.execute = AsyncMock(
        return_value={"stdout": "created", "exit_status": 0, "working_directory": "/"}
    )

    result = await _run(guard, session_mgr, command="pwd")

    session_mgr.create.assert_awaited_once_with("n1")
    assert result == "created"


@pytest.mark.asyncio
async def test_implicit_session_reused_across_calls():
    session = SSHSession(session_id="reuse-1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    session_mgr = MagicMock(spec=SessionManager)
    session_mgr.list_active.return_value = [session]
    session_mgr.create = AsyncMock()  # should NOT be called
    session_mgr.execute = AsyncMock(
        return_value={
            "stdout": "/workspace",
            "exit_status": 0,
            "working_directory": "/workspace",
        }
    )

    await _run(guard, session_mgr, command="cd /workspace")
    result = await _run(guard, session_mgr, command="pwd")

    session_mgr.create.assert_not_awaited()
    calls = session_mgr.execute.call_args_list
    assert all(c.args[0] == "reuse-1" for c in calls)
    assert result == "/workspace"


# ---------------------------------------------------------------------------
# DB logging
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_persists_command_log_to_db():
    """After successful execution, LogRepo.create is called with correct fields."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _make_session_mgr(session, execute_result=None)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        await _run(guard, mgr, command="echo hello")

    mock_log_repo.create.assert_awaited_once()
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["node_id"] == "fake-uuid-0001"
    assert kwargs["session_id"] == "s1"
    assert kwargs["command"] == "echo hello"
    assert kwargs["exit_code"] == 0
    assert kwargs["security_level"] == "allow"
    assert isinstance(kwargs["duration_ms"], int)
    assert kwargs["duration_ms"] >= 0


@pytest.mark.asyncio
async def test_execute_persists_log_with_nonzero_exit_code():
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _make_session_mgr(
        session,
        execute_result={
            "stdout": "error output",
            "exit_status": 1,
            "working_directory": "/",
        },
    )

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        await _run(guard, mgr, command="false")

    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["exit_code"] == 1


@pytest.mark.asyncio
async def test_execute_updates_node_last_seen_at():
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _make_session_mgr(session)

    update_calls = []
    _node = MagicMock()
    _node.id = "fake-uuid-0001"

    def tracking_factory(db_sess):
        repo = MagicMock()
        repo.get_by_name = AsyncMock(return_value=_node)
        repo.list_all = AsyncMock(return_value=[])

        async def _update(*args, **kwargs):
            update_calls.append((args, kwargs))

        repo.update = _update
        return repo

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        await _run(guard, mgr, node_repo_factory=tracking_factory)

    assert len(update_calls) >= 1
    _, kwargs = update_calls[-1]
    assert kwargs.get("status") == "active"
    assert "last_seen_at" in kwargs


# ---------------------------------------------------------------------------
# Error tolerance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_still_returns_stdout_when_db_logging_fails():
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _make_session_mgr(
        session,
        execute_result={
            "stdout": "important output",
            "exit_status": 0,
            "working_directory": "/",
        },
    )

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock(side_effect=RuntimeError("DB down"))

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        out = await _run(guard, mgr)

    assert out == "important output"


@pytest.mark.asyncio
async def test_execute_returns_error_message_on_session_failure():
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = [session]
    mgr.execute = AsyncMock(side_effect=ConnectionError("SSH connection lost"))

    out = await _run(guard, mgr)
    assert "[ERROR]" in out
    assert "SSH connection lost" in out


@pytest.mark.asyncio
async def test_execute_logs_to_db_even_on_command_error():
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = [session]
    mgr.execute = AsyncMock(side_effect=TimeoutError("timed out"))

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        out = await _run(guard, mgr, command="sleep 9999")

    assert "[ERROR]" in out
    mock_log_repo.create.assert_awaited_once()
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["exit_code"] == -1


@pytest.mark.asyncio
async def test_session_creation_failure_returns_error():
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(side_effect=OSError("no route to host"))

    out = await _run(guard, mgr)
    assert "Error" in out
