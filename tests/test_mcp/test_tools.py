"""Tests for shuttle.mcp.tools — _execute_command_logic orchestration.

Covers the block / allow / gate routing at the ssh_run seam, the uncertain
band handing off to the Hold seam, auto-session handling, DB logging, and
error paths. Gate scoring and Hold lifecycle are covered in
``tests/test_core/test_holds.py``; here we assert the routing.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from shuttle.core.holds import AWAITING_MESSAGE, Execution, HoldAction, HoldManager
from shuttle.core.security import CommandGuard, SecurityDecision, SecurityLevel
from shuttle.core.session import SessionManager, SSHSession
from shuttle.db.models import CommandLog, Hold
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


class StubExecutor:
    def __init__(self, stdout="ran once", exit_code=0):
        self.stdout = stdout
        self.exit_code = exit_code
        self.calls: list[dict] = []

    async def __call__(
        self, *, node_id, command, gate_score=None, conversation_key=None
    ):
        self.calls.append({"node_id": node_id, "command": command})
        return Execution(stdout=self.stdout, exit_code=self.exit_code)


# ---------------------------------------------------------------------------
# Fixtures + helpers
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def session_factory(db_engine):
    return sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)


@pytest.fixture
def db_ctx(session_factory):
    @asynccontextmanager
    async def _ctx():
        async with session_factory() as session:
            yield session

    return _ctx


def _gate_settings(enabled=True, key="sk-or-test"):
    return SimpleNamespace(
        gate_enabled=enabled,
        openrouter_api_key=key,
        gate_safe_instructions="Decide if the command is safe.",
    )


def make_holds(
    db_session_ctx, *, gate=None, settings=None, executor=None, hold_wait=0.05
):
    return HoldManager(
        db_session_ctx=db_session_ctx,
        gate=gate,
        settings=settings if settings is not None else _gate_settings(),
        executor=executor if executor is not None else StubExecutor(),
        hold_wait=hold_wait,
        poll_interval=0.01,
    )


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
    repo.get_by_id = AsyncMock(return_value=_node)
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
    holds=None,
    db_session_ctx=_noop_db_session,
    conversation_key="conv-test",
    client_id="cursor",
):
    if holds is None:
        holds = make_holds(_noop_db_session, gate=None)
    return await _execute_command_logic(
        command=command,
        node=node,
        timeout=timeout,
        guard=guard,
        holds=holds,
        session_mgr=session_mgr,
        db_session_ctx=db_session_ctx,
        node_repo_factory=node_repo_factory,
        conversation_key=conversation_key,
        client_id=client_id,
    )


async def _logs(session_factory) -> list[CommandLog]:
    async with session_factory() as session:
        return list(
            (await session.execute(select(CommandLog).order_by(CommandLog.executed_at)))
            .scalars()
            .all()
        )


async def _holds(session_factory) -> list[Hold]:
    async with session_factory() as session:
        return list((await session.execute(select(Hold))).scalars().all())


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
async def test_allow_rule_never_consults_gate_or_holds(session_factory, db_ctx):
    session = SSHSession(session_id="s1", node_id="n1")
    gate = StubGate(score=0.1)
    holds = make_holds(db_ctx, gate=gate)

    result = await _run(
        _make_guard(SecurityLevel.ALLOW), _make_session_mgr(session), holds=holds
    )

    assert result == "ok"
    assert gate.calls == []
    assert await _holds(session_factory) == []


@pytest.mark.asyncio
async def test_blocked_command_returns_fixed_denial():
    """BLOCK: exact fixed string, no execution, no rule detail leaked."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.BLOCK, message="rm is forbidden")
    session_mgr = _make_session_mgr(session)
    gate = StubGate(score=0.99)

    result = await _run(
        guard,
        session_mgr,
        command="rm -rf /",
        holds=make_holds(_noop_db_session, gate=gate),
    )

    assert result == "Error: denied by policy"
    assert result == DENIED_MESSAGE
    assert gate.calls == []  # block rules never depend on the gate
    session_mgr.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# Unmatched → Hold seam
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_safe_score_executes(session_factory, db_ctx):
    """gate + score >= threshold -> executes, no Hold."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(session)
    gate = StubGate(score=SAFE_THRESHOLD)
    holds = make_holds(db_ctx, gate=gate)

    result = await _run(
        guard,
        mgr,
        command="sudo systemctl status nginx",
        holds=holds,
    )

    assert result == "ok"
    assert len(gate.calls) == 1
    assert gate.calls[0]["state"] == {
        "command": "sudo systemctl status nginx",
        "node": "n1",
    }
    assert gate.calls[0]["instructions"] == "Decide if the command is safe."
    assert await _holds(session_factory) == []


@pytest.mark.asyncio
async def test_gate_safe_logs_score_on_executed_row(session_factory, db_ctx):
    """An executed gated command records its passing gate score."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(session)
    gate = StubGate(score=0.97)

    await _run(guard, mgr, holds=make_holds(db_ctx, gate=gate), db_session_ctx=db_ctx)

    logs = await _logs(session_factory)
    assert len(logs) == 1
    assert logs[0].gate_score == 0.97
    assert logs[0].gate_reason is None
    assert logs[0].security_level == "gate"
    assert logs[0].exit_code == 0


@pytest.mark.asyncio
async def test_unsafe_score_denies_and_logs(session_factory, db_ctx):
    """gate + score below the hold floor -> fixed denial, reason unsafe."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.1)

    result = await _run(guard, mgr, holds=make_holds(db_ctx, gate=gate))

    assert result == DENIED_MESSAGE
    mgr.execute.assert_not_awaited()
    assert await _holds(session_factory) == []
    logs = await _logs(session_factory)
    assert logs[0].gate_score == 0.1
    assert logs[0].gate_reason == "unsafe"
    assert logs[0].security_level == "gate"
    assert logs[0].exit_code is None


@pytest.mark.asyncio
async def test_uncertain_score_parks_hold_and_awaits(session_factory, db_ctx):
    """gate + score in the band -> Hold created, awaiting returned."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.5)

    result = await _run(
        guard, mgr, command="usermod -aG sudo bob", holds=make_holds(db_ctx, gate=gate)
    )

    assert result == AWAITING_MESSAGE
    holds = await _holds(session_factory)
    assert len(holds) == 1
    assert holds[0].gate_score == 0.5
    assert holds[0].conversation_key == "conv-test"


@pytest.mark.asyncio
async def test_gate_error_denies_and_logs_error(session_factory, db_ctx):
    """Gate exception/timeout -> fixed denial, log row reason=error, no score."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(error=TimeoutError("gate timed out"))

    result = await _run(guard, mgr, holds=make_holds(db_ctx, gate=gate))

    assert result == DENIED_MESSAGE
    logs = await _logs(session_factory)
    assert logs[0].gate_score is None
    assert logs[0].gate_reason == "error"


@pytest.mark.asyncio
async def test_gate_disabled_denies_and_logs_disabled(session_factory, db_ctx):
    """gate_enabled=false -> fixed denial, log row reason=disabled, no gate call."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.99)

    result = await _run(
        guard,
        mgr,
        holds=make_holds(db_ctx, gate=gate, settings=_gate_settings(enabled=False)),
    )

    assert result == DENIED_MESSAGE
    assert gate.calls == []  # never called
    logs = await _logs(session_factory)
    assert logs[0].gate_reason == "disabled"
    assert logs[0].gate_score is None


@pytest.mark.asyncio
async def test_gate_missing_key_denies(session_factory, db_ctx):
    """Enabled gate but no API key -> disabled denial (fail closed)."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.99)

    result = await _run(
        guard,
        mgr,
        holds=make_holds(db_ctx, gate=gate, settings=_gate_settings(key=None)),
    )

    assert result == DENIED_MESSAGE
    assert gate.calls == []
    assert (await _logs(session_factory))[0].gate_reason == "disabled"


@pytest.mark.asyncio
async def test_gate_none_denies_disabled(session_factory, db_ctx):
    """No gate wired at all -> disabled."""
    guard = _make_guard(SecurityLevel.GATE)
    mgr = _make_session_mgr(None)

    result = await _run(guard, mgr, holds=make_holds(db_ctx, gate=None))

    assert result == DENIED_MESSAGE
    assert (await _logs(session_factory))[0].gate_reason == "disabled"


@pytest.mark.asyncio
async def test_block_denies_and_logs_without_gate_call(session_factory, db_ctx):
    """block -> fixed denial + log row; the gate is never consulted."""
    guard = _make_guard(SecurityLevel.BLOCK)
    mgr = _make_session_mgr(None)
    gate = StubGate(score=0.99)

    result = await _run(
        guard,
        mgr,
        db_session_ctx=db_ctx,
        holds=make_holds(db_ctx, gate=gate),
    )

    assert result == DENIED_MESSAGE
    assert gate.calls == []
    logs = await _logs(session_factory)
    assert logs[0].security_level == "block"
    assert logs[0].gate_reason is None
    assert logs[0].gate_score is None


@pytest.mark.asyncio
async def test_denial_still_returned_when_denial_log_fails(db_ctx):
    """A denial-log DB failure must not turn a denial into anything else."""
    guard = _make_guard(SecurityLevel.BLOCK)
    mgr = _make_session_mgr(None)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock(side_effect=RuntimeError("DB down"))

    with pytest.MonkeyPatch.context() as mp:
        mp.setattr("shuttle.db.repository.LogRepo", lambda _s: mock_log_repo)
        result = await _run(guard, mgr, db_session_ctx=db_ctx)

    assert result == DENIED_MESSAGE


@pytest.mark.asyncio
async def test_denial_does_not_create_session(db_ctx):
    """A denied command must not open an SSH session just to be refused."""
    guard = _make_guard(SecurityLevel.GATE)
    session_mgr = _make_session_mgr(None)

    await _run(
        guard,
        session_mgr,
        command="sudo ls",
        holds=make_holds(db_ctx, gate=None),
        db_session_ctx=db_ctx,
    )

    session_mgr.create.assert_not_awaited()
    session_mgr.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_run_once_execution_log_records_once_and_conversation(
    session_factory, db_ctx
):
    """A run-once execution writes a `once` CommandLog row tied to the conversation."""
    from shuttle.mcp.tools import build_hold_executor

    session = SSHSession(session_id="s1", node_id="n1")
    session_mgr = _make_session_mgr(
        session,
        execute_result={"stdout": "once out", "exit_status": 0},
    )
    executor = build_hold_executor(
        session_mgr=session_mgr,
        db_session_ctx=db_ctx,
        node_repo_factory=_node_repo_factory,
    )
    gate = StubGate(score=0.5)
    holds = HoldManager(
        db_session_ctx=db_ctx,
        gate=gate,
        settings=_gate_settings(),
        executor=executor,
        hold_wait=0.0,
    )

    assert (
        await _execute_command_logic(
            command="usermod -aG sudo bob",
            node="n1",
            timeout=10,
            guard=_make_guard(SecurityLevel.GATE),
            holds=holds,
            session_mgr=session_mgr,
            db_session_ctx=db_ctx,
            node_repo_factory=_node_repo_factory,
            conversation_key="conv-test",
            client_id="cursor",
        )
        == AWAITING_MESSAGE
    )

    async with session_factory() as db:
        hold = (await db.execute(select(Hold))).scalars().one()
    await holds.decide(hold.id, HoldAction.RUN_ONCE, operator="op")
    for _ in range(100):
        async with session_factory() as db:
            hold = (await db.execute(select(Hold))).scalars().one()
        if hold.status == "executed":
            break
        await asyncio.sleep(0.01)

    logs = await _logs(session_factory)
    once_logs = [log for log in logs if log.gate_reason == "once"]
    assert len(once_logs) == 1
    assert once_logs[0].conversation_key == "conv-test"
    assert once_logs[0].gate_score == 0.5
    assert once_logs[0].stdout == "once out"


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
    assert kwargs["conversation_key"] == "conv-test"
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


@pytest.mark.asyncio
async def test_session_creation_failure_still_writes_audit_row(session_factory, db_ctx):
    """A failed session attempt is still recorded — no silent drop."""
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(side_effect=OSError("no route to host"))
    mgr.execute = AsyncMock()

    out = await _run(
        guard,
        mgr,
        command="systemctl restart nginx",
        db_session_ctx=db_ctx,
    )

    assert "Error" in out
    logs = await _logs(session_factory)
    assert len(logs) == 1
    assert logs[0].command == "systemctl restart nginx"
    assert logs[0].security_level == "allow"
    assert logs[0].conversation_key == "conv-test"
    assert logs[0].exit_code == -1
    assert "no route to host" in (logs[0].stderr or "")


@pytest.mark.asyncio
async def test_failed_session_creation_does_not_mark_node_seen(db_ctx):
    """A failed attempt must not falsify node liveness."""
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(side_effect=OSError("no route"))

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

    await _run(guard, mgr, node_repo_factory=tracking_factory, db_session_ctx=db_ctx)

    assert update_calls == []


@pytest.mark.asyncio
async def test_run_once_execution_logs_once_when_session_cannot_be_created(
    session_factory, db_ctx
):
    """A run-once decision that cannot open a session still writes a `once` row."""
    from shuttle.mcp.tools import build_hold_executor

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(side_effect=OSError("host down"))

    executor = build_hold_executor(
        session_mgr=mgr,
        db_session_ctx=db_ctx,
        node_repo_factory=_node_repo_factory,
    )

    result = await executor(
        node_id="fake-uuid-0001",
        command="usermod -aG sudo bob",
        gate_score=0.5,
        conversation_key="conv-test",
    )

    assert result.exit_code == -1
    logs = await _logs(session_factory)
    once_logs = [log for log in logs if log.gate_reason == "once"]
    assert len(once_logs) == 1
    assert once_logs[0].exit_code == -1
    assert once_logs[0].conversation_key == "conv-test"


@pytest.mark.asyncio
async def test_gated_session_creation_failure_still_writes_audit_row(
    session_factory, db_ctx
):
    """A confident-safe gated command that cannot open a session is still logged."""
    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(side_effect=OSError("host down"))
    mgr.execute = AsyncMock()

    gate = StubGate(score=0.99)
    out = await _run(
        _make_guard(SecurityLevel.GATE),
        mgr,
        command="systemctl status nginx",
        holds=make_holds(db_ctx, gate=gate),
        db_session_ctx=db_ctx,
    )

    assert "Error" in out
    logs = await _logs(session_factory)
    assert len(logs) == 1
    assert logs[0].security_level == "gate"
    assert logs[0].gate_score == 0.99
    assert logs[0].exit_code == -1


@pytest.mark.asyncio
async def test_execute_persists_nonzero_exit_status_from_session(
    session_factory, db_ctx
):
    """A real non-zero exit status from the session is recorded, not flattened to 0."""
    session = SSHSession(session_id="s1", node_id="n1")
    mgr = _make_session_mgr(
        session,
        execute_result={
            "stdout": "",
            "stderr": "boom",
            "exit_status": 3,
            "working_directory": "/",
        },
    )

    await _run(
        _make_guard(SecurityLevel.ALLOW),
        mgr,
        command="false",
        db_session_ctx=db_ctx,
    )

    logs = await _logs(session_factory)
    assert logs[0].exit_code == 3
    assert logs[0].stderr == "boom"


@pytest.mark.asyncio
async def test_run_once_session_failure_stores_output_on_hold(session_factory, db_ctx):
    """A run-once decision that cannot reach the node stores the failure on the Hold."""
    from shuttle.mcp.tools import build_hold_executor

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(side_effect=OSError("host down"))

    holds = HoldManager(
        db_session_ctx=db_ctx,
        gate=StubGate(score=0.5),
        settings=_gate_settings(),
        executor=build_hold_executor(
            session_mgr=mgr,
            db_session_ctx=db_ctx,
            node_repo_factory=_node_repo_factory,
        ),
        hold_wait=0.0,
        poll_interval=0.01,
    )

    out = await holds.triage(
        command="usermod -aG sudo bob",
        node="n1",
        node_id="fake-uuid-0001",
        conversation_key="conv-test",
        client_id="cursor",
    )
    assert out.text == AWAITING_MESSAGE

    async with session_factory() as db:
        hold = (await db.execute(select(Hold))).scalars().one()
    await holds.decide(hold.id, HoldAction.RUN_ONCE, operator="op")

    for _ in range(100):
        async with session_factory() as db:
            hold = (await db.execute(select(Hold))).scalars().one()
        if hold.status == "executed":
            break
        await asyncio.sleep(0.01)

    assert hold.status == "executed"
    assert hold.exit_code == -1
    assert "failed to auto-create session" in (hold.stdout or "")
