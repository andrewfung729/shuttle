"""Additional tests for _execute_command_logic and _truncate (MCP core).

Covers: truncation, multi-node auto-select error, confirm token validation,
warn-level execution, auto-session creation, DB logging, and error tolerance.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shuttle.core.security import (
    CommandGuard,
    SecurityDecision,
    SecurityLevel,
)
from shuttle.core.session import SessionManager, SSHSession
from shuttle.mcp.tools import MAX_OUTPUT_BYTES, _execute_command_logic, _truncate

# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------


_TEST_SETTINGS = SimpleNamespace(approval_ttl=900, approval_wait=20.0)


class FakeApprovalRepo:
    """In-memory stand-in for ApprovalRepo."""

    def __init__(self, approvals=None):
        self.approvals = approvals if approvals is not None else {}
        self._counter = 0

    async def create(
        self,
        node_id,
        command,
        session_id=None,
        rule_id=None,
        rule_description=None,
        bypass_scope=None,
        expires_at=None,
    ):
        from datetime import UTC, datetime, timedelta

        self._counter += 1
        ap = MagicMock()
        ap.id = f"ap-{self._counter}"
        ap.node_id = node_id
        ap.command = command
        ap.session_id = session_id
        ap.rule_id = rule_id
        ap.rule_description = rule_description
        ap.bypass_scope = bypass_scope
        ap.status = "pending"
        ap.requested_at = datetime.now(UTC)
        ap.expires_at = expires_at or datetime.now(UTC) + timedelta(seconds=900)
        ap.reject_reason = None
        ap.exec_exit_code = None
        self.approvals[ap.id] = ap
        return ap

    async def get(self, approval_id):
        return self.approvals.get(approval_id)

    async def decide(self, approval_id, decision, reason=None):
        from datetime import UTC, datetime

        ap = self.approvals.get(approval_id)
        if ap is None or ap.status != "pending" or ap.expires_at <= datetime.now(UTC):
            return False
        ap.status = decision
        if decision == "rejected":
            ap.reject_reason = reason
        return True

    async def claim(self, approval_id):
        from datetime import UTC, datetime

        ap = self.approvals.get(approval_id)
        if ap and ap.status == "approved" and ap.expires_at > datetime.now(UTC):
            ap.status = "executed"
            return True
        return False

    async def sweep_expired(self):
        return 0

    async def set_exec_result(self, approval_id, exit_code):
        ap = self.approvals.get(approval_id)
        if ap is not None:
            ap.exec_exit_code = exit_code


def _approval_repo_factory(approvals=None):
    repo = FakeApprovalRepo(approvals)
    return lambda _db_sess: repo


def _make_guard(level: SecurityLevel, message: str = "", rule: str = "test-rule"):
    guard = MagicMock(spec=CommandGuard)
    guard.evaluate = AsyncMock(
        return_value=SecurityDecision(level=level, matched_rule=rule, message=message)
    )
    return guard


def _sm_with_session(
    session: SSHSession,
    stdout: str = "x",
    exit_status: int = 0,
) -> MagicMock:
    mgr = MagicMock(spec=SessionManager)
    mgr.get.return_value = session
    mgr.list_active.return_value = [session]
    mgr.create = AsyncMock(return_value=session)
    mgr.execute = AsyncMock(
        return_value={
            "stdout": stdout,
            "exit_status": exit_status,
            "working_directory": "/",
        }
    )
    return mgr


@asynccontextmanager
async def _noop_db_ctx():
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


# ---------------------------------------------------------------------------
# _truncate
# ---------------------------------------------------------------------------


def test_truncate_short_unchanged() -> None:
    assert _truncate("hello", 100) == "hello"


def test_truncate_appends_marker_when_over_limit() -> None:
    raw = "\u4e00" * 500
    out = _truncate(raw, 10)
    assert "truncated" in out
    assert len(out.encode("utf-8")) <= MAX_OUTPUT_BYTES


# ---------------------------------------------------------------------------
# Node resolution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_no_node_multi_nodes_error() -> None:
    guard = _make_guard(SecurityLevel.ALLOW)

    repo = MagicMock()
    n1, n2 = MagicMock(), MagicMock()
    repo.list_all = AsyncMock(return_value=[n1, n2])

    out = await _execute_command_logic(
        command="ls",
        node=None,
        timeout=1,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=MagicMock(spec=SessionManager),
        db_session_ctx=_noop_db_ctx,
        node_repo_factory=lambda _s: repo,
    )
    assert "cannot auto-select" in out


# ---------------------------------------------------------------------------
# Security: CONFIRM / WARN
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_confirm_unknown_approval_id() -> None:
    """An unknown approval_id must error and never execute."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.CONFIRM, message="check", rule="r1")

    out = await _execute_command_logic(
        command="sudo ls",
        node="n1",
        timeout=1,
        approval_id="does-not-exist",
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory(),
        settings=_TEST_SETTINGS,
        session_mgr=_sm_with_session(session),
        db_session_ctx=_noop_db_ctx,
        node_repo_factory=_node_repo_factory,
    )
    assert "unknown approval_id" in out


@pytest.mark.asyncio
async def test_execute_warn_still_runs_session_execute() -> None:
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.WARN, message="careful", rule="w1")
    mgr = _sm_with_session(session)

    with patch("shuttle.mcp.tools.logger.warning") as log_warn:
        out = await _execute_command_logic(
            command="curl x",
            node="n1",
            timeout=1,
            approval_id=None,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory,
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
        )
    log_warn.assert_called()
    assert out == "x"


# ---------------------------------------------------------------------------
# Auto-session creation
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_auto_session_creation_on_pool_node() -> None:
    """When no session exists, auto-create one and execute via session_mgr."""
    new_session = SSHSession(session_id="auto-new", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    mgr.create = AsyncMock(return_value=new_session)
    mgr.execute = AsyncMock(
        return_value={"stdout": "hello", "exit_status": 0, "working_directory": "/"}
    )

    out = await _execute_command_logic(
        command="hostname",
        node="n1",
        timeout=1,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=mgr,
        db_session_ctx=_noop_db_ctx,
        node_repo_factory=_node_repo_factory,
    )
    assert out == "hello"
    mgr.create.assert_awaited_once_with("n1")
    mgr.execute.assert_awaited_once()


# ---------------------------------------------------------------------------
# DB logging — LogRepo.create called after execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_persists_command_log_to_db() -> None:
    """After successful execution, LogRepo.create must be called with correct fields."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _sm_with_session(session, stdout="hello world", exit_status=0)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with patch("shuttle.db.repository.LogRepo", return_value=mock_log_repo):
        await _execute_command_logic(
            command="echo hello",
            node="n1",
            timeout=10,
            approval_id=None,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory,
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
        )

    mock_log_repo.create.assert_awaited_once()
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["node_id"] == "fake-uuid-0001"
    assert kwargs["session_id"] == "s1"
    assert kwargs["command"] == "echo hello"
    assert kwargs["exit_code"] == 0
    assert kwargs["security_level"] == "allow"
    assert kwargs["bypassed"] is False
    assert isinstance(kwargs["duration_ms"], int)
    assert kwargs["duration_ms"] >= 0


@pytest.mark.asyncio
async def test_execute_persists_log_with_claimed_approval() -> None:
    """A claimed approval executes, sets bypassed=True and stamps approval_id."""
    from datetime import UTC, datetime, timedelta

    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.CONFIRM, message="sudo", rule="r1")

    approvals = {}
    factory = _approval_repo_factory(approvals)
    repo = factory(None)
    ap = await repo.create(
        node_id="fake-uuid-0001",
        command="sudo whoami",
        expires_at=datetime.now(UTC) + timedelta(seconds=60),
    )
    await repo.decide(ap.id, "approved")

    mgr = _sm_with_session(session, stdout="root")

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with patch("shuttle.db.repository.LogRepo", return_value=mock_log_repo):
        out = await _execute_command_logic(
            command="sudo whoami",
            node="n1",
            timeout=10,
            approval_id=ap.id,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=factory,
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
        )

    assert out == "root"
    mock_log_repo.create.assert_awaited_once()
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["bypassed"] is True
    assert kwargs["security_level"] == "confirm"
    assert kwargs["approval_id"] == ap.id
    assert ap.status == "executed"


@pytest.mark.asyncio
async def test_execute_persists_log_with_nonzero_exit_code() -> None:
    """Log entry must record the real exit_code from execute()."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _sm_with_session(session, stdout="error output", exit_status=1)

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with patch("shuttle.db.repository.LogRepo", return_value=mock_log_repo):
        await _execute_command_logic(
            command="false",
            node="n1",
            timeout=10,
            approval_id=None,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory,
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
        )

    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["exit_code"] == 1


@pytest.mark.asyncio
async def test_execute_updates_node_last_seen_at() -> None:
    """After execution, node's last_seen_at and status should be updated."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _sm_with_session(session)

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

    with patch("shuttle.db.repository.LogRepo", return_value=mock_log_repo):
        await _execute_command_logic(
            command="ls",
            node="n1",
            timeout=10,
            approval_id=None,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory,
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=tracking_factory,
        )

    assert len(update_calls) >= 1
    _, kwargs = update_calls[-1]
    assert kwargs.get("status") == "active"
    assert "last_seen_at" in kwargs


# ---------------------------------------------------------------------------
# DB logging — error tolerance
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_execute_still_returns_stdout_when_db_logging_fails() -> None:
    """If DB logging raises, the command output must still be returned."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)
    mgr = _sm_with_session(session, stdout="important output")

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock(side_effect=RuntimeError("DB down"))

    with patch("shuttle.db.repository.LogRepo", return_value=mock_log_repo):
        out = await _execute_command_logic(
            command="echo test",
            node="n1",
            timeout=10,
            approval_id=None,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory(),
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
        )
    assert out == "important output"


@pytest.mark.asyncio
async def test_execute_still_returns_on_session_execute_error() -> None:
    """If session_mgr.execute raises, an error message is returned (not raised)."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = [session]
    mgr.execute = AsyncMock(side_effect=ConnectionError("SSH connection lost"))

    out = await _execute_command_logic(
        command="ls",
        node="n1",
        timeout=10,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=mgr,
        db_session_ctx=_noop_db_ctx,
        node_repo_factory=_node_repo_factory,
    )
    assert "[ERROR]" in out
    assert "SSH connection lost" in out


@pytest.mark.asyncio
async def test_execute_logs_to_db_even_on_command_error() -> None:
    """When execute() raises, exit_code=-1 should still be logged."""
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.ALLOW)

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = [session]
    mgr.execute = AsyncMock(side_effect=TimeoutError("timed out"))

    mock_log_repo = MagicMock()
    mock_log_repo.create = AsyncMock()

    with patch("shuttle.db.repository.LogRepo", return_value=mock_log_repo):
        out = await _execute_command_logic(
            command="sleep 9999",
            node="n1",
            timeout=1,
            approval_id=None,
            approval_wait=None,
            bypass_scope=None,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory,
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
        )

    assert "[ERROR]" in out
    mock_log_repo.create.assert_awaited_once()
    kwargs = mock_log_repo.create.call_args.kwargs
    assert kwargs["exit_code"] == -1


# ---------------------------------------------------------------------------
# Approval queue flow (ticket 02 acceptance criteria)
# ---------------------------------------------------------------------------


async def _run_confirm(
    approvals,
    *,
    approval_id=None,
    approval_wait=None,
    command="sudo whoami",
    bypass_scope=None,
    stdout="root",
):
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.CONFIRM, message="sudo", rule="r1")
    mgr = _sm_with_session(session, stdout=stdout)
    return await _execute_command_logic(
        command=command,
        node="n1",
        timeout=10,
        approval_id=approval_id,
        approval_wait=approval_wait,
        bypass_scope=bypass_scope,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory(approvals),
        settings=_TEST_SETTINGS,
        session_mgr=mgr,
        db_session_ctx=_noop_db_ctx,
        node_repo_factory=_node_repo_factory,
    )


@pytest.mark.asyncio
async def test_approval_pending_then_rejected_with_reason() -> None:
    approvals = {}
    out = await _run_confirm(approvals, approval_wait=0)
    ap = approvals["ap-1"]

    await _approval_repo_factory(approvals)(None).decide(
        ap.id, "rejected", reason="use systemctl instead"
    )
    out = await _run_confirm(approvals, approval_id=ap.id, command=ap.command)
    assert "❌ Approval rejected" in out
    assert "use systemctl instead" in out


@pytest.mark.asyncio
async def test_approval_rejected_without_reason_fallback() -> None:
    approvals = {}
    out = await _run_confirm(approvals, approval_wait=0)
    ap = approvals["ap-1"]
    await _approval_repo_factory(approvals)(None).decide(ap.id, "rejected")
    out = await _run_confirm(approvals, approval_id=ap.id, command=ap.command)
    assert "no reason given" in out


@pytest.mark.asyncio
async def test_approval_replay_reports_already_used() -> None:
    approvals = {}
    out = await _run_confirm(approvals, approval_wait=0)
    ap = approvals["ap-1"]
    await _approval_repo_factory(approvals)(None).decide(ap.id, "approved")
    # First claim+execute succeeds...
    out = await _run_confirm(approvals, approval_id=ap.id, command=ap.command)
    assert out == "root"
    # ...replay reports "already used" and never executes again.
    out = await _run_confirm(approvals, approval_id=ap.id, command=ap.command)
    assert "already used" in out


@pytest.mark.asyncio
async def test_approval_wrong_command_rejected() -> None:
    approvals = {}
    out = await _run_confirm(approvals, approval_wait=0)
    ap = approvals["ap-1"]
    await _approval_repo_factory(approvals)(None).decide(ap.id, "approved")
    out = await _run_confirm(approvals, approval_id=ap.id, command="sudo rm file")
    assert "different command" in out


@pytest.mark.asyncio
async def test_approval_wrong_node_rejected() -> None:
    approvals = {}
    out = await _run_confirm(approvals, approval_wait=0)
    ap = approvals["ap-1"]
    await _approval_repo_factory(approvals)(None).decide(ap.id, "approved")
    ap.node_id = "some-other-node-uuid"
    out = await _run_confirm(approvals, approval_id=ap.id, command=ap.command)
    assert "different node" in out


@pytest.mark.asyncio
async def test_approval_expired_reports_expiry() -> None:
    from datetime import UTC, datetime, timedelta

    approvals = {}
    out = await _run_confirm(approvals, approval_wait=0)
    ap = approvals["ap-1"]
    ap.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    out = await _run_confirm(approvals, approval_id=ap.id, command=ap.command)
    assert "expired" in out


@pytest.mark.asyncio
async def test_approval_bypass_scope_persisted_on_row() -> None:
    approvals = {}
    await _run_confirm(approvals, approval_wait=0, bypass_scope="session")
    assert approvals["ap-1"].bypass_scope == "session"


@pytest.mark.asyncio
async def test_approval_claim_unlocks_bypass_from_persisted_scope() -> None:
    """Claim WITHOUT repeating bypass_scope still unlocks the session pattern.

    The re-call recipe only passes approval_id, so the claim call relies on
    pending_approvals.bypass_scope recorded by the initial call (ticket 07).
    """
    approvals = {}
    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.CONFIRM, message="sudo", rule="r1")
    mgr = _sm_with_session(session, stdout="root")

    async def run(**kwargs):
        kwargs.setdefault("approval_id", None)
        kwargs.setdefault("approval_wait", None)
        kwargs.setdefault("bypass_scope", None)
        return await _execute_command_logic(
            command="sudo whoami",
            node="n1",
            timeout=10,
            pool=MagicMock(),
            guard=guard,
            approval_repo_factory=_approval_repo_factory(approvals),
            settings=_TEST_SETTINGS,
            session_mgr=mgr,
            db_session_ctx=_noop_db_ctx,
            node_repo_factory=_node_repo_factory,
            **kwargs,
        )

    out = await run(approval_wait=0, bypass_scope="session")
    assert "Approval required" in out
    assert approvals["ap-1"].bypass_scope == "session"

    await _approval_repo_factory(approvals)(None).decide("ap-1", "approved")

    rule = SimpleNamespace(pattern=r"sudo .*")
    repo_inst = SimpleNamespace(get_by_id=AsyncMock(return_value=rule))
    with patch("shuttle.db.repository.RuleRepo", lambda _sess: repo_inst):
        out = await run(approval_id="ap-1", bypass_scope=None)
    assert out == "root"
    assert r"sudo .*" in session.bypass_patterns


@pytest.mark.asyncio
async def test_approval_decision_injected_mid_wait_executes() -> None:
    """Decision lands between polls — the hybrid wait executes without a second call."""
    approvals = {}
    repo = _approval_repo_factory(approvals)(None)

    class MidWaitRepo(FakeApprovalRepo):
        def __init__(self, inner):
            self.inner = inner
            self.polls = 0

        async def get(self, approval_id):
            ap = await self.inner.get(approval_id)
            self.polls += 1
            if self.polls >= 2 and ap.status == "pending":
                ap.status = "approved"
            return ap

        def __getattr__(self, name):
            return getattr(self.inner, name)

    factory = lambda _db_sess: MidWaitRepo(repo)  # noqa: E731

    session = SSHSession(session_id="s1", node_id="n1")
    guard = _make_guard(SecurityLevel.CONFIRM, message="sudo", rule="r1")
    mgr = _sm_with_session(session, stdout="root")

    out = await _execute_command_logic(
        command="sudo whoami",
        node="n1",
        timeout=10,
        approval_id=None,
        approval_wait=30,  # long enough for a mid-wait decision
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=factory,
        settings=_TEST_SETTINGS,
        session_mgr=mgr,
        db_session_ctx=_noop_db_ctx,
        node_repo_factory=_node_repo_factory,
    )
    assert out == "root"
