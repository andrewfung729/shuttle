"""Tests for shuttle.mcp.tools — _execute_command_logic unit tests."""

from __future__ import annotations

from contextlib import asynccontextmanager
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest

from shuttle.core.security import (
    CommandGuard,
    SecurityDecision,
    SecurityLevel,
)
from shuttle.core.session import SessionManager, SSHSession
from shuttle.mcp.tools import _execute_command_logic

# ---------------------------------------------------------------------------
# Helpers
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


def _noop_node_repo_factory(db_sess):
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[])
    # get_by_name returns a mock node with an id attribute for UUID resolution
    _node = MagicMock()
    _node.id = "fake-uuid-0001"
    repo.get_by_name = AsyncMock(return_value=_node)
    return repo


def _single_node_repo_factory(db_sess):
    """Returns a repo mock with exactly one node named 'mynode'."""
    node = MagicMock()
    node.name = "mynode"
    node.id = "fake-uuid-mynode"
    node.host = "10.0.0.1"
    node.port = 22
    node.username = "root"
    node.status = "active"
    repo = MagicMock()
    repo.list_all = AsyncMock(return_value=[node])
    repo.get_by_name = AsyncMock(return_value=node)
    return repo


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_allowed_command_executes():
    """When guard returns ALLOW, the command should execute via session_mgr."""
    session = SSHSession(session_id="s1", node_id="node1")
    guard = _make_guard(SecurityLevel.ALLOW)
    session_mgr = _make_session_mgr(
        session=session,
        execute_result={
            "stdout": "hello world",
            "exit_status": 0,
            "working_directory": "/tmp",
        },
    )

    result = await _execute_command_logic(
        command="echo hello",
        node="node1",
        timeout=30,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=_noop_node_repo_factory,
    )

    assert result == "hello world"
    session_mgr.execute.assert_awaited_once_with("s1", "echo hello", timeout=30)


@pytest.mark.asyncio
async def test_blocked_command_rejected():
    """When guard returns BLOCK, the command should be rejected immediately."""
    session = SSHSession(session_id="s1", node_id="node1")
    guard = _make_guard(SecurityLevel.BLOCK, message="rm is forbidden")
    session_mgr = _make_session_mgr(session=session)

    result = await _execute_command_logic(
        command="rm -rf /",
        node="node1",
        timeout=30,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=_noop_node_repo_factory,
    )

    assert "Blocked:" in result
    assert "rm is forbidden" in result
    session_mgr.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_confirm_creates_pending_approval_zero_wait():
    """CONFIRM + approval_wait=0 creates a pending approval and returns the
    pending message with approval_id, unquoted command line, and re-call recipe."""
    session = SSHSession(session_id="s1", node_id="node1")
    guard = _make_guard(SecurityLevel.CONFIRM, message="Needs approval")
    approvals = {}
    session_mgr = _make_session_mgr(session=session)

    result = await _execute_command_logic(
        command="shutdown -h now",
        node="node1",
        timeout=30,
        approval_id=None,
        approval_wait=0,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory(approvals),
        settings=_TEST_SETTINGS,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=_noop_node_repo_factory,
    )

    assert "⏳ Approval required" in result
    assert "Approval required (id: ap-1)" in result
    assert "Command: shutdown -h now\n" in result  # command on its own unquoted line
    assert 'approval_id="ap-1"' in result
    assert "byte-for-byte" in result
    assert len(approvals) == 1
    ap = approvals["ap-1"]
    assert ap.status == "pending"
    assert ap.command == "shutdown -h now"
    session_mgr.execute.assert_not_awaited()


@pytest.mark.asyncio
async def test_implicit_session_created_when_none_exists():
    """When no active session exists for the node, one is auto-created."""
    new_session = SSHSession(session_id="auto-1", node_id="node1")
    guard = _make_guard(SecurityLevel.ALLOW)

    session_mgr = MagicMock(spec=SessionManager)
    session_mgr.list_active.return_value = []  # no existing sessions
    session_mgr.create = AsyncMock(return_value=new_session)
    session_mgr.execute = AsyncMock(
        return_value={"stdout": "created", "exit_status": 0, "working_directory": "/"}
    )

    result = await _execute_command_logic(
        command="pwd",
        node="node1",
        timeout=30,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=_noop_node_repo_factory,
    )

    session_mgr.create.assert_awaited_once_with("node1")
    assert result == "created"


@pytest.mark.asyncio
async def test_implicit_session_reused_across_calls():
    """When an active session exists for the node, it is reused (working dir preserved)."""
    session = SSHSession(session_id="reuse-1", node_id="node1")
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

    # First call
    await _execute_command_logic(
        command="cd /workspace",
        node="node1",
        timeout=30,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=_noop_node_repo_factory,
    )

    # Second call — same node, should reuse session
    result = await _execute_command_logic(
        command="pwd",
        node="node1",
        timeout=30,
        approval_id=None,
        approval_wait=None,
        bypass_scope=None,
        pool=MagicMock(),
        guard=guard,
        approval_repo_factory=_approval_repo_factory,
        settings=_TEST_SETTINGS,
        session_mgr=session_mgr,
        db_session_ctx=_noop_db_session,
        node_repo_factory=_noop_node_repo_factory,
    )

    # session.create should never have been called — session was reused
    session_mgr.create.assert_not_awaited()
    # Both calls should use the same session_id
    calls = session_mgr.execute.call_args_list
    assert all(c.args[0] == "reuse-1" for c in calls)
    assert result == "/workspace"
