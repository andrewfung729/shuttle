"""FastMCP in-memory client tests for Shuttle MCP tools.

Uses ``fastmcp.Client(server)`` to exercise tools end-to-end without SSH or
network, validating tool registration, argument schemas, security flow, and
DB logging through the real FastMCP protocol layer.
"""

from __future__ import annotations

import json
import re
import tempfile
from contextlib import asynccontextmanager
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock

import pytest
import pytest_asyncio
from fastmcp import Client, FastMCP
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from shuttle.core.credentials import CredentialManager
from shuttle.core.security import CommandGuard
from shuttle.core.session import SSHSession
from shuttle.db.models import Base, CommandLog
from shuttle.db.repository import ApprovalRepo, NodeRepo, RuleRepo
from shuttle.mcp.resources import register_resources
from shuttle.mcp.tools import register_tools

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _result_text(result) -> str:
    """Extract text from a FastMCP CallToolResult."""
    if hasattr(result, "content") and result.content:
        return result.content[0].text
    if hasattr(result, "data") and result.data is not None:
        return str(result.data)
    return str(result)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def mock_pool():
    p = MagicMock()
    p._registry = {}
    p.start_eviction_loop = AsyncMock()
    p.register_node = MagicMock()
    return p


@pytest.fixture
def mock_session_mgr():
    from shuttle.core.session import SessionManager

    mgr = MagicMock(spec=SessionManager)
    mgr.list_active.return_value = []
    return mgr


@pytest_asyncio.fixture
async def db_engine(tmp_path):
    db_path = tmp_path / "fastmcp_test.db"
    engine = create_async_engine(f"sqlite+aiosqlite:///{db_path}")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def db_factory(db_engine):
    return sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)


@pytest_asyncio.fixture
async def mcp_server(mock_pool, mock_session_mgr, db_factory, tmp_path):
    """Build a FastMCP server with real DB but mocked SSH."""
    mcp = FastMCP(name="shuttle-test")
    guard = CommandGuard()
    settings = SimpleNamespace(approval_ttl=900, approval_wait=20.0)
    cred_mgr = CredentialManager(tmp_path)

    @asynccontextmanager
    async def db_session_ctx():
        async with db_factory() as sess:
            yield sess

    async with db_factory() as sess:
        node_repo = NodeRepo(sess)
        await node_repo.create(
            name="test-node",
            host="10.0.0.1",
            port=22,
            username="root",
            auth_type="password",
            encrypted_credential="enc",
        )

    register_tools(
        mcp=mcp,
        pool=mock_pool,
        guard=guard,
        session_mgr=mock_session_mgr,
        db_session_ctx=db_session_ctx,
        node_repo_factory=NodeRepo,
        approval_repo_factory=ApprovalRepo,
        settings=settings,
        cred_mgr=cred_mgr,
    )
    register_resources(
        mcp=mcp,
        pool=mock_pool,
        session_mgr=mock_session_mgr,
        db_session_ctx=db_session_ctx,
        node_repo_factory=NodeRepo,
    )
    return mcp


@pytest_asyncio.fixture
async def mcp_server_with_session(mcp_server, mock_session_mgr):
    """mcp_server + session_mgr pre-configured to simulate execution."""
    session = SSHSession(session_id="test-sess-1", node_id="test-node")
    mock_session_mgr.list_active.return_value = [session]
    mock_session_mgr.create = AsyncMock(return_value=session)
    mock_session_mgr.execute = AsyncMock(
        return_value={
            "stdout": "mocked output",
            "exit_status": 0,
            "working_directory": "/home/root",
        }
    )
    return mcp_server


# ---------------------------------------------------------------------------
# Tool registration / discovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_client_discovers_all_tools(mcp_server):
    """FastMCP Client.list_tools() must see all 4 Shuttle tools."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()

    tool_names = {t.name for t in tools}
    expected = {
        "ssh_run",
        "ssh_upload",
        "ssh_download",
        "ssh_add_node",
    }
    assert expected == tool_names


@pytest.mark.asyncio
async def test_tool_schemas_have_descriptions(mcp_server):
    """Every tool must have a non-empty description."""
    async with Client(mcp_server) as client:
        tools = await client.list_tools()

    for tool in tools:
        assert tool.description, f"Tool {tool.name} has no description"


# ---------------------------------------------------------------------------
# shuttle://nodes resource via Client (replaces deleted ssh_list_nodes tool)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_list_nodes_via_client(mcp_server):
    """shuttle://nodes resource read through Client returns the seeded node."""
    async with Client(mcp_server) as client:
        result = await client.read_resource("shuttle://nodes")

    data = json.loads(result[0].text)
    assert data["total"] == 1
    assert data["nodes"][0]["name"] == "test-node"
    assert data["nodes"][0]["host"] == "10.0.0.1"


# ---------------------------------------------------------------------------
# ssh_run via Client — security flow
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_allowed_command_via_client(mcp_server_with_session):
    """ALLOW-level command executes and returns output through Client."""
    async with Client(mcp_server_with_session) as client:
        result = await client.call_tool(
            "ssh_run", {"command": "hostname", "node": "test-node"}
        )

    text = _result_text(result)
    assert "mocked output" in text


@pytest.mark.asyncio
async def test_run_blocked_command_via_client(mcp_server_with_session, db_factory):
    """A command matching a BLOCK rule returns BLOCKED through Client."""
    async with db_factory() as sess:
        rule_repo = RuleRepo(sess)
        await rule_repo.create(
            pattern=r"^rm\s+-rf\s+/",
            level="block",
            description="Block dangerous rm",
            priority=0,
        )

    async with Client(mcp_server_with_session) as client:
        result = await client.call_tool(
            "ssh_run", {"command": "rm -rf /", "node": "test-node"}
        )

    text = _result_text(result)
    assert "BLOCKED" in text


@pytest.mark.asyncio
async def test_run_confirm_flow_via_client(mcp_server_with_session, db_factory):
    """CONFIRM command → pending approval (wait=0) → panel approve → re-call executes."""
    async with db_factory() as sess:
        rule_repo = RuleRepo(sess)
        await rule_repo.create(
            pattern=r"^sudo\b",
            level="confirm",
            description="Confirm sudo",
            priority=0,
        )

    async with Client(mcp_server_with_session) as client:
        result1 = await client.call_tool(
            "ssh_run",
            {"command": "sudo ls", "node": "test-node", "approval_wait": 0},
        )
        text1 = _result_text(result1)
        assert "Approval required" in text1

        match = re.search(r'approval_id="([^"]+)"', text1)
        assert match, f"Could not find approval_id in: {text1}"
        approval_id = match.group(1)

        # Human approves in the panel.
        async with db_factory() as sess:
            assert await ApprovalRepo(sess).decide(approval_id, "approved") is True

        # AI re-calls with the same command byte-for-byte plus approval_id.
        result2 = await client.call_tool(
            "ssh_run",
            {"command": "sudo ls", "node": "test-node", "approval_id": approval_id},
        )
        text2 = _result_text(result2)
        assert "mocked output" in text2

        # Approval row is now executed (single-use claim).
        async with db_factory() as sess:
            ap = await ApprovalRepo(sess).get(approval_id)
            assert ap.status == "executed"


# ---------------------------------------------------------------------------
# ssh_run via Client — DB logging verification
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_persists_log_to_real_db(mcp_server_with_session, db_factory):
    """After ssh_run, a CommandLog row must exist in the real DB."""
    async with Client(mcp_server_with_session) as client:
        await client.call_tool("ssh_run", {"command": "whoami", "node": "test-node"})

    from sqlalchemy import select

    async with db_factory() as sess:
        result = await sess.execute(select(CommandLog))
        logs = list(result.scalars().all())

    assert len(logs) >= 1
    log = logs[-1]
    assert log.command == "whoami"
    assert log.exit_code == 0
    assert log.security_level == "allow"
    assert log.duration_ms is not None
    assert log.duration_ms >= 0


@pytest.mark.asyncio
async def test_run_persists_log_with_correct_node_id(
    mcp_server_with_session, db_factory
):
    """Log entry must reference the correct node UUID, not the name."""
    async with Client(mcp_server_with_session) as client:
        await client.call_tool("ssh_run", {"command": "pwd", "node": "test-node"})

    from sqlalchemy import select

    async with db_factory() as sess:
        node_repo = NodeRepo(sess)
        node = await node_repo.get_by_name("test-node")
        assert node is not None

        result = await sess.execute(select(CommandLog))
        logs = list(result.scalars().all())

    assert len(logs) >= 1
    assert logs[-1].node_id == node.id


# ---------------------------------------------------------------------------
# ssh_add_node via Client
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_add_node_inline_secrets_rejected(mcp_server):
    """password/private_key are not in the schema — FastMCP rejects them."""
    async with Client(mcp_server) as client:
        with pytest.raises(Exception, match="private_key_path"):
            await client.call_tool(
                "ssh_add_node",
                {"name": "new-node", "host": "1.2.3.4", "username": "user"},
            )

        with pytest.raises(Exception, match="password"):
            await client.call_tool(
                "ssh_add_node",
                {
                    "name": "new-node",
                    "host": "1.2.3.4",
                    "username": "user",
                    "private_key_path": "/tmp/k.pem",
                    "password": "hunter2",
                },
            )

        with pytest.raises(Exception, match="private_key"):
            await client.call_tool(
                "ssh_add_node",
                {
                    "name": "new-node",
                    "host": "1.2.3.4",
                    "username": "user",
                    "private_key_path": "/tmp/k.pem",
                    "private_key": "FAKE-KEY-CONTENT",
                },
            )


@pytest.mark.asyncio
async def test_add_node_key_path_via_client(mcp_server, mock_pool, db_factory):
    """private_key_path is read server-side; key content never returned to agent."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write("-----BEGIN OPENSSH PRIVATE KEY-----\nFAKE-KEY-CONTENT\n-----END OPENSSH PRIVATE KEY-----\n")
        key_path = f.name

    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "ssh_add_node",
            {
                "name": "key-node",
                "host": "10.0.0.9",
                "username": "deploy",
                "private_key_path": key_path,
            },
        )

    assert "OK: node 'key-node' added" in _result_text(result)

    # Connection pool got the plaintext key, not None
    info = mock_pool.register_node.call_args.args[0]
    assert "FAKE-KEY-CONTENT" in info.private_key

    # DB stored encrypted material, not plaintext
    async with db_factory() as sess:
        node = await NodeRepo(sess).get_by_name("key-node")
    assert node.auth_type == "key"
    assert "FAKE-KEY-CONTENT" not in node.encrypted_credential

    Path(key_path).unlink()


@pytest.mark.asyncio
async def test_add_node_key_path_missing_via_client(mcp_server):
    """A nonexistent key path returns an error instead of a traceback."""
    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "ssh_add_node",
            {
                "name": "ghost",
                "host": "10.0.0.10",
                "private_key_path": "/nonexistent/key.pem",
            },
        )

    assert "key file not found" in _result_text(result)


@pytest.mark.asyncio
async def test_add_node_key_path_not_a_key_via_client(mcp_server):
    """A file whose content is not an SSH private key is rejected."""
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write("DB_PASSWORD=hunter2\n")
        bad_path = f.name

    async with Client(mcp_server) as client:
        result = await client.call_tool(
            "ssh_add_node",
            {
                "name": "sneaky",
                "host": "10.0.0.11",
                "private_key_path": bad_path,
            },
        )

    assert "does not look like an SSH private key" in _result_text(result)
    Path(bad_path).unlink()


# ---------------------------------------------------------------------------
# ssh_run — auto-select single node
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_auto_selects_single_node(mcp_server_with_session):
    """When node is omitted and only one exists, it auto-selects."""
    async with Client(mcp_server_with_session) as client:
        result = await client.call_tool("ssh_run", {"command": "uptime"})

    text = _result_text(result)
    assert "mocked output" in text


@pytest.mark.asyncio
async def test_run_errors_with_no_node_and_multiple(
    mcp_server_with_session, db_factory
):
    """When node is omitted and multiple exist, it should error."""
    async with db_factory() as sess:
        node_repo = NodeRepo(sess)
        await node_repo.create(
            name="second-node",
            host="10.0.0.2",
            port=22,
            username="root",
            auth_type="password",
            encrypted_credential="enc",
        )

    async with Client(mcp_server_with_session) as client:
        result = await client.call_tool("ssh_run", {"command": "uptime"})

    text = _result_text(result)
    assert "cannot auto-select" in text.lower() or "Error" in text
