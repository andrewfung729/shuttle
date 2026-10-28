"""Tests for shuttle.mcp.server — create_mcp_server integration test."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from shuttle.mcp.server import _build_gate, create_mcp_server

EXPECTED_TOOLS = {
    "ssh_run",
    "ssh_upload",
    "ssh_download",
    "ssh_add_node",
}


@pytest.mark.asyncio
async def test_create_mcp_server_registers_expected_tools(tmp_path):
    """create_mcp_server returns a FastMCP with all 5 Shuttle tools registered."""
    shuttle_dir = tmp_path / ".shuttle"
    shuttle_dir.mkdir()
    db_url = f"sqlite+aiosqlite:///{tmp_path / 'test.db'}"

    # Mock ConnectionPool to avoid SSH connections and eviction loop
    with (
        patch("shuttle.mcp.server.ConnectionPool") as MockPool,
        patch("shuttle.mcp.server.SessionManager") as MockSessionMgr,
    ):
        mock_pool = MagicMock()
        mock_pool._registry = {}
        mock_pool.start_eviction_loop = AsyncMock()
        mock_pool.register_node = MagicMock()
        MockPool.return_value = mock_pool

        mock_session_mgr = MagicMock()
        mock_session_mgr.list_active.return_value = []
        MockSessionMgr.return_value = mock_session_mgr

        mcp = await create_mcp_server(shuttle_dir=shuttle_dir, db_url=db_url)

    # Verify it's a FastMCP
    from fastmcp import FastMCP

    assert isinstance(mcp, FastMCP)

    # Verify all expected tools are registered
    tools = await mcp.get_tools()
    tool_names = set(tools.keys())
    assert EXPECTED_TOOLS.issubset(tool_names), (
        f"Missing tools: {EXPECTED_TOOLS - tool_names}"
    )


def _gate_config(**overrides):
    values = {
        "gate_enabled": True,
        "openrouter_api_key": "sk-or-test",
        "gate_model": "typesafe/jev-1.13",
        "gate_base_url": "https://openrouter.ai/api",
    }
    values.update(overrides)
    return SimpleNamespace(**values)


def test_build_gate_requires_gate_model():
    """An enabled gate without SHUTTLE_GATE_MODEL is not constructed."""
    with patch("shuttle.mcp.server.TypeSafeGate") as gate_cls:
        assert _build_gate(_gate_config(gate_model=None)) is None
    gate_cls.assert_not_called()


def test_build_gate_uses_configured_model():
    with patch("shuttle.mcp.server.TypeSafeGate") as gate_cls:
        gate = _build_gate(_gate_config(gate_model="jev-1.13.0"))
    assert gate is gate_cls.return_value
    assert gate_cls.call_args.kwargs["model"] == "jev-1.13.0"
