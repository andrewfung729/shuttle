"""Smoke tests for the Holds panel adapter.

The behavioral seam is ``core/holds.py``; these tests only check that the
HTTP adapter lists context and routes both Operator actions through
``HoldManager.decide``. No UI or sidebar concerns.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from shuttle.core.holds import Execution, HoldManager
from shuttle.db.repository import HoldRepo, LogRepo, NodeRepo
from shuttle.web.deps import set_holds_manager


class _Gate:
    async def is_safe(self, state, instructions):
        return 0.5


class _Executor:
    def __init__(self):
        self.calls = 0

    async def __call__(
        self, *, node_id, command, gate_score=None, conversation_key=None
    ):
        self.calls += 1
        return Execution(stdout="adapter output", exit_code=0)


@pytest_asyncio.fixture
async def holds_manager(db_engine):
    factory = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    @asynccontextmanager
    async def db_ctx():
        async with factory() as session:
            yield session

    manager = HoldManager(
        db_session_ctx=db_ctx,
        gate=_Gate(),
        settings=SimpleNamespace(
            gate_enabled=True,
            openrouter_api_key="sk-test",
            gate_safe_instructions="be strict",
        ),
        executor=_Executor(),
        hold_wait=0.0,
    )
    set_holds_manager(manager)
    async with factory() as session:
        await NodeRepo(session).create(
            name="node-a",
            host="10.0.0.1",
            username="root",
            auth_type="password",
            encrypted_credential="enc",
        )
    yield manager
    set_holds_manager(None)


@pytest_asyncio.fixture
async def pending_hold(db_engine, holds_manager):
    factory = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)
    async with factory() as session:
        node = await NodeRepo(session).get_by_name("node-a")
        repo = HoldRepo(session)
        hold = await repo.create(
            conversation_key="conv-api",
            client_id="cursor",
            node_id=node.id,
            command="usermod -aG sudo bob",
            command_hash="hash-1",
            gate_score=0.55,
            expires_at=datetime.now(UTC) + timedelta(seconds=900),
        )
        await LogRepo(session).create(
            node_id=node.id,
            command="whoami",
            conversation_key="conv-api",
            security_level="gate",
            exit_code=0,
        )
        return hold.id


@pytest.mark.asyncio
async def test_list_holds_shows_context(pending_hold, client):
    resp = await client.get("/api/holds", params={"status": "pending"})

    assert resp.status_code == 200
    items = resp.json()
    assert len(items) == 1
    item = items[0]
    assert item["command"] == "usermod -aG sudo bob"
    assert item["node_name"] == "node-a"
    assert item["client_id"] == "cursor"
    assert item["gate_score"] == 0.55
    assert [c["command"] for c in item["recent_commands"]] == ["whoami"]


@pytest.mark.asyncio
async def test_run_once_through_adapter(pending_hold, client, holds_manager):
    resp = await client.post(f"/api/holds/{pending_hold}/run", json={})

    assert resp.status_code == 200
    # decide marks executing; the server-owned task may already have finished.
    assert resp.json()["status"] in {"executing", "executed"}
    assert holds_manager._executor.calls == 1


@pytest.mark.asyncio
async def test_deny_through_adapter_with_note(pending_hold, client):
    resp = await client.post(
        f"/api/holds/{pending_hold}/deny", json={"note": "use rsync"}
    )

    assert resp.status_code == 200
    body = resp.json()
    assert body["status"] == "denied"
    assert body["denial_note"] == "use rsync"


@pytest.mark.asyncio
async def test_decide_unknown_hold_conflicts(client, holds_manager):
    resp = await client.post("/api/holds/does-not-exist/deny", json={})
    assert resp.status_code == 409
