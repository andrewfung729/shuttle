"""Tests for the approvals web API."""

from datetime import UTC, datetime, timedelta

import pytest
from httpx import ASGITransport, AsyncClient
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from shuttle.db.repository import ApprovalRepo, NodeRepo


async def _make_node(db_session, name="approval-node"):
    return await NodeRepo(db_session).create(
        name=name, host="h", username="u", encrypted_credential="e"
    )


async def _make_pending(db_session, node, *, expires_in=60, command="sudo ls"):
    return await ApprovalRepo(db_session).create(
        node_id=node.id,
        command=command,
        rule_id="r1",
        rule_description="Confirm sudo",
        expires_at=datetime.now(UTC) + timedelta(seconds=expires_in),
    )


@pytest.mark.asyncio
async def test_list_pending_sorted_by_requested_at(client, db_session):
    node = await _make_node(db_session)
    ap1 = await _make_pending(db_session, node, command="a")
    ap2 = await _make_pending(db_session, node, command="b")

    res = await client.get("/api/approvals?status=pending")
    assert res.status_code == 200
    items = res.json()
    ids = [a["id"] for a in items]
    assert ap2.id in ids and ap1.id in ids
    first = items[0]
    assert first["command"] in ("a", "b")
    assert first["node_name"] == "approval-node"
    assert first["status"] == "pending"


@pytest.mark.asyncio
async def test_list_sweeps_expired_before_listing(client, db_session):
    node = await _make_node(db_session)
    await _make_pending(db_session, node, expires_in=-5)

    res = await client.get("/api/approvals?status=pending")
    assert res.status_code == 200
    assert res.json() == []

    res = await client.get("/api/approvals?status=expired")
    assert res.status_code == 200
    assert len(res.json()) == 1


@pytest.mark.asyncio
async def test_get_detail_404(client, db_session):
    res = await client.get("/api/approvals/nope")
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_get_detail_fields(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node)
    await ApprovalRepo(db_session).create(
        node_id=node.id, command="cmd", bypass_scope="session"
    )

    res = await client.get(f"/api/approvals/{ap.id}")
    assert res.status_code == 200
    body = res.json()
    assert body["command"] == "sudo ls"
    assert body["rule_description"] == "Confirm sudo"
    assert body["node_name"] == "approval-node"


@pytest.mark.asyncio
async def test_approve_happy_path_sets_decided_at(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node)

    res = await client.post(f"/api/approvals/{ap.id}/approve")
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "approved"
    assert body["decided_at"] is not None


@pytest.mark.asyncio
async def test_reject_with_reason_stores_it(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node)

    res = await client.post(
        f"/api/approvals/{ap.id}/reject", json={"reason": "too risky"}
    )
    assert res.status_code == 200
    body = res.json()
    assert body["status"] == "rejected"
    assert body["reject_reason"] == "too risky"


@pytest.mark.asyncio
async def test_reject_without_body_still_works(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node)

    res = await client.post(f"/api/approvals/{ap.id}/reject")
    assert res.status_code == 200
    assert res.json()["reject_reason"] is None


@pytest.mark.asyncio
async def test_reject_reason_over_2000_chars_rejected(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node)

    res = await client.post(
        f"/api/approvals/{ap.id}/reject", json={"reason": "x" * 2001}
    )
    assert res.status_code in (400, 422)


@pytest.mark.asyncio
async def test_double_decide_returns_409(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node)

    res = await client.post(f"/api/approvals/{ap.id}/approve")
    assert res.status_code == 200
    res = await client.post(f"/api/approvals/{ap.id}/approve")
    assert res.status_code == 409
    res = await client.post(f"/api/approvals/{ap.id}/reject", json={"reason": "r"})
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_decide_on_expired_returns_409(client, db_session):
    node = await _make_node(db_session)
    ap = await _make_pending(db_session, node, expires_in=-5)

    res = await client.post(f"/api/approvals/{ap.id}/approve")
    assert res.status_code == 409


@pytest.mark.asyncio
async def test_decide_unknown_id_returns_404_distinct_from_409(client, db_session):
    res = await client.post("/api/approvals/nope/approve")
    assert res.status_code == 404
    res = await client.post("/api/approvals/nope/reject", json={"reason": "r"})
    assert res.status_code == 404


@pytest.mark.asyncio
async def test_approvals_require_bearer_token_when_configured(db_engine):
    """With api_token set, approvals endpoints must 401 without credentials."""

    from shuttle.web.app import create_app
    from shuttle.web.deps import get_db_session

    app = create_app(api_token="secret")
    factory = sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)

    async def _override():
        async with factory() as session:
            yield session

    app.dependency_overrides[get_db_session] = _override
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        res = await ac.get("/api/approvals")
        assert res.status_code == 401
        res = await ac.post("/api/approvals/x/approve")
        assert res.status_code == 401
        res = await ac.get("/api/approvals", headers={"Authorization": "Bearer secret"})
        assert res.status_code == 200
