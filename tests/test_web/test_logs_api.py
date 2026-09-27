"""Tests for the Command Logs API."""

import pytest

from shuttle.db.repository import LogRepo, NodeRepo


@pytest.mark.asyncio
async def test_list_logs_empty(client):
    resp = await client.get("/api/logs")
    assert resp.status_code == 200
    data = resp.json()
    assert data["items"] == []
    assert data["total"] == 0


@pytest.mark.asyncio
async def test_list_logs_with_data(client, db_session):
    # Seed a node and 5 logs
    node_repo = NodeRepo(db_session)
    node = await node_repo.create(
        name="log-node",
        host="10.0.0.1",
        username="root",
        auth_type="password",
        encrypted_credential="enc",
    )

    log_repo = LogRepo(db_session)
    for i in range(5):
        await log_repo.create(
            node_id=node.id,
            command=f"cmd-{i}",
            exit_code=0,
        )

    # Page 1, page_size 3
    resp = await client.get("/api/logs?page=1&page_size=3")
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 3
    assert data["total"] == 5
    assert data["page"] == 1
    assert data["page_size"] == 3


@pytest.mark.asyncio
async def test_list_logs_filter_by_node(client, db_session):
    node_repo = NodeRepo(db_session)
    node_a = await node_repo.create(
        name="node-a",
        host="10.0.0.1",
        username="root",
        auth_type="password",
        encrypted_credential="enc",
    )
    node_b = await node_repo.create(
        name="node-b",
        host="10.0.0.2",
        username="root",
        auth_type="password",
        encrypted_credential="enc",
    )

    log_repo = LogRepo(db_session)
    await log_repo.create(node_id=node_a.id, command="ls")
    await log_repo.create(node_id=node_b.id, command="pwd")

    # Filter by node_a
    resp = await client.get(f"/api/logs?node_id={node_a.id}")
    assert resp.status_code == 200
    data = resp.json()
    assert data["total"] == 1
    assert data["items"][0]["node_name"] == "node-a"
    assert data["items"][0]["command"] == "ls"


@pytest.mark.asyncio
async def test_list_logs_includes_gate_metadata(client, db_session):
    """Denial rows surface gate_score/gate_reason for the audit view."""
    node_repo = NodeRepo(db_session)
    node = await node_repo.create(
        name="gate-node", host="10.0.0.9", username="root", encrypted_credential="enc"
    )
    await LogRepo(db_session).create(
        node_id=node.id,
        command="sudo reboot",
        exit_code=None,
        security_level="gate",
        gate_score=0.11,
        gate_reason="unsafe",
    )

    resp = await client.get("/api/logs")
    assert resp.status_code == 200
    item = resp.json()["items"][0]
    assert item["gate_score"] == 0.11
    assert item["gate_reason"] == "unsafe"
    assert item["exit_code"] is None
