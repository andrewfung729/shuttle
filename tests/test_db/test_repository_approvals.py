"""Tests for ApprovalRepo — pending_approvals state machine."""

from datetime import UTC, datetime, timedelta

import pytest

from shuttle.db.repository import ApprovalRepo, NodeRepo


def _utc(dt: datetime) -> datetime:
    """SQLite (aiosqlite) returns naive datetimes — re-attach UTC for comparisons."""
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


@pytest.mark.asyncio
async def test_create_defaults_pending(db_session):
    node = await NodeRepo(db_session).create(
        name="n1", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="sudo systemctl restart nginx",
        rule_id="r1",
        rule_description="systemctl",
    )
    assert ap.id
    assert ap.status == "pending"
    assert ap.command == "sudo systemctl restart nginx"
    assert ap.node_id == node.id
    assert ap.session_id is None
    assert ap.bypass_scope is None
    assert ap.reject_reason is None
    assert ap.decided_by is None
    assert ap.exec_exit_code is None
    assert ap.requested_at is not None
    assert _utc(ap.expires_at) > datetime.now(UTC)


@pytest.mark.asyncio
async def test_decide_approved_happy_path(db_session):
    node = await NodeRepo(db_session).create(
        name="n2", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    assert await repo.decide(ap.id, "approved") is True
    row = await repo.get(ap.id)
    assert row.status == "approved"
    assert row.decided_at is not None


@pytest.mark.asyncio
async def test_decide_already_decided_returns_false(db_session):
    node = await NodeRepo(db_session).create(
        name="n3", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    assert await repo.decide(ap.id, "approved") is True
    # Second decide on the same row must fail (conditional update).
    assert await repo.decide(ap.id, "approved") is False
    assert await repo.decide(ap.id, "rejected") is False


@pytest.mark.asyncio
async def test_decide_expired_row_returns_false(db_session):
    node = await NodeRepo(db_session).create(
        name="n4", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) - timedelta(seconds=1),
    )
    assert ap.status == "pending"
    assert await repo.decide(ap.id, "approved") is False


@pytest.mark.asyncio
async def test_decide_unknown_id_returns_false(db_session):
    assert await ApprovalRepo(db_session).decide("nope", "approved") is False


@pytest.mark.asyncio
async def test_reject_stores_reason(db_session):
    node = await NodeRepo(db_session).create(
        name="n5", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    assert await repo.decide(ap.id, "rejected", reason="too dangerous") is True
    row = await repo.get(ap.id)
    assert row.status == "rejected"
    assert row.reject_reason == "too dangerous"


@pytest.mark.asyncio
async def test_claim_race_second_claim_loses(db_session):
    node = await NodeRepo(db_session).create(
        name="n6", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    await repo.decide(ap.id, "approved")
    assert await repo.claim(ap.id) is True
    # Second claim must lose — status is already executed.
    assert await repo.claim(ap.id) is False
    row = await repo.get(ap.id)
    assert row.status == "executed"
    assert row.executed_at is not None


@pytest.mark.asyncio
async def test_claim_pending_or_rejected_fails(db_session):
    node = await NodeRepo(db_session).create(
        name="n7", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    # Claim before any decision — must fail.
    assert await repo.claim(ap.id) is False
    await repo.decide(ap.id, "rejected")
    assert await repo.claim(ap.id) is False


@pytest.mark.asyncio
async def test_claim_refuses_expired_approved_row_via_sql(db_session):
    """Approved row past TTL must refuse to claim — refusal from the SQL predicate."""
    node = await NodeRepo(db_session).create(
        name="n8", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    await repo.decide(ap.id, "approved")
    # Force expires_at into the past directly — no status change.
    ap.expires_at = datetime.now(UTC) - timedelta(seconds=1)
    db_session.add(ap)
    await db_session.commit()
    assert await repo.claim(ap.id) is False
    row = await repo.get(ap.id)
    assert row.status == "approved"  # untouched


@pytest.mark.asyncio
async def test_sweep_expired_flips_only_stale_pending(db_session):
    node = await NodeRepo(db_session).create(
        name="n9", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    stale = await repo.create(
        node_id=node.id,
        command="a",
        expires_at=_utc(datetime.now(UTC)) - timedelta(seconds=5),
    )
    fresh = await repo.create(
        node_id=node.id,
        command="b",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    approved_stale = await repo.create(
        node_id=node.id,
        command="c",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    await repo.decide(approved_stale.id, "approved")
    # Force its expiry into the past after approval.
    approved_stale.expires_at = datetime.now(UTC) - timedelta(seconds=5)
    db_session.add(approved_stale)
    await db_session.commit()

    count = await repo.sweep_expired()
    assert count == 1
    assert (await repo.get(stale.id)).status == "expired"
    assert (await repo.get(fresh.id)).status == "pending"
    assert (await repo.get(approved_stale.id)).status == "approved"


@pytest.mark.asyncio
async def test_set_exec_result_backfills_exit_code(db_session):
    node = await NodeRepo(db_session).create(
        name="n10", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap = await repo.create(
        node_id=node.id,
        command="cmd",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    await repo.decide(ap.id, "approved")
    await repo.claim(ap.id)
    await repo.set_exec_result(ap.id, 2)
    row = await repo.get(ap.id)
    assert row.exec_exit_code == 2


@pytest.mark.asyncio
async def test_list_filters_by_status(db_session):
    node = await NodeRepo(db_session).create(
        name="n11", host="h", username="u", encrypted_credential="e"
    )
    repo = ApprovalRepo(db_session)
    ap1 = await repo.create(
        node_id=node.id,
        command="a",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    ap2 = await repo.create(
        node_id=node.id,
        command="b",
        expires_at=_utc(datetime.now(UTC)) + timedelta(seconds=60),
    )
    await repo.decide(ap2.id, "approved")

    pending = await repo.list(status="pending")
    assert [a.id for a in pending] == [ap1.id]
    approved = await repo.list(status="approved")
    assert [a.id for a in approved] == [ap2.id]
    assert len(await repo.list()) == 2
