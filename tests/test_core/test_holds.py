"""Tests for shuttle.core.holds — the uncertain-band Hold seam.

One seam: the Hold lifecycle, ``decide``, and decision-triggered execution,
against a real database, with an injected gate, clock, executor, and
caller-supplied identity. External behavior is the returned string plus the
durable Hold and CommandLog rows. No network, no HTTP, no browser.
"""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from types import SimpleNamespace

import pytest
import pytest_asyncio
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import sessionmaker

from shuttle.core.holds import (
    AWAITING_MESSAGE,
    DENIED_MESSAGE,
    HOLD_FLOOR,
    HOLD_TTL,
    HOLD_WAIT,
    OPEN_HOLD_CAP,
    Execution,
    HoldAction,
    HoldManager,
    HoldStatus,
    command_hash,
    normalize_note,
)
from shuttle.db.models import CommandLog, Hold

NODE_ID = "11111111-1111-1111-1111-111111111111"
NODE_NAME = "n1"
CONV = "conv-1"


# ---------------------------------------------------------------------------
# Stubs + helpers
# ---------------------------------------------------------------------------


class StubGate:
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
    """Records executions; optionally blocks until released."""

    def __init__(self, stdout="ran once", exit_code=0, block=None, started=None):
        self.stdout = stdout
        self.exit_code = exit_code
        self.calls: list[dict] = []
        self._block = block
        self._started = started

    async def __call__(
        self, *, node_id, command, gate_score=None, conversation_key=None
    ):
        self.calls.append({"node_id": node_id, "command": command})
        if self._started is not None:
            self._started.set()
        if self._block is not None:
            await self._block.wait()
        return Execution(stdout=self.stdout, exit_code=self.exit_code)


def gate_settings(enabled=True, key="sk-test"):
    return SimpleNamespace(
        gate_enabled=enabled,
        openrouter_api_key=key,
        gate_safe_instructions="Decide if the command is safe.",
    )


@pytest_asyncio.fixture
async def session_factory(db_engine):
    return sessionmaker(db_engine, class_=AsyncSession, expire_on_commit=False)


def make_db_ctx(session_factory):
    @asynccontextmanager
    async def _ctx():
        async with session_factory() as session:
            yield session

    return _ctx


def make_manager(
    session_factory,
    *,
    gate=None,
    settings=None,
    executor=None,
    clock=None,
    hold_wait=HOLD_WAIT,
    hold_ttl=HOLD_TTL,
    open_hold_cap=OPEN_HOLD_CAP,
):
    return HoldManager(
        db_session_ctx=make_db_ctx(session_factory),
        gate=gate,
        settings=settings if settings is not None else gate_settings(),
        executor=executor if executor is not None else StubExecutor(),
        clock=clock,
        hold_wait=hold_wait,
        hold_ttl=hold_ttl,
        open_hold_cap=open_hold_cap,
        poll_interval=0.01,
    )


async def triage(
    manager,
    *,
    command="do something uncertain",
    node=NODE_NAME,
    node_id=NODE_ID,
    conversation_key=CONV,
    client_id="cursor",
    session_id=None,
):
    return await manager.triage(
        command=command,
        node=node,
        node_id=node_id,
        conversation_key=conversation_key,
        client_id=client_id,
        session_id=session_id,
    )


async def get_hold_by_key(
    session_factory, command="do something uncertain", *, conv=CONV
):
    async with session_factory() as session:
        return (
            await session.execute(
                select(Hold).where(
                    Hold.conversation_key == conv,
                    Hold.command_hash == command_hash(command),
                )
            )
        ).scalar_one_or_none()


async def count_holds(session_factory, command="do something uncertain", *, conv=CONV):
    async with session_factory() as session:
        rows = (
            await session.execute(
                select(Hold).where(
                    Hold.conversation_key == conv,
                    Hold.command_hash == command_hash(command),
                )
            )
        ).scalars()
        return len(list(rows))


async def list_logs(session_factory):
    async with session_factory() as session:
        return list(
            (await session.execute(select(CommandLog).order_by(CommandLog.executed_at)))
            .scalars()
            .all()
        )


async def wait_for_status(session_factory, hold_id, status, timeout=2.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with session_factory() as session:
            row = (
                await session.execute(select(Hold).where(Hold.id == hold_id))
            ).scalar_one_or_none()
        if row is not None and row.status == status:
            return row
        await asyncio.sleep(0.01)
    raise AssertionError(f"hold {hold_id} never reached {status}")


# ---------------------------------------------------------------------------
# Bands
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_score_at_threshold_executes_without_hold(session_factory):
    gate = StubGate(score=0.9)
    executor = StubExecutor()
    mgr = make_manager(session_factory, gate=gate, executor=executor)

    outcome = await triage(mgr)

    assert outcome.execute is True
    assert outcome.gate_score == 0.9
    assert executor.calls == []
    assert await count_holds(session_factory) == 0
    assert await list_logs(session_factory) == []


@pytest.mark.asyncio
async def test_score_just_below_threshold_parks_hold_and_awaits(session_factory):
    gate = StubGate(score=0.89)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.05)

    outcome = await triage(mgr)

    assert outcome.text == AWAITING_MESSAGE
    assert outcome.execute is False
    hold = await get_hold_by_key(session_factory)
    assert hold is not None
    assert hold.status == HoldStatus.PENDING.value
    assert hold.gate_score == 0.89
    assert hold.client_id == "cursor"


@pytest.mark.asyncio
async def test_score_at_floor_parks_hold(session_factory):
    gate = StubGate(score=HOLD_FLOOR)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.05)

    outcome = await triage(mgr)

    assert outcome.text == AWAITING_MESSAGE
    assert await count_holds(session_factory) == 1


@pytest.mark.asyncio
async def test_score_below_floor_denies_unsafe_without_hold(session_factory):
    gate = StubGate(score=0.29)
    mgr = make_manager(session_factory, gate=gate)

    outcome = await triage(mgr)

    assert outcome.text == DENIED_MESSAGE
    assert await count_holds(session_factory) == 0
    logs = await list_logs(session_factory)
    assert len(logs) == 1
    assert logs[0].gate_reason == "unsafe"
    assert logs[0].gate_score == 0.29


# ---------------------------------------------------------------------------
# Gate failures deny without a Hold
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_gate_error_denies_error_without_hold(session_factory):
    gate = StubGate(error=TimeoutError("gate timed out"))
    mgr = make_manager(session_factory, gate=gate)

    outcome = await triage(mgr)

    assert outcome.text == DENIED_MESSAGE
    assert await count_holds(session_factory) == 0
    logs = await list_logs(session_factory)
    assert logs[0].gate_reason == "error"
    assert logs[0].gate_score is None


@pytest.mark.asyncio
async def test_gate_disabled_denies_without_hold(session_factory):
    gate = StubGate(score=0.99)
    mgr = make_manager(
        session_factory, gate=gate, settings=gate_settings(enabled=False)
    )

    outcome = await triage(mgr)

    assert outcome.text == DENIED_MESSAGE
    assert gate.calls == []
    assert await count_holds(session_factory) == 0
    assert (await list_logs(session_factory))[0].gate_reason == "disabled"


@pytest.mark.asyncio
async def test_gate_missing_key_denies_without_hold(session_factory):
    gate = StubGate(score=0.99)
    mgr = make_manager(session_factory, gate=gate, settings=gate_settings(key=None))

    outcome = await triage(mgr)

    assert outcome.text == DENIED_MESSAGE
    assert gate.calls == []
    assert (await list_logs(session_factory))[0].gate_reason == "disabled"


@pytest.mark.asyncio
async def test_gate_none_denies_disabled_without_hold(session_factory):
    mgr = make_manager(session_factory, gate=None)

    outcome = await triage(mgr)

    assert outcome.text == DENIED_MESSAGE
    assert (await list_logs(session_factory))[0].gate_reason == "disabled"


# ---------------------------------------------------------------------------
# Decision-triggered execution
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_run_once_inside_wait_returns_stdout_and_runs_once(session_factory):
    gate = StubGate(score=0.5)
    executor = StubExecutor(stdout="once-output", exit_code=0)
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=2.0)

    task = asyncio.create_task(triage(mgr))
    hold = await wait_for_status_any(session_factory, HoldStatus.PENDING.value)
    assert await mgr.decide(hold.id, HoldAction.RUN_ONCE, operator="op") is not None
    outcome = await task

    assert outcome.text == "once-output"
    assert len(executor.calls) == 1
    assert executor.calls[0] == {
        "node_id": NODE_ID,
        "command": "do something uncertain",
    }
    stored = await get_hold_by_key(session_factory)
    assert stored.status == HoldStatus.EXECUTED.value
    assert stored.stdout == "once-output"
    assert stored.exit_code == 0


@pytest.mark.asyncio
async def test_decision_extends_wait_past_hold_wait_into_execution(session_factory):
    """Once decided, the caller waits for execution even past HOLD_WAIT."""
    gate = StubGate(score=0.5)
    started = asyncio.Event()
    release = asyncio.Event()
    executor = StubExecutor(stdout="slow but decided", block=release, started=started)
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=0.05)

    task = asyncio.create_task(triage(mgr))
    hold = await wait_for_status_any(session_factory, HoldStatus.PENDING.value)
    await mgr.decide(hold.id, HoldAction.RUN_ONCE, operator="op")
    await asyncio.wait_for(started.wait(), timeout=1.0)

    # The 0.05 s decision window has elapsed, but the run-once was decided in
    # time, so the caller keeps waiting for its (bounded) execution.
    await asyncio.sleep(0.15)
    assert not task.done()

    release.set()
    outcome = await task
    assert outcome.text == "slow but decided"


@pytest.mark.asyncio
async def test_no_decision_waits_then_awaits_and_retry_collects(session_factory):
    gate = StubGate(score=0.5)
    executor = StubExecutor(stdout="collected")
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=0.05)

    first = await triage(mgr)
    assert first.text == AWAITING_MESSAGE
    assert executor.calls == []

    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.RUN_ONCE, operator="op")

    second = await triage(mgr)

    assert second.text == "collected"
    assert len(executor.calls) == 1


@pytest.mark.asyncio
async def test_retry_while_executing_awaits_then_collects(session_factory):
    gate = StubGate(score=0.5)
    block = asyncio.Event()
    started = asyncio.Event()
    executor = StubExecutor(stdout="slow", block=block, started=started)
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=0.05)

    assert (await triage(mgr)).text == AWAITING_MESSAGE
    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.RUN_ONCE, operator="op")
    await asyncio.wait_for(started.wait(), timeout=1.0)

    mid = await triage(mgr)
    assert mid.text == AWAITING_MESSAGE
    assert len(executor.calls) == 1

    block.set()
    await wait_for_status(session_factory, hold.id, HoldStatus.EXECUTED.value)

    final = await triage(mgr)
    assert final.text == "slow"
    assert len(executor.calls) == 1  # never re-run


@pytest.mark.asyncio
async def test_executed_hold_returns_stored_output_without_rerun(session_factory):
    gate = StubGate(score=0.5)
    executor = StubExecutor(stdout="stored")
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=0.05)

    await triage(mgr)
    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.RUN_ONCE, operator="op")
    await wait_for_status(session_factory, hold.id, HoldStatus.EXECUTED.value)

    out = await triage(mgr)
    assert out.text == "stored"
    assert len(executor.calls) == 1
    assert gate.calls == [
        {
            "state": {"command": "do something uncertain", "node": NODE_NAME},
            "instructions": "Decide if the command is safe.",
        }
    ]


# ---------------------------------------------------------------------------
# Deny + note
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_deny_without_note_returns_fixed_string(session_factory):
    gate = StubGate(score=0.5)
    executor = StubExecutor()
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=0.05)

    await triage(mgr)
    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.DENY, operator="op")

    out = await triage(mgr)
    assert out.text == DENIED_MESSAGE
    assert executor.calls == []


@pytest.mark.asyncio
async def test_deny_with_note_returns_prefixed_note(session_factory):
    gate = StubGate(score=0.5)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.05)

    await triage(mgr)
    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.DENY, operator="op", note="use rsync")

    out = await triage(mgr)
    assert out.text == "Error: denied by policy: use rsync"


@pytest.mark.asyncio
async def test_machine_denials_never_carry_a_note(session_factory):
    mgr = make_manager(session_factory, gate=StubGate(error=RuntimeError("x")))
    out = await triage(mgr)
    assert out.text == DENIED_MESSAGE


@pytest.mark.asyncio
async def test_denied_hold_not_recreated_on_retry(session_factory):
    gate = StubGate(score=0.5)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.05)

    await triage(mgr)
    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.DENY, operator="op", note="no")

    out = await triage(mgr)
    assert out.text == "Error: denied by policy: no"
    assert await count_holds(session_factory) == 1
    assert gate.calls and len(gate.calls) == 1  # second call never re-scored


@pytest.mark.asyncio
async def test_deny_writes_one_denial_log_row_per_call(session_factory):
    gate = StubGate(score=0.5)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.05)

    await triage(mgr)
    hold = await get_hold_by_key(session_factory)
    await mgr.decide(hold.id, HoldAction.DENY, operator="op")

    await triage(mgr)
    logs = await list_logs(session_factory)
    assert [log.gate_reason for log in logs] == ["denied"]


# ---------------------------------------------------------------------------
# Expiry
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_already_expired_hold_denies_without_waiting(session_factory):
    """A new call that finds an expired Hold denies immediately, not after HOLD_WAIT."""
    from shuttle.db.repository import HoldRepo

    async with session_factory() as session:
        await HoldRepo(session).create(
            conversation_key=CONV,
            client_id="cursor",
            node_id=NODE_ID,
            command="do something uncertain",
            command_hash=command_hash("do something uncertain"),
            gate_score=0.5,
            expires_at=datetime(2020, 1, 1, tzinfo=UTC),
        )

    clock = _Clock()
    mgr = make_manager(
        session_factory,
        gate=StubGate(score=0.5),
        clock=clock,
        hold_wait=5.0,
    )

    started = asyncio.get_event_loop().time()
    out = await triage(mgr)
    elapsed = asyncio.get_event_loop().time() - started

    assert out.text == DENIED_MESSAGE
    assert elapsed < 1.0
    refreshed = await get_hold_by_key(session_factory)
    assert refreshed.status == HoldStatus.EXPIRED.value


@pytest.mark.asyncio
async def test_expired_hold_returns_denial_and_is_not_reheld(session_factory):
    clock = _Clock()
    gate = StubGate(score=0.5)
    mgr = make_manager(
        session_factory,
        gate=gate,
        clock=clock,
        hold_wait=0.0,
        hold_ttl=10.0,
    )

    await triage(mgr)
    hold = await get_hold_by_key(session_factory)
    assert hold.status == HoldStatus.PENDING.value

    clock.now += timedelta(seconds=11)
    out = await triage(mgr)

    assert out.text == DENIED_MESSAGE
    assert await count_holds(session_factory) == 1
    refreshed = await get_hold_by_key(session_factory)
    assert refreshed.status == HoldStatus.EXPIRED.value
    assert (await list_logs(session_factory))[0].gate_reason == "expired"


# ---------------------------------------------------------------------------
# Caps
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_open_hold_cap_denies_fourth_without_deleting(session_factory):
    gate = StubGate(score=0.5)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.0, open_hold_cap=3)

    for i in range(3):
        out = await triage(mgr, command=f"uncertain-{i}")
        assert out.text == AWAITING_MESSAGE

    out = await triage(mgr, command="uncertain-3")

    assert out.text == DENIED_MESSAGE
    async with session_factory() as session:
        pending = list(
            (
                await session.execute(
                    select(Hold).where(Hold.status == HoldStatus.PENDING.value)
                )
            )
            .scalars()
            .all()
        )
    assert len(pending) == 3  # cap denial did not delete open Holds
    logs = await list_logs(session_factory)
    assert logs[-1].gate_reason == "capped"


@pytest.mark.asyncio
async def test_open_hold_cap_holds_under_concurrent_submissions(session_factory):
    """A burst of uncertain commands cannot exceed the cap in one conversation."""
    gate = StubGate(score=0.5)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.0, open_hold_cap=3)

    outs = await asyncio.gather(*(triage(mgr, command=f"burst-{i}") for i in range(6)))

    async with session_factory() as session:
        pending = list(
            (
                await session.execute(
                    select(Hold).where(Hold.status == HoldStatus.PENDING.value)
                )
            )
            .scalars()
            .all()
        )
    assert len(pending) == 3

    texts = [o.text for o in outs]
    assert texts.count(AWAITING_MESSAGE) == 3
    assert texts.count(DENIED_MESSAGE) == 3

    logs = await list_logs(session_factory)
    assert sum(1 for log in logs if log.gate_reason == "capped") == 3


@pytest.mark.asyncio
async def test_different_command_still_executes_while_pending(session_factory):
    gate = StubGate(score=0.5)
    mgr = make_manager(session_factory, gate=gate, hold_wait=0.0)

    assert (await triage(mgr, command="uncertain")).text == AWAITING_MESSAGE

    safe_gate = StubGate(score=0.99)
    safe_mgr = make_manager(session_factory, gate=safe_gate, hold_wait=0.0)
    out = await triage(safe_mgr, command="safe-cmd")

    assert out.execute is True
    assert await count_holds(session_factory, "safe-cmd") == 0


# ---------------------------------------------------------------------------
# Restart recovery
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_recover_marks_executing_failed_and_never_reruns(session_factory):
    from shuttle.db.repository import HoldRepo

    gate = StubGate(score=0.5)
    executor = StubExecutor()
    mgr = make_manager(session_factory, gate=gate, executor=executor, hold_wait=0.0)

    # A row left executing with no result by a crashed process.
    async with session_factory() as session:
        repo = HoldRepo(session)
        hold = await repo.create(
            conversation_key=CONV,
            client_id="cursor",
            node_id=NODE_ID,
            command="do something uncertain",
            command_hash=command_hash("do something uncertain"),
            gate_score=0.5,
            expires_at=datetime(2026, 1, 1, tzinfo=UTC) + timedelta(seconds=HOLD_TTL),
        )
        assert await repo.mark_executing(hold.id, "op") is True

    recovered = await mgr.recover()
    assert recovered == 1
    refreshed = await get_hold_by_key(session_factory)
    assert refreshed.status == HoldStatus.FAILED.value

    # A later identical call denies; the abandoned command is never re-run.
    out = await triage(mgr)
    assert out.text == DENIED_MESSAGE
    assert executor.calls == []


# ---------------------------------------------------------------------------
# Constants, hashing, notes
# ---------------------------------------------------------------------------


def test_code_constants():
    assert HOLD_WAIT == 20.0
    assert HOLD_TTL == 900
    assert HOLD_FLOOR == 0.3
    assert OPEN_HOLD_CAP == 3


def test_command_hash_is_stable_and_whitespace_sensitive():
    assert command_hash("echo  hi") == command_hash("echo  hi")
    assert command_hash("echo  hi") != command_hash("echo hi")


def test_normalize_note_collapses_and_caps():
    assert normalize_note(None) is None
    assert normalize_note("   ") is None
    assert normalize_note("a\nb") == "a b"
    assert len(normalize_note("x" * 600)) == 500


# ---------------------------------------------------------------------------
# Local helpers
# ---------------------------------------------------------------------------


class _Clock:
    def __init__(self):
        self.now = datetime(2026, 1, 1, tzinfo=UTC)

    def __call__(self):
        return self.now


async def wait_for_status_any(session_factory, status, timeout=2.0):
    deadline = asyncio.get_event_loop().time() + timeout
    while asyncio.get_event_loop().time() < deadline:
        async with session_factory() as session:
            row = (
                (await session.execute(select(Hold).where(Hold.status == status)))
                .scalars()
                .first()
            )
        if row is not None:
            return row
        await asyncio.sleep(0.01)
    raise AssertionError(f"no hold reached {status}")
