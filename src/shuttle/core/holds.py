"""Uncertain-band Holds — a bounded human decision inside the LLM gate.

The LLM gate auto-runs unmatched commands only when it is confident they are
safe. Confident-safe commands execute, block/allow rules short-circuit, and
gate failures deny. The band between the hold floor and the safe threshold is
where a human still judges better than the model: those commands park a
**Hold** and wait, at most ``HOLD_WAIT``, for one Operator decision.

A Hold is not an Approval. The requesting agent never receives its id, score,
band, or rule text — only ``Error: awaiting operator`` (retry the identical
bytes) or ``Error: denied by policy[: <note>]`` (replan). The operator's
Denial Note is the one deliberate, operator-authored exception.

This module is the single behavioral seam: injected gate, clock, executor,
and caller-supplied identity against a real database. The web panel is an
adapter over :meth:`HoldManager.decide`.
"""

from __future__ import annotations

import asyncio
import hashlib
import os
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import Enum
from typing import Any, Protocol

from loguru import logger

from shuttle.core.gate import SAFE_THRESHOLD, GatePort
from shuttle.db.repository import HoldRepo, LogRepo

# ── Code constants (bands, caps, wait) — deliberately not configuration ──
HOLD_FLOOR = 0.3
HOLD_WAIT = 20.0
HOLD_TTL = 900
OPEN_HOLD_CAP = 3
DENIAL_NOTE_MAX = 500
MAX_STORED_OUTPUT_BYTES = 64 * 1024
DEFAULT_COMMAND_TIMEOUT = 30.0
_POLL_INTERVAL = 0.05

# The only agent-visible strings.
AWAITING_MESSAGE = "Error: awaiting operator"
DENIED_MESSAGE = "Error: denied by policy"

# Process-local conversation key for transports that expose no MCP session id.
_LOCAL_CONVERSATION_KEY = f"local-{os.getpid()}"


class HoldStatus(str, Enum):
    """Hold lifecycle states. All but pending/executing are terminal."""

    PENDING = "pending"
    EXECUTING = "executing"
    EXECUTED = "executed"
    DENIED = "denied"
    EXPIRED = "expired"
    FAILED = "failed"


class HoldAction(str, Enum):
    """The two Operator decisions. There is no promote and no Grant."""

    RUN_ONCE = "run_once"
    DENY = "deny"


@dataclass
class Execution:
    """The result of one command execution."""

    stdout: str
    exit_code: int | None = None


@dataclass
class HoldOutcome:
    """What ``ssh_run`` should do after triage.

    ``execute`` means the caller runs the command immediately (score at or
    above ``SAFE_THRESHOLD``). Otherwise ``text`` is the exact string to
    return. Any denial triage performed is already logged.
    """

    execute: bool = False
    text: str | None = None
    gate_score: float | None = None


class Executor(Protocol):
    """Runs one exact command for a Hold, independent of the requester."""

    async def __call__(
        self,
        *,
        node_id: str,
        command: str,
        gate_score: float | None = None,
        conversation_key: str | None = None,
    ) -> Execution: ...


def command_hash(command: str) -> str:
    """SHA-256 of the raw command bytes. No whitespace folding, no parsing."""
    return hashlib.sha256(command.encode("utf-8")).hexdigest()


def normalize_note(note: str | None) -> str | None:
    """Collapse a Denial Note to one line, trim it, and cap its length."""
    if note is None:
        return None
    collapsed = " ".join(note.split())
    if not collapsed:
        return None
    return collapsed[:DENIAL_NOTE_MAX]


def conversation_key(ctx: Any) -> str:
    """Server-derived conversation key; never supplied by the agent."""
    if ctx is None:
        return _LOCAL_CONVERSATION_KEY
    try:
        value = ctx.session_id
    except Exception:
        return _LOCAL_CONVERSATION_KEY
    return str(value) if value else _LOCAL_CONVERSATION_KEY


def client_id(ctx: Any) -> str | None:
    """Server-derived client label; panel only, never trusted for identity."""
    if ctx is None:
        return None
    try:
        value = ctx.client_id
    except Exception:
        return None
    return str(value) if value else None


def _as_utc(dt: datetime) -> datetime:
    """SQLite returns naive datetimes — re-attach UTC when missing."""
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def truncate_output(text: str, limit: int) -> str:
    """Truncate *text* to *limit* UTF-8 bytes, marking a truncation."""
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= limit:
        return text
    return encoded[:limit].decode("utf-8", errors="replace") + "\n... [truncated]"


class HoldManager:
    """Hold lifecycle, ``decide``, and decision-triggered execution.

    Parameters
    ----------
    db_session_ctx:
        Async context manager factory yielding an ``AsyncSession``.
    gate:
        The LLM gate port, or None when the server skipped construction.
    settings:
        Runtime config carrying ``gate_enabled``, ``openrouter_api_key``, and
        ``gate_safe_instructions``.
    executor:
        Runs one exact command server-side, independent of the requester.
    clock:
        Injectable UTC clock (tests).
    hold_wait / hold_ttl / open_hold_cap:
        Overridable only for tests; the shipped values are code constants.
    """

    def __init__(
        self,
        *,
        db_session_ctx: Callable[[], AsyncIterator[Any]],
        gate: GatePort | None,
        settings: Any,
        executor: Executor,
        clock: Callable[[], datetime] | None = None,
        hold_wait: float = HOLD_WAIT,
        hold_ttl: float = HOLD_TTL,
        open_hold_cap: int = OPEN_HOLD_CAP,
        poll_interval: float = _POLL_INTERVAL,
    ) -> None:
        self._db = db_session_ctx
        self._gate = gate
        self._settings = settings
        self._executor = executor
        self._clock = clock or (lambda: datetime.now(UTC))
        self._hold_wait = hold_wait
        self._hold_ttl = hold_ttl
        self._open_hold_cap = open_hold_cap
        self._poll_interval = poll_interval
        self._events: dict[str, asyncio.Event] = {}
        self._tasks: set[asyncio.Task] = set()
        # Serializes every open-Hold cap check-and-create so a burst of
        # uncertain commands cannot exceed the cap. One in-process lock (not
        # one per conversation) keeps the critical section atomic without an
        # unbounded key map; the section is a short count + insert. In-process
        # only, consistent with the wait signal's single-process assumption.
        self._cap_lock = asyncio.Lock()

    # -- public seam --------------------------------------------------------

    async def triage(
        self,
        *,
        command: str,
        node: str,
        node_id: str,
        conversation_key: str,
        client_id: str | None = None,
        session_id: str | None = None,
        matched_rule: str | None = None,
    ) -> HoldOutcome:
        """Look up an existing Hold, else score with the gate and apply bands.

        Returns an instruction for ``ssh_run``: execute now, or the exact
        agent-visible string. Gate and lifecycle denials are logged here.
        """
        command_hash_ = command_hash(command)

        existing = await self._get_by_key(conversation_key, node_id, command_hash_)
        if existing is not None:
            return await self._await_hold(existing.id)

        if not self._gate_ready():
            await self._log_denial(
                node_id=node_id,
                command=command,
                session_id=session_id,
                conversation_key=conversation_key,
                matched_rule=matched_rule,
                gate_score=None,
                reason="disabled",
            )
            return HoldOutcome(text=DENIED_MESSAGE)

        try:
            score = await self._gate.is_safe(
                state={"command": command, "node": node},
                instructions=self._settings.gate_safe_instructions,
            )
        except Exception:
            await self._log_denial(
                node_id=node_id,
                command=command,
                session_id=session_id,
                conversation_key=conversation_key,
                matched_rule=matched_rule,
                gate_score=None,
                reason="error",
            )
            return HoldOutcome(text=DENIED_MESSAGE)

        if score >= SAFE_THRESHOLD:
            return HoldOutcome(execute=True, gate_score=score)

        if score < HOLD_FLOOR:
            await self._log_denial(
                node_id=node_id,
                command=command,
                session_id=session_id,
                conversation_key=conversation_key,
                matched_rule=matched_rule,
                gate_score=score,
                reason="unsafe",
            )
            return HoldOutcome(text=DENIED_MESSAGE)

        # Uncertain band. The cap is checked only when the band would Hold,
        # and check-and-create is atomic so concurrent submissions cannot
        # exceed the cap.
        async with self._cap_lock:
            if await self._count_pending(conversation_key) >= self._open_hold_cap:
                await self._log_denial(
                    node_id=node_id,
                    command=command,
                    session_id=session_id,
                    conversation_key=conversation_key,
                    matched_rule=matched_rule,
                    gate_score=score,
                    reason="capped",
                )
                return HoldOutcome(text=DENIED_MESSAGE)

            hold = await self._create_hold(
                conversation_key=conversation_key,
                client_id=client_id,
                node_id=node_id,
                command=command,
                command_hash=command_hash_,
                gate_score=score,
            )
        return await self._await_hold(hold.id)

    async def decide(
        self,
        hold_id: str,
        action: HoldAction,
        *,
        operator: str,
        note: str | None = None,
    ) -> Any | None:
        """Apply one Operator decision to a pending, unexpired Hold.

        Returns the updated Hold, or None when the Hold is missing, already
        decided, or expired (a no-op conflict for the panel adapter).
        """
        row = await self._load(hold_id)
        if row is None or row.status != HoldStatus.PENDING.value:
            return None
        if _as_utc(row.expires_at) <= self._clock():
            await self._mark_expired(hold_id)
            return None

        if action == HoldAction.DENY:
            normalized = normalize_note(note)
            async with self._db() as db:
                decided = await HoldRepo(db).mark_denied(hold_id, operator, normalized)
            if not decided:
                return None
            self._signal(hold_id)
            return await self._load(hold_id)

        if action == HoldAction.RUN_ONCE:
            async with self._db() as db:
                decided = await HoldRepo(db).mark_executing(hold_id, operator)
            if not decided:
                return None
            self._signal(hold_id)
            self._schedule_execution(hold_id)
            return await self._load(hold_id)

        raise ValueError(f"unknown hold action: {action!r}")

    async def recover(self) -> int:
        """Fail executing Holds from a previous run; never re-run them."""

        async with self._db() as db:
            repo = HoldRepo(db)
            failed = await repo.recover_executing()
            await repo.sweep_expired(self._clock())
        if failed:
            logger.warning("Marked {n} interrupted Hold(s) failed at startup", n=failed)
        return failed

    # -- internals ----------------------------------------------------------

    def _gate_ready(self) -> bool:
        return (
            self._gate is not None
            and bool(getattr(self._settings, "gate_enabled", False))
            and bool(getattr(self._settings, "openrouter_api_key", None))
        )

    async def _await_hold(self, hold_id: str) -> HoldOutcome:
        """Wait at most HOLD_WAIT for a decision, else return awaiting.

        A Hold this call parked and saw decided keeps waiting for the
        server-owned execution to finish (bounded by the command timeout), so
        20 + 30 stays under a 60-second client timeout. A Hold that was
        *already* executing when this call arrived only waits HOLD_WAIT.
        """
        deadline = self._clock() + timedelta(seconds=self._hold_wait)
        started_pending: bool | None = None
        extended = False
        try:
            while True:
                row = await self._load(hold_id)
                if row is None:
                    return HoldOutcome(text=DENIED_MESSAGE)

                status = row.status
                if status == HoldStatus.EXECUTED.value:
                    return HoldOutcome(text=row.stdout or "")
                if status == HoldStatus.DENIED.value:
                    return await self._denial_outcome(row, "denied")
                if status == HoldStatus.EXPIRED.value:
                    return await self._denial_outcome(row, "expired")
                if status == HoldStatus.FAILED.value:
                    return await self._denial_outcome(row, "error")

                if started_pending is None:
                    started_pending = status == HoldStatus.PENDING.value
                if status == HoldStatus.EXECUTING.value and started_pending:
                    extended = True

                now = self._clock()
                if (
                    status == HoldStatus.PENDING.value
                    and _as_utc(row.expires_at) <= now
                ):
                    await self._mark_expired(row.id)
                    return await self._denial_outcome(row, "expired")
                if not extended and now >= deadline:
                    return HoldOutcome(text=AWAITING_MESSAGE)

                event = self._events.setdefault(hold_id, asyncio.Event())
                remaining = (
                    max(0.001, self._poll_interval)
                    if extended
                    else max(
                        0.001,
                        min(self._poll_interval, (deadline - now).total_seconds()),
                    )
                )
                try:
                    await asyncio.wait_for(event.wait(), timeout=remaining)
                except TimeoutError:
                    pass
                event.clear()  # avoid a tight loop if the signal outlives its status
        finally:
            self._events.pop(hold_id, None)

    async def _denial_outcome(self, row: Any, reason: str) -> HoldOutcome:
        await self._log_denial(
            node_id=row.node_id,
            command=row.command,
            session_id=None,
            conversation_key=row.conversation_key,
            matched_rule=None,
            gate_score=row.gate_score,
            reason=reason,
        )
        if reason == "denied" and row.denial_note:
            return HoldOutcome(text=f"{DENIED_MESSAGE}: {row.denial_note}")
        return HoldOutcome(text=DENIED_MESSAGE)

    async def _log_denial(
        self,
        *,
        node_id: str,
        command: str,
        session_id: str | None,
        conversation_key: str | None,
        matched_rule: str | None,
        gate_score: float | None,
        reason: str,
    ) -> None:
        try:
            async with self._db() as db:
                await LogRepo(db).create(
                    node_id=node_id,
                    session_id=session_id,
                    command=command,
                    exit_code=None,
                    security_level="gate",
                    security_rule_id=matched_rule,
                    conversation_key=conversation_key,
                    gate_score=gate_score,
                    gate_reason=reason,
                )
        except Exception:
            logger.warning("Failed to persist denial log for {cmd}", cmd=command[:80])

    async def _create_hold(
        self,
        *,
        conversation_key: str,
        client_id: str | None,
        node_id: str,
        command: str,
        command_hash: str,
        gate_score: float,
    ) -> Any:
        from sqlalchemy.exc import IntegrityError

        expires_at = self._clock() + timedelta(seconds=self._hold_ttl)
        try:
            async with self._db() as db:
                return await HoldRepo(db).create(
                    conversation_key=conversation_key,
                    client_id=client_id,
                    node_id=node_id,
                    command=command,
                    command_hash=command_hash,
                    gate_score=gate_score,
                    expires_at=expires_at,
                )
        except IntegrityError:
            # A concurrent identical call won the create; resume that Hold.
            row = await self._get_by_key(conversation_key, node_id, command_hash)
            if row is None:
                raise
            return row

    async def _get_by_key(
        self, conversation_key: str, node_id: str, command_hash: str
    ) -> Any | None:
        async with self._db() as db:
            return await HoldRepo(db).get_by_key(
                conversation_key=conversation_key,
                node_id=node_id,
                command_hash=command_hash,
            )

    async def _load(self, hold_id: str) -> Any | None:
        async with self._db() as db:
            return await HoldRepo(db).get(hold_id)

    async def _count_pending(self, conversation_key: str) -> int:
        async with self._db() as db:
            return await HoldRepo(db).count_pending(conversation_key)

    async def _mark_expired(self, hold_id: str) -> None:
        async with self._db() as db:
            await HoldRepo(db).mark_expired(hold_id)

    # -- decision-triggered execution --------------------------------------

    def _schedule_execution(self, hold_id: str) -> None:
        """Run the command in a server-owned task; never cancellable by a caller."""
        task = asyncio.create_task(self._execute_hold(hold_id))
        self._tasks.add(task)
        task.add_done_callback(self._tasks.discard)

    async def _execute_hold(self, hold_id: str) -> None:
        row = await self._load(hold_id)
        if row is None:
            return
        try:
            result = await self._executor(
                node_id=row.node_id,
                command=row.command,
                gate_score=row.gate_score,
                conversation_key=row.conversation_key,
            )
        except Exception:
            logger.exception("Run-once execution failed for hold {id}", id=hold_id)
            async with self._db() as db:
                await HoldRepo(db).mark_failed(hold_id)
        else:
            async with self._db() as db:
                await HoldRepo(db).set_result(
                    hold_id,
                    stdout=truncate_output(result.stdout, MAX_STORED_OUTPUT_BYTES)
                    if result.stdout
                    else None,
                    exit_code=result.exit_code,
                )
        finally:
            self._signal(hold_id)

    def _signal(self, hold_id: str) -> None:
        event = self._events.get(hold_id)
        if event is not None:
            event.set()
