"""Holds API — the Operator's decision surface for uncertain-band commands.

This is an adapter over ``HoldManager.decide``: the panel lists pending Holds
with context and applies one of two actions, *run once* or *deny* (with an
optional Denial Note). The requesting agent can never reach this surface; it
is gated by the existing panel bearer like every other ``/api`` route.
"""

from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.ext.asyncio import AsyncSession

from shuttle.core.holds import HoldAction
from shuttle.db.models import CommandLog, Hold
from shuttle.db.repository import HoldRepo, LogRepo
from shuttle.web.deps import get_db_session, get_holds_manager
from shuttle.web.routes._helpers import batch_node_names
from shuttle.web.schemas import HoldDecisionRequest, HoldResponse

router = APIRouter(tags=["holds"])

RECENT_COMMAND_LIMIT = 10


async def _to_response(
    db: AsyncSession, hold: Hold, node_names: dict[str, str]
) -> HoldResponse:
    logs = await LogRepo(db).list_by_conversation(
        hold.conversation_key, limit=RECENT_COMMAND_LIMIT
    )
    return HoldResponse(
        id=hold.id,
        conversation_key=hold.conversation_key,
        client_id=hold.client_id,
        node_id=hold.node_id,
        node_name=node_names.get(hold.node_id),
        command=hold.command,
        gate_score=hold.gate_score,
        status=hold.status,
        operator=hold.operator,
        denial_note=hold.denial_note,
        created_at=hold.created_at,
        expires_at=hold.expires_at,
        decided_at=hold.decided_at,
        executed_at=hold.executed_at,
        exit_code=hold.exit_code,
        stdout=hold.stdout,
        recent_commands=[_log_to_response(log) for log in logs],
    )


def _log_to_response(log: CommandLog) -> dict:
    return {
        "id": log.id,
        "session_id": log.session_id,
        "node_id": log.node_id,
        "node_name": None,
        "command": log.command,
        "exit_code": log.exit_code,
        "stdout": log.stdout,
        "stderr": log.stderr,
        "security_level": log.security_level,
        "security_rule_id": log.security_rule_id,
        "gate_score": log.gate_score,
        "gate_reason": log.gate_reason,
        "duration_ms": log.duration_ms,
        "executed_at": log.executed_at,
    }


@router.get("/holds", response_model=list[HoldResponse])
async def list_holds(
    status_filter: str | None = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=200),
    db: AsyncSession = Depends(get_db_session),
):
    """List Holds, optionally filtered by status. Sweeps expired pending rows."""
    repo = HoldRepo(db)
    await repo.sweep_expired(datetime.now(UTC))
    holds = await repo.list(status=status_filter, limit=limit)
    node_names = await batch_node_names(db, {h.node_id for h in holds})
    return [await _to_response(db, hold, node_names) for hold in holds]


async def _decide(
    db: AsyncSession,
    hold_id: str,
    action: HoldAction,
    body: HoldDecisionRequest | None,
) -> HoldResponse:
    holds = get_holds_manager()
    if holds is None:
        raise HTTPException(
            status.HTTP_503_SERVICE_UNAVAILABLE,
            "Hold decisions are not available in this process",
        )
    operator = body.operator if body is not None else "operator"
    note = body.note if body is not None else None
    decided = await holds.decide(hold_id, action, operator=operator, note=note)
    if decided is None:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Hold is not decidable (missing, already decided, or expired)",
        )
    hold = await HoldRepo(db).get(hold_id)
    if hold is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Hold not found")
    node_names = await batch_node_names(db, {hold.node_id})
    return await _to_response(db, hold, node_names)


@router.post("/holds/{hold_id}/run", response_model=HoldResponse)
async def run_hold(
    hold_id: str,
    body: HoldDecisionRequest | None = None,
    db: AsyncSession = Depends(get_db_session),
):
    """Run the held command once; the output is stored on the Hold for pickup."""
    return await _decide(db, hold_id, HoldAction.RUN_ONCE, body)


@router.post("/holds/{hold_id}/deny", response_model=HoldResponse)
async def deny_hold(
    hold_id: str,
    body: HoldDecisionRequest | None = None,
    db: AsyncSession = Depends(get_db_session),
):
    """Deny the held command, optionally attaching a Denial Note."""
    return await _decide(db, hold_id, HoldAction.DENY, body)
