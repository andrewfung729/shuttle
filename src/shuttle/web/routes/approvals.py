"""Approvals API endpoints — human decision surface for the approval queue."""

from typing import Literal

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from shuttle.db.repository import ApprovalRepo
from shuttle.web.deps import get_db_session
from shuttle.web.routes._helpers import batch_node_names
from shuttle.web.schemas import ApprovalResponse

router = APIRouter(tags=["approvals"])

MAX_REASON_LENGTH = 2000


class RejectRequest(BaseModel):
    reason: str | None = Field(None, max_length=MAX_REASON_LENGTH)


def _to_response(ap, node_names: dict[str, str]) -> ApprovalResponse:
    return ApprovalResponse(
        id=ap.id,
        command=ap.command,
        node_id=ap.node_id,
        node_name=node_names.get(ap.node_id),
        session_id=ap.session_id,
        rule_id=ap.rule_id,
        rule_description=ap.rule_description,
        bypass_scope=ap.bypass_scope,
        status=ap.status,
        requested_at=ap.requested_at,
        expires_at=ap.expires_at,
        decided_at=ap.decided_at,
        decided_by=ap.decided_by,
        reject_reason=ap.reject_reason,
        executed_at=ap.executed_at,
        exec_exit_code=ap.exec_exit_code,
    )


@router.get("/approvals", response_model=list[ApprovalResponse])
async def list_approvals(
    status_filter: Literal["pending", "approved", "rejected", "expired", "executed"]
    | None = Query(None, alias="status"),
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db_session),
):
    """List approvals, optionally filtered by status. Sweeps expired pending rows first."""
    repo = ApprovalRepo(db)
    await repo.sweep_expired()
    approvals = await repo.list(status=status_filter, limit=limit)
    node_names = await batch_node_names(db, {a.node_id for a in approvals})
    return [_to_response(a, node_names) for a in approvals]


@router.get("/approvals/{approval_id}", response_model=ApprovalResponse)
async def get_approval(
    approval_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    repo = ApprovalRepo(db)
    ap = await repo.get(approval_id)
    if ap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    node_names = await batch_node_names(db, {ap.node_id})
    return _to_response(ap, node_names)


@router.post("/approvals/{approval_id}/approve", response_model=ApprovalResponse)
async def approve_approval(
    approval_id: str,
    db: AsyncSession = Depends(get_db_session),
):
    repo = ApprovalRepo(db)
    ap = await repo.get(approval_id)
    if ap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    if not await repo.decide(approval_id, "approved"):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Approval is not decidable (already decided or expired)",
        )
    ap = await repo.get(approval_id)
    node_names = await batch_node_names(db, {ap.node_id})
    return _to_response(ap, node_names)


@router.post("/approvals/{approval_id}/reject", response_model=ApprovalResponse)
async def reject_approval(
    approval_id: str,
    body: RejectRequest | None = None,
    db: AsyncSession = Depends(get_db_session),
):
    repo = ApprovalRepo(db)
    ap = await repo.get(approval_id)
    if ap is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "Approval not found")
    reason = body.reason if body is not None else None
    if reason is not None and len(reason) > MAX_REASON_LENGTH:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            f"Reason must be at most {MAX_REASON_LENGTH} characters",
        )
    if not await repo.decide(approval_id, "rejected", reason=reason):
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "Approval is not decidable (already decided or expired)",
        )
    ap = await repo.get(approval_id)
    node_names = await batch_node_names(db, {ap.node_id})
    return _to_response(ap, node_names)
