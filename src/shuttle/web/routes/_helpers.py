"""Shared helpers for web route modules."""

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from shuttle.db.models import Node


async def batch_node_names(db: AsyncSession, node_ids: set[str]) -> dict[str, str]:
    """Load node names for a set of node IDs."""
    if not node_ids:
        return {}
    result = await db.execute(select(Node.id, Node.name).where(Node.id.in_(node_ids)))
    return {row.id: row.name for row in result.all()}
