"""Command security primitives: SecurityLevel, CommandGuard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from loguru import logger
from sqlalchemy import select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SecurityLevel(str, Enum):
    """Security levels used when evaluating a command against security rules."""

    BLOCK = "block"
    REVIEW = "review"
    ALLOW = "allow"


@dataclass
class SecurityDecision:
    """The result produced by CommandGuard.evaluate()."""

    level: SecurityLevel
    matched_rule: str | None = None
    message: str = ""


# ---------------------------------------------------------------------------
# CommandGuard
# ---------------------------------------------------------------------------


class CommandGuard:
    """Evaluates commands against security rules from the database."""

    async def evaluate(
        self,
        command: str,
        node_id: str,
        db_session: AsyncSession,
    ) -> SecurityDecision:
        """Evaluate *command* against security rules fetched from the database.

        Parameters
        ----------
        command:
            The shell command string to inspect.
        node_id:
            Identifier of the target node.
        db_session:
            An async SQLAlchemy session used to query rules.

        Returns
        -------
        SecurityDecision
        """
        from shuttle.db.models import SecurityRule

        query = (
            select(SecurityRule)
            .where(
                SecurityRule.enabled.is_(True),
                (SecurityRule.node_id.is_(None)) | (SecurityRule.node_id == node_id),
            )
            .order_by(SecurityRule.priority, SecurityRule.node_id.nullsfirst())
        )
        result = await db_session.execute(query)
        rules = result.scalars().all()

        # Merge: node-specific overrides global with same pattern
        seen_patterns: dict[str, SecurityRule] = {}
        for rule in rules:
            if rule.pattern in seen_patterns:
                if rule.node_id is not None:
                    seen_patterns[rule.pattern] = rule
            else:
                seen_patterns[rule.pattern] = rule

        for rule in sorted(seen_patterns.values(), key=lambda r: r.priority):
            try:
                # Limit pattern length to prevent ReDoS
                if len(rule.pattern) > 500:
                    continue
                compiled = re.compile(rule.pattern)
                if compiled.search(command):
                    try:
                        level = SecurityLevel(rule.level)
                    except ValueError:
                        # Unknown level (e.g. legacy confirm/warn rows) — skip
                        # rather than silently reinterpret. Consistent with the
                        # invalid-regex skip below.
                        logger.warning(
                            "Skipping rule {id} with unknown level {level!r}",
                            id=rule.id,
                            level=rule.level,
                        )
                        continue
                    return SecurityDecision(
                        level=level,
                        matched_rule=rule.id,
                        message=rule.description or "",
                    )
            except re.error:
                continue

        return SecurityDecision(level=SecurityLevel.ALLOW)
