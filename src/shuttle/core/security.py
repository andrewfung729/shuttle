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
    """Disposition after CommandGuard.evaluate().

    ``block`` / ``allow`` are the only valid *rule* levels. ``gate`` is the
    fail-closed default when nothing matches — never stored on a rule row.
    """

    BLOCK = "block"
    ALLOW = "allow"
    GATE = "gate"


# Levels an operator may put on a SecurityRule row.
RULE_LEVELS = frozenset({SecurityLevel.BLOCK, SecurityLevel.ALLOW})


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
            First matching rule wins (by priority). No match → GATE
            (LLM gate). Only an explicit allow rule bypasses the gate.
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
                        level = None
                    # Only block/allow are rule levels. Legacy review/confirm/warn
                    # (and bare "gate") are skipped — never reinterpreted.
                    if level not in RULE_LEVELS:
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

        # Fail closed: unmatched → LLM gate.
        return SecurityDecision(level=SecurityLevel.GATE)
