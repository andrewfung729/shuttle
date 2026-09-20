"""Command security primitives: SecurityLevel, CommandGuard."""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum
from typing import TYPE_CHECKING

from sqlalchemy import select

if TYPE_CHECKING:
    from sqlalchemy.ext.asyncio import AsyncSession


class SecurityLevel(str, Enum):
    """Severity levels used when evaluating a command against security rules."""

    BLOCK = "block"
    CONFIRM = "confirm"
    WARN = "warn"
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
        bypass_patterns: list[str] | None = None,
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
        bypass_patterns:
            A list of rule pattern strings that should be skipped
            (unless the rule is BLOCK).

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

        bypassed = set(bypass_patterns or [])

        for rule in sorted(seen_patterns.values(), key=lambda r: r.priority):
            try:
                # Limit pattern length to prevent ReDoS
                if len(rule.pattern) > 500:
                    continue
                compiled = re.compile(rule.pattern)
                if compiled.search(command):
                    level = SecurityLevel(rule.level)
                    if level == SecurityLevel.BLOCK:
                        return SecurityDecision(
                            level=level,
                            matched_rule=rule.id,
                            message=f"BLOCKED: {rule.description or rule.pattern}",
                        )
                    if rule.pattern in bypassed:
                        continue
                    return SecurityDecision(
                        level=level,
                        matched_rule=rule.id,
                        message=rule.description or "",
                    )
            except re.error:
                continue

        return SecurityDecision(level=SecurityLevel.ALLOW)
