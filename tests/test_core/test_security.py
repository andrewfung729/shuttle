"""Tests for CommandGuard and the three-level SecurityLevel model."""

import pytest
import pytest_asyncio
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine
from sqlalchemy.orm import sessionmaker

from shuttle.core.security import CommandGuard, SecurityLevel
from shuttle.db.models import Base, SecurityRule

# ---------------------------------------------------------------------------
# SecurityLevel enum
# ---------------------------------------------------------------------------


def test_security_level_values():
    """SecurityLevel must expose exactly block / review / allow."""
    assert SecurityLevel.BLOCK == "block"
    assert SecurityLevel.REVIEW == "review"
    assert SecurityLevel.ALLOW == "allow"
    assert {level.value for level in SecurityLevel} == {"block", "review", "allow"}


# ---------------------------------------------------------------------------
# DB fixtures for CommandGuard tests
# ---------------------------------------------------------------------------


@pytest_asyncio.fixture
async def guard_db_engine():
    engine = create_async_engine("sqlite+aiosqlite:///:memory:")
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    yield engine
    await engine.dispose()


@pytest_asyncio.fixture
async def guard_db_session(guard_db_engine):
    async_session = sessionmaker(
        guard_db_engine, class_=AsyncSession, expire_on_commit=False
    )
    async with async_session() as session:
        yield session


async def _seed_sample_rules(session: AsyncSession) -> None:
    """Seed standard sample rules for most tests."""
    rules = [
        SecurityRule(
            pattern=r"rm\s+-rf\s+/",
            level="block",
            priority=10,
            description="Block rm -rf /",
            enabled=True,
        ),
        SecurityRule(
            pattern=r"\bsudo\b",
            level="review",
            priority=20,
            description="Review sudo",
            enabled=True,
        ),
        SecurityRule(
            pattern=r"^ls\b",
            level="allow",
            priority=40,
            description="Allow ls",
            enabled=True,
        ),
    ]
    session.add_all(rules)
    await session.commit()


# ---------------------------------------------------------------------------
# CommandGuard tests
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_evaluate_block(guard_db_session):
    """A command matching a BLOCK rule must be blocked."""
    await _seed_sample_rules(guard_db_session)
    guard = CommandGuard()
    decision = await guard.evaluate("rm -rf /home", "node1", guard_db_session)
    assert decision.level == SecurityLevel.BLOCK
    assert decision.matched_rule is not None


@pytest.mark.asyncio
async def test_evaluate_review(guard_db_session):
    """A command matching a REVIEW rule must produce a review decision."""
    await _seed_sample_rules(guard_db_session)
    guard = CommandGuard()
    decision = await guard.evaluate("sudo apt-get update", "node1", guard_db_session)
    assert decision.level == SecurityLevel.REVIEW
    assert decision.matched_rule is not None


@pytest.mark.asyncio
async def test_evaluate_allow(guard_db_session):
    """A command matching an ALLOW rule must be allowed."""
    await _seed_sample_rules(guard_db_session)
    guard = CommandGuard()
    decision = await guard.evaluate("ls -la", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW
    assert decision.matched_rule is not None


@pytest.mark.asyncio
async def test_no_match_defaults_to_allow(guard_db_session):
    """A command that matches no rule must default to ALLOW."""
    await _seed_sample_rules(guard_db_session)
    guard = CommandGuard()
    decision = await guard.evaluate("echo hello", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW
    assert decision.matched_rule is None


@pytest.mark.asyncio
async def test_evaluate_has_no_bypass_parameter(guard_db_session):
    """The bypass-pattern path is gone: evaluate takes no bypass_patterns."""
    import inspect

    await _seed_sample_rules(guard_db_session)
    guard = CommandGuard()
    sig = inspect.signature(guard.evaluate)
    assert "bypass_patterns" not in sig.parameters

    decision = await guard.evaluate("sudo apt-get update", "node1", guard_db_session)
    assert decision.level == SecurityLevel.REVIEW


@pytest.mark.asyncio
async def test_disabled_rule_ignored(guard_db_session):
    """Rules with enabled=False must not match any command."""
    rule = SecurityRule(
        pattern=r"echo",
        level="block",
        priority=1,
        description="Block echo",
        enabled=False,
    )
    guard_db_session.add(rule)
    await guard_db_session.commit()

    guard = CommandGuard()
    decision = await guard.evaluate("echo hello", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW


@pytest.mark.asyncio
async def test_invalid_regex_skipped(guard_db_session):
    """An invalid regex pattern in the DB should be silently skipped."""
    rule = SecurityRule(
        pattern=r"[invalid",
        level="block",
        priority=1,
        description="Bad regex",
        enabled=True,
    )
    guard_db_session.add(rule)
    await guard_db_session.commit()

    guard = CommandGuard()
    decision = await guard.evaluate("anything", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW


@pytest.mark.asyncio
async def test_unknown_level_rule_skipped(guard_db_session):
    """A rule whose level is not block/review/allow is skipped (legacy rows
    like confirm/warn must never be silently reinterpreted)."""
    guard_db_session.add_all(
        [
            SecurityRule(
                pattern=r"\bsudo\b", level="confirm", priority=1, enabled=True
            ),
            SecurityRule(pattern=r"curl", level="warn", priority=2, enabled=True),
        ]
    )
    await guard_db_session.commit()

    guard = CommandGuard()
    decision = await guard.evaluate("sudo curl http://x", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW


@pytest.mark.asyncio
async def test_node_specific_overrides_global(guard_db_session):
    """A node-specific rule should override a global rule with the same pattern."""
    global_rule = SecurityRule(
        pattern=r"\bsudo\b",
        level="review",
        priority=10,
        description="Global review sudo",
        enabled=True,
        node_id=None,
    )
    node_rule = SecurityRule(
        pattern=r"\bsudo\b",
        level="allow",
        priority=10,
        description="Node-specific allow sudo",
        enabled=True,
        node_id="node1",
    )
    guard_db_session.add_all([global_rule, node_rule])
    await guard_db_session.commit()

    guard = CommandGuard()
    decision = await guard.evaluate("sudo ls", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW


@pytest.mark.asyncio
async def test_evaluate_skips_overlong_regex_pattern(guard_db_session):
    """Patterns longer than 500 chars are ignored (ReDoS guard)."""
    long_pat = "x" * 501
    guard_db_session.add(
        SecurityRule(pattern=long_pat, level="block", priority=1, enabled=True)
    )
    await guard_db_session.commit()
    guard = CommandGuard()
    decision = await guard.evaluate("xxx", "node1", guard_db_session)
    assert decision.level == SecurityLevel.ALLOW


@pytest.mark.asyncio
async def test_evaluate_duplicate_pattern_prefers_node_specific(guard_db_session):
    """When two rules share a pattern, the node-scoped rule wins over global."""
    guard_db_session.add_all(
        [
            SecurityRule(
                pattern=r"^uniquepat\b",
                level="review",
                priority=5,
                enabled=True,
                node_id=None,
            ),
            SecurityRule(
                pattern=r"^uniquepat\b",
                level="block",
                priority=5,
                enabled=True,
                node_id="node1",
            ),
        ]
    )
    await guard_db_session.commit()
    guard = CommandGuard()
    decision = await guard.evaluate("uniquepat foo", "node1", guard_db_session)
    assert decision.level == SecurityLevel.BLOCK
