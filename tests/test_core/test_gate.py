"""Tests for the TypeSafeGate port implementation (no network)."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from shuttle.core.gate import GATE_TIMEOUT, SAFE_THRESHOLD, GateError, TypeSafeGate


def _make_gate():
    return TypeSafeGate(
        api_key="sk-test",
        base_url="https://openrouter.ai/api",
        model="typesafe/jev-1.13",
    )


def _answer(score):
    return SimpleNamespace(nouls={"is_safe": SimpleNamespace(noul=score)})


def _client(result):
    return SimpleNamespace(
        system_one=AsyncMock(return_value=result), aclose=AsyncMock()
    )


@pytest.mark.asyncio
async def test_is_safe_returns_calibrated_probability():
    gate = _make_gate()
    gate._client = _client(_answer(0.97))
    score = await gate.is_safe(
        state={"command": "sudo uptime", "node": "n1"}, instructions="be strict"
    )
    assert score == 0.97
    gate._client.system_one.assert_awaited_once()
    kwargs = gate._client.system_one.call_args.kwargs
    assert kwargs["state"] == {"command": "sudo uptime", "node": "n1"}
    assert "is_safe" in kwargs["questions"]


@pytest.mark.asyncio
async def test_is_safe_missing_answer_raises_gate_error():
    gate = _make_gate()
    gate._client = _client(SimpleNamespace(nouls={}))
    with pytest.raises(GateError):
        await gate.is_safe(state={}, instructions="x")


@pytest.mark.asyncio
async def test_is_safe_out_of_range_score_raises_gate_error():
    gate = _make_gate()
    gate._client = _client(_answer(1.5))
    with pytest.raises(GateError):
        await gate.is_safe(state={}, instructions="x")


@pytest.mark.asyncio
async def test_is_safe_sdk_exception_propagates():
    """Transport/timeout errors surface as exceptions — callers treat as error."""
    gate = _make_gate()
    gate._client = SimpleNamespace(
        system_one=AsyncMock(side_effect=TimeoutError("gate timed out")),
        aclose=AsyncMock(),
    )
    with pytest.raises(TimeoutError):
        await gate.is_safe(state={}, instructions="x")


def test_constants():
    assert SAFE_THRESHOLD == 0.9
    assert GATE_TIMEOUT == 2.0
