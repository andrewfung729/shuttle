"""LLM Gate — scores review-level commands against a TypeSafe System One endpoint.

The gate is trusted-but-fail-closed: any transport error, timeout, or
malformed answer counts as not safe. Callers depend on the narrow
``GatePort`` interface so tests never hit the real endpoint.

Threat model: the command string is attacker-controlled input to the judge.
It travels in ``state``; the verdict criteria live in ``instructions``. Jev
is decision-only (no text generation, no off-schema output), so there is no
prose channel to hijack — but an attacker can still craft commands that
merely *look* safe. The calibrated probability is the only signal; keep
``SAFE_THRESHOLD`` high.
"""

from __future__ import annotations

import math
from typing import Any, Protocol

# Score >= SAFE_THRESHOLD executes. High on purpose: measured scores are
# polarized (benign reads ~0.99, destructive ~0.01), but context-dependent
# commands like `usermod -aG sudo` land at 0.5-0.7 under permissive
# instructions — a 0.5 bar lets privilege escalation through. A
# false-positive deny is cheap (one refused command, logged). See
# examples/try_jev_gate.py for the measurement.
SAFE_THRESHOLD = 0.9

# The gate sits on the command hot path; Jev's own latency is ~70-500ms.
GATE_TIMEOUT = 2.0


class GateError(Exception):
    """The gate could not produce a usable verdict (malformed / missing answer)."""


class GatePort(Protocol):
    """Narrow port: state + instructions → calibrated P(safe) in [0, 1]."""

    async def is_safe(self, state: Any, instructions: Any) -> float: ...


class TypeSafeGate:
    """GatePort over typesafe-sdk's AsyncTypeSafeClient.

    Point at OpenRouter via ``base_url`` (the SDK appends ``/v1/systemone``);
    TypeSafe direct works too with the default base URL and model
    ``jev-1.13.0``. Construct once at startup and ``aclose()`` on shutdown.
    Retries are disabled — fail fast on the command hot path.
    """

    def __init__(
        self,
        *,
        api_key: str | None,
        base_url: str,
        model: str,
        timeout: float = GATE_TIMEOUT,
    ) -> None:
        from typesafe_sdk import AsyncTypeSafeClient, RetryPolicy

        self._client = AsyncTypeSafeClient(
            api_key=api_key,
            base_url=base_url,
            model=model,
            timeout=timeout,
            retry=RetryPolicy(max_retries=0),
        )

    async def is_safe(self, state: Any, instructions: Any) -> float:
        from typesafe_sdk import Noul

        result = await self._client.system_one(
            # attacker-controlled text goes in state, never in instructions
            state=state,
            questions={"is_safe": Noul(instructions=instructions)},
        )
        try:
            score = result.nouls["is_safe"].noul
        except (KeyError, AttributeError, TypeError) as exc:
            raise GateError("malformed gate answer") from exc
        if not isinstance(score, int | float) or not math.isfinite(score):
            raise GateError(f"gate score not a finite number: {score!r}")
        if not 0.0 <= float(score) <= 1.0:
            raise GateError(f"gate score out of range: {score!r}")
        return float(score)

    async def aclose(self) -> None:
        await self._client.aclose()
