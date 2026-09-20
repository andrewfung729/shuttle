# 02: LLM gate and denial audit

**What to build:** Review-level commands go through the gate when the gate is enabled. Scores at or above the safe threshold execute; anything else (below threshold, gate failure, disabled gate, missing key) is recorded as a denial in CommandLog and returns `Error: denied by policy`. Denial is always command-local — there is no node quarantine. The gate is called through an injectable port so tests never hit the real endpoint.

**Blocked by:** 01 — Strip Approvals; three Security Levels only

**Status:** resolved

- [x] Config exposes `openrouter_api_key`, `gate_enabled`, `gate_safe_instructions`, `gate_model` (code default `typesafe/jev-1.13`), and `gate_base_url` (default `https://openrouter.ai/api`); safe threshold (~0.9) and gate timeout (~2s) remain code constants
- [x] Gate port: `typesafe-sdk` `AsyncTypeSafeClient` (new dependency) constructed once with `api_key`/`base_url`/`model`/`timeout` from config and retries disabled; one `system_one` call where `state` is `{command, node}` and `questions` is a single `is_safe` noul question whose `instructions` come from config; verdict is `result.nouls["is_safe"].noul`, a calibrated probability; SDK exceptions/timeouts/malformed answers count as not safe (see spec "Gate port" for the request shape)
- [x] `gate_enabled` and key present: review + score ≥ threshold → command executes
- [x] `gate_enabled` and key present: review + score < threshold → `Error: denied by policy`, CommandLog row with `gate_score` and reason `unsafe`
- [x] Gate error/timeout → `Error: denied by policy`, CommandLog row reason `error`
- [x] `gate_enabled` false or missing key: review → `Error: denied by policy`, CommandLog row reason `disabled`
- [x] CommandLog gains `gate_score`/`gate_reason` columns; denied commands are logged, not only executed ones; `approval_id`/`bypassed` columns removed
- [x] The only agent-visible denial string is `Error: denied by policy` — no scores, rule text, or retry recipes
- [x] Tests at the command-orchestration seam cover the matrix with a mock Gate port; repo tests cover gate-metadata persistence
