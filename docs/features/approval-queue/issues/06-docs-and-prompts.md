# 06 — Docs + prompts update

Status: resolved
Blocked by: 02, 04

## Context

The confirm-token flow is documented in several places and baked into the MCP prompts that teach AI assistants how to behave. All of it must describe the approval queue, or assistants will follow stale instructions.

## Tasks

- [ ] `docs/security-rules.md`: rewrite the "Confirm Token Mechanism" section → "Approval Queue": pending message, panel approval, `approval_id` re-call (**byte-for-byte, no reformatting**), hybrid wait, TTL, single-use claim, reject reasons, block-still-unkillable. Update the level table's confirm row wording.
- [ ] `docs/web-panel.md`: add the Approvals page (incl. reject-reason textarea); call out that panel **auth is security-relevant now** — deployments exposing the panel must set `api_token` (approving is a capability).
- [ ] `docs/api.md`: the four `/api/approvals` endpoints, incl. the optional `{reason}` body on reject and its 2000-char cap.
- [ ] `docs/TOOL_OUTPUT_FORMAT.md` / `docs/TOOLS_V2_FEATURES.md`: `ssh_run` signature change (`confirm_token` removed; `approval_id`, `approval_wait` added) + new output shapes (pending / rejected-with-reason / expired / already-used).
- [ ] `src/shuttle/mcp/prompts.py`: line ~82 (`require explicit confirmation token`) and lines ~160-161 (`get a confirm_token, then call ssh_run() again with that token`) → approval-queue instructions — must state explicitly: re-send the command **verbatim**, keep `bypass_scope` if the intent was session bypass, and read the `Reason:` line on rejection before deciding how to revise.
- [ ] `src/shuttle/mcp/resources.py` + tool docstrings: sweep for token-flow mentions (`grep -rn "confirm_token\|confirm token" src/ docs/` should come back clean or only historical).
- [ ] `docs/troubleshooting.md`: add "approval expired before I could decide", "AI says approval already used", and "rejected with a reason the AI keeps ignoring" entries.

## Acceptance criteria

- `grep -rn "confirm_token" src/ docs/` returns nothing outside this feature's docs (spec/ADR/issues).
- Docs build/render fine; a fresh reader can run the full confirm → approve → execute loop from `security-rules.md` alone, and knows what a rejection reason looks like on the AI side.

## Notes

- Version bump / release notes are handled by `docs/RELEASE_PROCESS.md`, not this ticket — but the breaking-change callout text for the changelog should be drafted here.

## Comments

security-rules.md ("Approval Queue" section), web-panel.md (Approvals page + auth-is-a-capability callout), api.md (new ssh_run signature), troubleshooting.md (3 new entries), prompts.py (both CONFIRM mentions), CHANGELOG breaking-change callout drafted. `grep -rn confirm_token src/ docs/` is clean outside this feature dir, the ADR (historical record) and frozen docs/superpowers/ plans.
