# 05 — Approvals panel UI

Status: resolved
Blocked by: 04

## Context

Panel surface where the human approves or rejects. React + Vite + Tailwind + Radix + TanStack Query, following the existing pages in `web/src/pages/`.

## Tasks

- [ ] New Approvals page + nav entry:
  - **Pending tab**: command (monospace, full text — no truncation in the dialog), node name, matched rule description, requested-at, live countdown to `expires_at`, Approve / Reject buttons
  - Confirm dialog before acting: shows the full command + node + rule; prominent notice when the row has `bypass_scope="session"` (approving also unlocks the pattern for that session)
  - **Reject dialog carries a reason textarea** — optional but encouraged; placeholder copy makes clear the text is shown to the AI verbatim so it knows how to revise (e.g. "Why is this unsafe? The AI will see this reason."). Approve requires no reason.
  - **History tab**: recent decided/expired/executed rows with decided-at, exit code, and reject reason where present
- [ ] TanStack Query hooks in `web/src/api/`: list (auto-refresh ~3 s while on the page), detail, approve/reject mutations with invalidation
- [ ] API client additions for the four endpoints from ticket 04
- [ ] `npx tsc --noEmit` clean; match existing styling conventions (no new deps unless unavoidable)

## Acceptance criteria

- Manual check: create a confirm-level command via `ssh_run` → appears in the panel within ~3 s → Approve → the waiting/polling `ssh_run` call proceeds; Reject with a reason → the caller's rejection message contains that reason; countdown hits zero → row leaves pending, lands in history as expired.
- Dialog cannot be dismissed into an accidental approve (explicit confirm button).
- `bypass_scope="session"` notice renders from the API response field, not from any separate fetch.

## Notes

- Node name resolution comes from the API response (route layer already resolves it) — do not fetch nodes separately.
- Optional micro-UX (browser notification / sound on new pending item) may ride along if trivial, otherwise defer — see spec Open question 1.

## Comments

Implemented `web/src/pages/Approvals.tsx` + nav entry + TanStack Query hooks (`useApprovals` 3 s refetch on pending, approve/reject mutations with invalidation). Pending tab: full monospace command, node, rule, requested time, per-second countdown, session-bypass notice. Approve dialog shows the full command with explicit Approve button (cancel is the only dismiss path). Reject dialog carries the reason textarea with the verbatim-to-AI placeholder. History tab: status badges, decided-at, exit code, reject reason. `tsc --noEmit` and `vite build` clean. Manual click-through against a live server still to do per ticket 07.
