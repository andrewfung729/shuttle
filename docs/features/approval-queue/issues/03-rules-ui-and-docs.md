# 03: Rules UI, denial surface, and domain docs

**What to build:** No replacement panel is needed for Approvals — gate denials are rows in the existing command-log view, shown with score and reason. A denied row can pre-fill the Rules form so a false positive becomes an explicit allow rule. Rules UI only offers block/review/allow. Product docs, MCP prompts, and the domain glossary describe the LLM gate and review level — and no longer describe Approvals, bypass, confirm, or warn.

**Blocked by:** 02 — LLM gate and denial audit

**Status:** resolved

- [x] Approvals page/nav deleted; command-log view shows `gate_score`/`gate_reason` on denied rows
- [x] Denied log row offers a "create allow rule" shortcut that opens the Rules form pre-filled with the command (a human edits and saves the rule; never executes the held command or returns output to the agent)
- [x] Security Rules UI level choices are only `block` | `review` | `allow`
- [x] CONTEXT.md glossary and security/MCP/web docs match the new model; approval-queue protocol and bypass are documented as removed
- [x] MCP prompts/tool copy do not teach approval polling or bypass
