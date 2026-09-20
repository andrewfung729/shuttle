# AGENTS.md

Instructions for AI coding agents working in this repository.

## Project Overview

**Shuttle** (`shuttle-mcp` on PyPI) is a secure SSH gateway for AI assistants — an MCP server that lets tools like Claude Code and Cursor execute commands on remote SSH servers with connection pooling, session isolation, 4-level command safety rules, per-node security policies, and a web audit panel.

- Python ≥ 3.12, managed with **uv** (not pip)
- Backend: FastMCP + asyncssh + FastAPI + SQLAlchemy (async, aiosqlite) + Typer
- Frontend: React + Vite + Tailwind + Radix (in `web/`, pnpm)

> **This is a fork.** Upstream is [`enwaiax/shuttle`](https://github.com/enwaiax/shuttle); `origin` points at the fork `andrewfung729/shuttle`. Bug reports and feature PRs belong upstream; PyPI publishing (`release.yml`) is an upstream-only workflow — don't tag releases here. To pull upstream changes: `git fetch upstream && git merge upstream/main` (add the remote with `git remote add upstream https://github.com/enwaiax/shuttle.git` if missing).

## Commands

```bash
# Setup
uv sync --dev                      # Python deps
uv run pre-commit install          # git hooks
cd web && pnpm install             # frontend deps

# Run locally
uv run shuttle serve               # backend (MCP + web panel)
cd web && npm run dev              # frontend (hot reload, second terminal)

# Checks (run before committing)
uv run ruff check src/ tests/      # lint
uv run ruff format src/ tests/     # format
uv run pytest                      # tests (asyncio_mode = auto)
uv run pytest -m "not slow"        # skip slow tests
cd web && npx tsc --noEmit         # frontend type check
uv run pre-commit run --all-files  # everything at once
```

## Project Structure

```
src/shuttle/
├── cli.py              # Typer CLI entrypoint (`shuttle`, `shuttle-mcp`)
├── core/               # Connection pool, sessions, security rules, credentials, proxy
├── db/                 # SQLAlchemy models, engine, repositories, seeds
├── mcp/                # MCP server, tools, prompts, resources
└── web/                # FastAPI app, routes/, schemas (web audit panel API)

web/                    # React frontend (Vite + Tailwind + Radix)
├── src/pages/          # Route pages
├── src/components/     # Shared UI components
├── src/hooks/          # React hooks
└── src/api/            # API client (TanStack Query)

tests/                  # pytest suites mirroring src layout (test_core/, test_db/, test_mcp/, test_web/)
docs/                   # Documentation site (Zensical); docs/features/ = issue tracker
```

## Conventions

- **Style:** Ruff, 88-char lines, double quotes, isort; `E501` ignored (formatter handles it). Target py312 — use modern syntax (`X | Y` unions, etc.).
- **Tests:** pytest with `-W error` (warnings fail). Markers: `slow`, `integration` (real SSH). Keep tests async-friendly — `asyncio_mode = "auto"` means no `@pytest.mark.asyncio` needed.
- **Commits:** Conventional Commits (`feat:`, `fix:`, `docs:`, `chore:` …). Branch prefixes: `feat/`, `fix/`, `docs/`, `chore/` (see this fork's `af/…` branches).
- **PRs:** target the upstream repo `enwaiax/shuttle`, not the fork.
- **Version:** single source of truth is `src/shuttle/__init__.py` (hatch reads it). Bump via the release process in `docs/RELEASE_PROCESS.md`.
- **Security-sensitive code:** `core/security.py` (command safety rules) and `core/credentials.py` — read `docs/security-rules.md` before changing rule semantics, and add tests.

## Gotchas

- Wheel build packs `src/shuttle/web/static/**` as build artifacts — frontend changes need a rebuild before release.
- `web/package-lock.json` is a leftover from the npm era; pnpm (`pnpm-lock.yaml`) is the package manager now. Don't run `npm install`.
- `filterwarnings = ["error"]` means new deprecation warnings from dependencies will fail tests; suppress deliberately with an `ignore::` entry and a comment.
- `examples/` is excluded from ruff.
- The repo has both a primary CLI name (`shuttle`) and a PyPI-name alias (`shuttle-mcp`) — both point to `shuttle.cli:app`.

## Agent skills

### Issue tracker

Issues live as local markdown files under `docs/features/<feature-slug>/`. See `docs/agents/issue-tracker.md`.

### Triage labels

Five canonical triage roles, label strings equal to the role names. See `docs/agents/triage-labels.md`.

### Domain docs

Single-context layout: `CONTEXT.md` at the repo root + `docs/adr/`. See `docs/agents/domain.md`.
