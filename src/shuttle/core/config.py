"""Shuttle configuration via pydantic-settings (env-var driven)."""

from pathlib import Path

from pydantic_settings import BaseSettings


class ShuttleConfig(BaseSettings):
    """Top-level configuration for the Shuttle SSH gateway.

    All fields can be overridden with environment variables prefixed SHUTTLE_.
    For example: SHUTTLE_WEB_PORT=9000.
    """

    model_config = {"env_prefix": "SHUTTLE_", "env_file": ".env"}

    # Core paths / database
    shuttle_dir: Path = Path.home() / ".shuttle"
    db_url: str = "sqlite+aiosqlite:///~/.shuttle/shuttle.db"

    # Web server
    web_host: str = "127.0.0.1"
    web_port: int = 9876

    # Connection pool settings
    pool_max_total: int = 50
    pool_max_per_node: int = 5
    pool_idle_timeout: int = 300
    pool_max_lifetime: int = 3600
    pool_queue_size: int = 10

    # LLM gate (review-level commands). Fail-closed: with the gate disabled
    # or no API key, review commands are denied (reason=disabled).
    openrouter_api_key: str | None = None
    gate_enabled: bool = False
    gate_safe_instructions: str = (
        "Decide whether the command is safe to execute on the named node. "
        "Answer safe only when the command cannot lose data, weaken security, "
        "or make an irreversible change. Clearly safe: read-only inspection "
        "(listing, reading, searching, checking status, reading logs) and "
        "verifying connectivity. Treat as unsafe: moving, renaming, deleting, "
        "or overwriting any file outside a temp scratch directory; editing or "
        "replacing system or service configuration; changing ownership or "
        "permissions on system paths; installing, upgrading, or removing "
        "packages; stopping, disabling, or reconfiguring a running service; "
        "piping downloaded code to a shell; and powering off or rebooting the "
        "node. Restarting or reloading a service and cleaning temp files are "
        "usually safe. If the effect on a running service or on persistent "
        "data is unclear, treat the command as unsafe."
    )
    gate_model: str = "typesafe/jev-1.13"
    gate_base_url: str = "https://openrouter.ai/api"
