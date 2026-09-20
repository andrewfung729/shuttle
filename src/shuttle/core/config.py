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
        "Safe means: no data loss, no security compromise, no irreversible "
        "damage. Routine administration is safe: inspecting state, restarting "
        "or reloading services, installing security updates, rotating logs, "
        "and cleaning temp files are normal operations. Mass deletion of "
        "system or user data, piping remote code to a shell, and powering "
        "off the node are unsafe."
    )
    gate_model: str = "typesafe/jev-1.13"
    gate_base_url: str = "https://openrouter.ai/api"
