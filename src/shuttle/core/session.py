"""SSH Session Manager with working-directory tracking via a PWD sentinel.

Design
------
* ``SSHSession`` is a plain dataclass that holds all per-session state
  entirely in memory.
* ``SessionManager`` wraps a ``ConnectionPool`` to run commands.

Invariant: ``mcp.tools._execute_command_logic`` is the single audit point for
command execution — every executed command's CommandLog row is written there.
No execution path may bypass it.
* Every command is wrapped as::

      cd <working_dir> && <command>; echo ---SHUTTLE_PWD---; pwd

  The output is split on the sentinel to extract the new working directory.
* Output is truncated to ``MAX_OUTPUT_BYTES`` (10 MB) before being returned.
"""

from __future__ import annotations

import shlex
import uuid
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

# Maximum output size returned to the caller (10 MB).
MAX_OUTPUT_BYTES = 10 * 1024 * 1024  # 10 MB

PWD_SENTINEL = "---SHUTTLE_PWD---"


# ---------------------------------------------------------------------------
# Enumerations / dataclasses
# ---------------------------------------------------------------------------


class SessionStatus(str, Enum):
    ACTIVE = "active"
    CLOSED = "closed"


@dataclass
class SSHSession:
    """Per-session state tracked by SessionManager.

    Attributes
    ----------
    session_id:
        Unique identifier (UUID4 string) assigned at creation time.
    node_id:
        Logical identifier of the node this session is bound to.
    working_directory:
        Current working directory on the remote host; updated after each
        ``execute()`` call.
    status:
        ``ACTIVE`` until ``close()`` is called.
    env_vars:
        Arbitrary environment variables forwarded to every command.
    """

    session_id: str
    node_id: str
    working_directory: str = "~"
    status: SessionStatus = SessionStatus.ACTIVE
    env_vars: dict[str, str] = field(default_factory=dict)


# ---------------------------------------------------------------------------
# SessionManager
# ---------------------------------------------------------------------------


class SessionManager:
    """Manages SSH sessions backed by a ConnectionPool.

    Parameters
    ----------
    pool:
        An initialised ``ConnectionPool`` with nodes already registered.
    """

    def __init__(self, pool: Any) -> None:
        self._pool = pool
        self._sessions: dict[str, SSHSession] = {}

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def create(self, node_id: str) -> SSHSession:
        """Create a new session for *node_id*.

        Runs ``pwd`` on the remote host to obtain the initial working
        directory, then stores the session in memory.

        Parameters
        ----------
        node_id:
            Must be a registered node in the underlying pool.

        Returns
        -------
        SSHSession
        """
        # Determine the initial working directory
        pwd_result = await self._run_on_node(node_id, "pwd", timeout=10.0)
        working_directory = pwd_result["stdout"].strip() or "~"

        session = SSHSession(
            session_id=str(uuid.uuid4()),
            node_id=node_id,
            working_directory=working_directory,
        )
        self._sessions[session.session_id] = session
        return session

    async def close(self, session_id: str) -> None:
        """Mark a session as closed and remove it from the active registry."""
        session = self._sessions.get(session_id)
        if session is not None:
            session.status = SessionStatus.CLOSED
            del self._sessions[session_id]

    def get(self, session_id: str) -> SSHSession | None:
        """Return the active session for *session_id*, or ``None``."""
        return self._sessions.get(session_id)

    def list_active(self) -> list[SSHSession]:
        """Return all currently active sessions."""
        return list(self._sessions.values())

    # ------------------------------------------------------------------
    # Command execution
    # ------------------------------------------------------------------

    async def execute(
        self,
        session_id: str,
        command: str,
        timeout: float = 30.0,
    ) -> dict:
        """Execute *command* in the context of *session_id*.

        The command is wrapped so that:

        1. The remote shell starts in the session's ``working_directory``.
        2. After the command finishes the remote ``pwd`` is captured via
           ``PWD_SENTINEL`` and the session's ``working_directory`` is updated.

        Parameters
        ----------
        session_id:
            Must belong to an active session.
        command:
            Shell command to run on the remote host.
        timeout:
            Seconds before the remote execution is abandoned.

        Returns
        -------
        dict with keys:
            ``stdout`` — command output (truncated to 10 MB),
            ``exit_status`` — integer exit code,
            ``working_directory`` — updated working directory.

        Raises
        ------
        KeyError
            If *session_id* does not correspond to an active session.
        """
        session = self._sessions.get(session_id)
        if session is None:
            raise KeyError(f"Session '{session_id}' not found or already closed.")

        wrapped = _wrap_command(command, session.working_directory)
        run_result = await self._run_on_node(session.node_id, wrapped, timeout=timeout)

        raw_stdout = run_result["stdout"]
        stderr = run_result["stderr"]
        exit_status = run_result["exit_status"]

        stdout, new_pwd = _parse_sentinel_output(raw_stdout)

        # Truncate output
        if len(stdout.encode()) > MAX_OUTPUT_BYTES:
            stdout = stdout.encode()[:MAX_OUTPUT_BYTES].decode(errors="replace")

        if new_pwd:
            session.working_directory = new_pwd

        return {
            "stdout": stdout,
            "stderr": stderr,
            "exit_status": exit_status,
            "working_directory": session.working_directory,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _run_on_node(
        self, node_id: str, command: str, timeout: float = 30.0
    ) -> dict:
        """Acquire a connection from the pool and run *command*.

        Returns dict with 'stdout', 'stderr', 'exit_status'.
        """
        async with self._pool.connection(node_id) as pc:
            result = await pc.conn.run(command, timeout=timeout, check=False)
            return {
                "stdout": result.stdout or "",
                "stderr": result.stderr or "",
                "exit_status": result.exit_status,
            }


# ---------------------------------------------------------------------------
# Pure functions (exported for testing)
# ---------------------------------------------------------------------------


def _wrap_command(command: str, working_directory: str) -> str:
    """Wrap *command* so it runs in *working_directory* and emits ``PWD_SENTINEL``.

    The working directory is shell-quoted via ``shlex.quote`` to handle paths
    with spaces and special characters safely.

    Returns
    -------
    str
        A shell string of the form::

            cd <quoted_dir> && <command>; echo ---SHUTTLE_PWD---; pwd
    """
    quoted_dir = shlex.quote(working_directory)
    return f"cd {quoted_dir} && {command}; echo {PWD_SENTINEL}; pwd"


def _parse_sentinel_output(raw: str) -> tuple[str, str]:
    """Split *raw* on ``PWD_SENTINEL`` and return (stdout, new_pwd).

    If the sentinel is not present the entire output is returned as stdout
    and new_pwd is an empty string.
    """
    if PWD_SENTINEL in raw:
        parts = raw.split(PWD_SENTINEL, 1)
        stdout = parts[0].rstrip("\n")
        new_pwd = parts[1].strip() if len(parts) > 1 else ""
        return stdout, new_pwd
    return raw, ""
