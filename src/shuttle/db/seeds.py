"""Default security rule seeds for Shuttle.

Inserted on first startup if no rules exist. Rule levels are only
``block`` / ``allow``; unmatched commands take the ``gate`` disposition
(LLM gate) — there is no ``review`` rule level.
"""

from __future__ import annotations

# Whitelist tail for allow rules: chars that carry no shell semantics may
# follow the prefix up to end-of-line. Everything else — ``;|&`` chains,
# newlines, ``>``/``<`` redirects, ``$()``/backtick substitution, parens,
# braces, globs — falls through to the gate. Commands run through a real
# shell (``conn.run``), so any of those would execute unchecked.
_NO_CHAIN = r"[\w \t.,:/=@%+'~-]*$"

DEFAULT_SECURITY_RULES = [
    # ------------------------------------------------------------------ block
    # Irreversible host destruction only — everything else is gated.
    # ``rm`` patterns are flag-order agnostic (``-rf``, ``-fr``, long opts).
    # Root wipe
    {
        "pattern": r"rm\s+.*--no-preserve-root",
        "level": "block",
        "description": "rm --no-preserve-root",
        "priority": 1,
    },
    {
        "pattern": r"rm\s+.*\s/\s*$",
        "level": "block",
        "description": "Remove root filesystem",
        "priority": 2,
    },
    {
        "pattern": r"rm\s+.*\s/\*",
        "level": "block",
        "description": "Remove root via glob",
        "priority": 3,
    },
    {
        "pattern": r"rm\s+.*\s/(usr|home|var|etc|boot)(/|\s|$)",
        "level": "block",
        "description": "Recursive delete of critical mount",
        "priority": 4,
    },
    # Storage / partition destruction
    {
        "pattern": r"mkfs\.",
        "level": "block",
        "description": "Format filesystem",
        "priority": 5,
    },
    {
        "pattern": r"\bmkswap\b",
        "level": "block",
        "description": "Create swap on device",
        "priority": 6,
    },
    {
        "pattern": r"dd\s+.*of=/dev/",
        "level": "block",
        "description": "Raw disk write",
        "priority": 7,
    },
    {
        "pattern": r"\bwipefs\b",
        "level": "block",
        "description": "Wipe filesystem signatures",
        "priority": 8,
    },
    {
        "pattern": r"\bblkdiscard\b",
        "level": "block",
        "description": "Discard device blocks",
        "priority": 9,
    },
    {
        "pattern": r"\bshred\b.*\s/dev/",
        "level": "block",
        "description": "Shred block device",
        "priority": 10,
    },
    {
        "pattern": r"\bnvme\s+format\b",
        "level": "block",
        "description": "NVMe secure format",
        "priority": 11,
    },
    {
        "pattern": r"hdparm\s+.*--security-erase",
        "level": "block",
        "description": "ATA security erase",
        "priority": 12,
    },
    {
        "pattern": r"sgdisk\s+.*--zap",
        "level": "block",
        "description": "Zap GPT partition table",
        "priority": 13,
    },
    {
        "pattern": r"\b(sfdisk|parted)\b.*\s/dev/",
        "level": "block",
        "description": "Repartition block device",
        "priority": 14,
    },
    {
        "pattern": r"\b(pvremove|vgremove|lvremove)\b",
        "level": "block",
        "description": "Destroy LVM volume",
        "priority": 15,
    },
    {
        "pattern": r"cryptsetup\s+luksFormat",
        "level": "block",
        "description": "LUKS format (destroys data)",
        "priority": 16,
    },
    {
        "pattern": r"\bzpool\s+destroy\b",
        "level": "block",
        "description": "Destroy ZFS pool",
        "priority": 17,
    },
    # Instant death
    {
        "pattern": r":\(\)\s*\{.*:\s*\|\s*:&\s*\}\s*;\s*:",
        "level": "block",
        "description": "Fork bomb",
        "priority": 18,
    },
    {
        "pattern": r"/proc/sysrq-trigger",
        "level": "block",
        "description": "SysRq trigger (crash/reboot)",
        "priority": 19,
    },
    {
        "pattern": r"kill\s+-9\s+1\b",
        "level": "block",
        "description": "Kill PID 1",
        "priority": 20,
    },
    # Auth root destroy
    {
        "pattern": r"(>|truncate\b).*\s/etc/(passwd|shadow|sudoers)\b",
        "level": "block",
        "description": "Wipe critical auth files",
        "priority": 21,
    },
    {
        "pattern": r"\buserdel\b.*\broot\b",
        "level": "block",
        "description": "Delete root user",
        "priority": 22,
    },
    {
        "pattern": r"\bpasswd\s+-d\s+root\b",
        "level": "block",
        "description": "Clear root password",
        "priority": 23,
    },
    # ------------------------------------------------------------------ allow
    # Shape: ``^prefix\b{_NO_CHAIN}`` — whitelisted chars only to end of
    # line, so chains/substitution/redirects never ride an allow rule.
    # Host introspection
    {
        "pattern": rf"^(hostname|uname|uptime|whoami|pwd|date|id)\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Host identity / clock",
        "priority": 100,
    },
    {
        "pattern": rf"^(df|free)\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Disk and memory usage",
        "priority": 101,
    },
    {
        "pattern": rf"^which\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Resolve binary path",
        "priority": 102,
    },
    {
        "pattern": rf"^command\s+-v\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Resolve command path",
        "priority": 103,
    },
    {
        "pattern": rf"^ls\b{_NO_CHAIN}",
        "level": "allow",
        "description": "List directory",
        "priority": 104,
    },
    # Docker read-only
    {
        "pattern": rf"^docker\s+(ps|images|info|version)\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Docker inventory / info",
        "priority": 110,
    },
    {
        "pattern": rf"^docker\s+(logs|inspect)\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Docker logs / inspect",
        "priority": 111,
    },
    # Kubernetes read-only
    {
        "pattern": (
            rf"^kubectl\s+(get|describe|logs|top|version|api-resources|"
            rf"cluster-info)\b{_NO_CHAIN}"
        ),
        "level": "allow",
        "description": "kubectl read-only",
        "priority": 120,
    },
    # systemd / network read-only
    {
        "pattern": (
            rf"^systemctl\s+(status|is-active|is-enabled|show|cat|"
            rf"list-units)\b{_NO_CHAIN}"
        ),
        "level": "allow",
        "description": "systemctl read-only",
        "priority": 130,
    },
    {
        "pattern": rf"^(ss|ip a|ip addr|ip link|ip route)\b{_NO_CHAIN}",
        "level": "allow",
        "description": "Network inventory",
        "priority": 131,
    },
    # Package query (not install/remove)
    {
        "pattern": rf"^apt-cache\b{_NO_CHAIN}",
        "level": "allow",
        "description": "APT cache query",
        "priority": 140,
    },
    {
        "pattern": rf"^dpkg\s+(-l|-s)\b{_NO_CHAIN}",
        "level": "allow",
        "description": "dpkg list / status",
        "priority": 141,
    },
]


async def seed_default_rules(session) -> int:
    """Insert default security rules if none exist.

    Parameters
    ----------
    session:
        An open SQLAlchemy async session.

    Returns
    -------
    int
        The number of rules inserted (0 if rules already existed).
    """
    from shuttle.db.repository import RuleRepo

    repo = RuleRepo(session)
    existing = await repo.list_all()
    if existing:
        return 0
    count = 0
    for rule_data in DEFAULT_SECURITY_RULES:
        await repo.create(**rule_data)
        count += 1
    return count
