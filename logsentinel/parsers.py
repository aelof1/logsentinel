"""Turn raw log lines into small event objects."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from urllib.parse import unquote_plus


@dataclass
class SSHEvent:
    time: datetime
    kind: str          # "failed", "invalid_user", "accepted"
    user: str
    ip: str
    raw: str


@dataclass
class WebEvent:
    time: datetime
    ip: str
    method: str
    path: str
    status: int
    user_agent: str
    raw: str


# --- auth.log ---------------------------------------------------------------
# Classic syslog:  "Nov 16 08:12:01 host sshd[123]: ..."
SYSLOG_TS = re.compile(r"^(?P<ts>[A-Z][a-z]{2}\s+\d{1,2} \d{2}:\d{2}:\d{2})\s")
# Newer rsyslog:   "2026-11-16T08:12:01.123456+00:00 host sshd[123]: ..."
ISO_TS = re.compile(r"^(?P<ts>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2})")

SSH_PATTERNS = [
    ("failed", re.compile(r"Failed (?:password|publickey) for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")),
    ("invalid_user", re.compile(r"Invalid user (?P<user>\S*) from (?P<ip>[\da-fA-F:.]+)")),
    ("accepted", re.compile(r"Accepted (?:password|publickey|keyboard-interactive/pam) for (?P<user>\S+) from (?P<ip>[\da-fA-F:.]+)")),
]


def parse_auth_line(line: str, year: int | None = None) -> SSHEvent | None:
    if "sshd" not in line:
        return None
    m = ISO_TS.match(line)
    if m:
        ts = datetime.strptime(m.group("ts"), "%Y-%m-%dT%H:%M:%S")
    else:
        m = SYSLOG_TS.match(line)
        if not m:
            return None
        year = year or datetime.now().year
        ts = datetime.strptime(f"{year} {m.group('ts')}", "%Y %b %d %H:%M:%S")
    for kind, pattern in SSH_PATTERNS:
        hit = pattern.search(line)
        if hit:
            return SSHEvent(ts, kind, hit.group("user"), hit.group("ip"), line.rstrip())
    return None


# --- Apache / Nginx "combined" format -------------------------------------
WEB_RE = re.compile(
    r'^(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>[A-Z]+) (?P<path>\S+)[^"]*" '
    r'(?P<status>\d{3}) \S+(?: "[^"]*" "(?P<ua>[^"]*)")?'
)


def parse_web_line(line: str) -> WebEvent | None:
    m = WEB_RE.match(line)
    if not m:
        return None
    try:
        ts = datetime.strptime(m.group("ts").split()[0], "%d/%b/%Y:%H:%M:%S")
    except ValueError:
        return None
    return WebEvent(
        time=ts,
        ip=m.group("ip"),
        method=m.group("method"),
        path=unquote_plus(m.group("path")),
        status=int(m.group("status")),
        user_agent=m.group("ua") or "",
        raw=line.rstrip(),
    )


def detect_format(lines: list[str]) -> str:
    """Guess if a file is an SSH auth log or a web access log."""
    web = sum(1 for l in lines[:50] if WEB_RE.match(l))
    ssh = sum(1 for l in lines[:50] if "sshd" in l)
    return "web" if web >= ssh else "auth"
