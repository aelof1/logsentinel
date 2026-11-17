"""Detection rules. Each detector receives a list of events and returns alerts."""

from __future__ import annotations

import re
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta

from .parsers import SSHEvent, WebEvent


@dataclass
class Alert:
    rule: str
    severity: str           # low / medium / high / critical
    ip: str
    first_seen: datetime
    last_seen: datetime
    count: int
    description: str
    samples: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = self.__dict__.copy()
        d["first_seen"] = self.first_seen.isoformat()
        d["last_seen"] = self.last_seen.isoformat()
        return d


@dataclass
class Settings:
    bruteforce_threshold: int = 5
    bruteforce_window: int = 60          # seconds
    scan_404_threshold: int = 20
    scan_404_window: int = 60
    enum_users_threshold: int = 5


# ----------------------------------------------------------------- SSH rules
def detect_ssh(events: list[SSHEvent], cfg: Settings) -> list[Alert]:
    alerts: list[Alert] = []
    failures: dict[str, list[SSHEvent]] = defaultdict(list)
    brute_ips: dict[str, Alert] = {}

    for ev in sorted(events, key=lambda e: e.time):
        if ev.kind == "failed":
            failures[ev.ip].append(ev)
        elif ev.kind == "accepted" and ev.ip in brute_ips:
            alerts.append(Alert(
                "ssh_login_after_bruteforce", "critical", ev.ip, ev.time, ev.time, 1,
                f"Successful login as '{ev.user}' from an IP that was brute forcing. Possible compromise!",
                [ev.raw],
            ))
            continue
        # brute force check with a sliding window
        if ev.kind == "failed":
            window = deque(e for e in failures[ev.ip]
                           if ev.time - e.time <= timedelta(seconds=cfg.bruteforce_window))
            if len(window) >= cfg.bruteforce_threshold:
                if ev.ip not in brute_ips:
                    a = Alert("ssh_bruteforce", "high", ev.ip, window[0].time, ev.time, len(window),
                              f"{cfg.bruteforce_threshold}+ failed SSH logins in {cfg.bruteforce_window}s",
                              [e.raw for e in list(window)[:3]])
                    brute_ips[ev.ip] = a
                    alerts.append(a)
                else:
                    brute_ips[ev.ip].last_seen = ev.time

    for ip, a in brute_ips.items():
        a.count = len(failures[ip])
        a.description = f"{a.count} failed SSH logins (threshold {cfg.bruteforce_threshold} in {cfg.bruteforce_window}s)"

    # username enumeration
    users_by_ip: dict[str, set[str]] = defaultdict(set)
    seen: dict[str, list[SSHEvent]] = defaultdict(list)
    for ev in events:
        if ev.kind in ("invalid_user", "failed"):
            users_by_ip[ev.ip].add(ev.user)
            seen[ev.ip].append(ev)
    for ip, users in users_by_ip.items():
        if len(users) >= cfg.enum_users_threshold:
            evs = seen[ip]
            alerts.append(Alert(
                "ssh_user_enumeration", "medium", ip, min(e.time for e in evs), max(e.time for e in evs),
                len(users), f"Tried {len(users)} different usernames: " + ", ".join(sorted(users)[:8]),
            ))
    return alerts


# ----------------------------------------------------------------- Web rules
WEB_SIGNATURES = [
    ("sql_injection", "high", re.compile(
        r"(\bunion\b.*\bselect\b|\bor\b\s+\d+=\d+|'\s*or\s*'|sleep\(\d+\)|benchmark\(|information_schema|"
        r"\bdrop\s+table\b|--\s*$|;--)", re.I)),
    ("xss", "medium", re.compile(r"(<script|javascript:|onerror\s*=|onload\s*=|alert\(|<svg[^>]*on\w+=)", re.I)),
    ("path_traversal", "high", re.compile(r"(\.\./|\.\.\\|/etc/passwd|/etc/shadow|c:\\windows|boot\.ini)", re.I)),
    ("command_injection", "high", re.compile(r"(;\s*(cat|id|whoami|uname|wget|curl)\b|\|\s*(id|whoami)\b|\$\(|`)", re.I)),
    ("sensitive_file", "medium", re.compile(
        r"(/\.env\b|/\.git/|/wp-config\.php|/\.aws/|/id_rsa|/\.htpasswd|/phpinfo\.php|/server-status|/backup\.(zip|sql|tar))",
        re.I)),
    ("log4shell", "critical", re.compile(r"\$\{jndi:", re.I)),
]

RULE_LABELS = {
    "sql_injection": "SQL injection attempt in URL",
    "xss": "Cross-site scripting (XSS) attempt in URL",
    "path_traversal": "Path traversal attempt (reading system files)",
    "command_injection": "OS command injection attempt",
    "sensitive_file": "Request for a sensitive file (.env, .git, backups...)",
    "log4shell": "Log4Shell exploit attempt (CVE-2021-44228)",
}

SCANNER_AGENTS = re.compile(
    r"(sqlmap|nikto|nmap|masscan|zgrab|gobuster|dirbuster|dirb|ffuf|wfuzz|wpscan|nuclei|acunetix|"
    r"nessus|openvas|hydra|zmeu|censys)", re.I)


def detect_web(events: list[WebEvent], cfg: Settings) -> list[Alert]:
    grouped: dict[tuple[str, str], Alert] = {}

    def add(rule, sev, ev, desc):
        key = (rule, ev.ip)
        if key in grouped:
            a = grouped[key]
            a.count += 1
            a.last_seen = max(a.last_seen, ev.time)
            if len(a.samples) < 3:
                a.samples.append(ev.raw)
        else:
            grouped[key] = Alert(rule, sev, ev.ip, ev.time, ev.time, 1, desc, [ev.raw])

    for ev in events:
        for rule, sev, pattern in WEB_SIGNATURES:
            if pattern.search(ev.path):
                add(rule, sev, ev, RULE_LABELS.get(rule, rule))
        ua = SCANNER_AGENTS.search(ev.user_agent)
        if ua:
            add("scanner_user_agent", "medium", ev, f"Known security scanner: {ua.group(1)}")

    # directory brute force: many 404 in a short window
    by_ip: dict[str, list[WebEvent]] = defaultdict(list)
    for ev in sorted(events, key=lambda e: e.time):
        if ev.status == 404:
            by_ip[ev.ip].append(ev)
    for ip, evs in by_ip.items():
        start = 0
        for end in range(len(evs)):
            while (evs[end].time - evs[start].time).total_seconds() > cfg.scan_404_window:
                start += 1
            if end - start + 1 >= cfg.scan_404_threshold:
                grouped[("directory_scan", ip)] = Alert(
                    "directory_scan", "medium", ip, evs[0].time, evs[-1].time, len(evs),
                    f"{len(evs)} pages not found (404) - looks like a directory brute force",
                    [e.raw for e in evs[:3]])
                break
    return list(grouped.values())


SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def sort_alerts(alerts: list[Alert]) -> list[Alert]:
    return sorted(alerts, key=lambda a: (SEVERITY_ORDER.get(a.severity, 9), -a.count))
