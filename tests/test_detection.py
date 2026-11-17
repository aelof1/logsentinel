from datetime import datetime
from pathlib import Path

from logsentinel.cli import analyze, read_lines
from logsentinel.detectors import Settings
from logsentinel.parsers import parse_auth_line, parse_web_line

SAMPLES = Path(__file__).resolve().parent.parent / "samples"


def rules(alerts):
    return {(a.rule, a.ip) for a in alerts}


def test_parse_auth_line():
    ev = parse_auth_line("Nov 16 09:00:01 web01 sshd[123]: Failed password for invalid user admin "
                         "from 203.0.113.45 port 4444 ssh2", year=2026)
    assert ev.kind == "failed" and ev.user == "admin" and ev.ip == "203.0.113.45"
    assert ev.time == datetime(2026, 11, 16, 9, 0, 1)


def test_parse_iso_auth_line():
    ev = parse_auth_line("2026-11-16T09:00:01.123+00:00 web01 sshd[1]: Accepted publickey for bob "
                         "from 2001:db8::1 port 22 ssh2")
    assert ev.kind == "accepted" and ev.ip == "2001:db8::1"


def test_parse_web_line():
    ev = parse_web_line('1.2.3.4 - - [16/Nov/2026:08:00:00 +0000] "GET /a%20b HTTP/1.1" 404 12 "-" "curl/8"')
    assert ev.path == "/a b" and ev.status == 404 and ev.user_agent == "curl/8"


def test_auth_sample():
    alerts, stats = analyze(read_lines(str(SAMPLES / "auth.log")), "auto", Settings(), year=2026)
    assert stats["format"] == "auth"
    found = rules(alerts)
    assert ("ssh_bruteforce", "203.0.113.45") in found
    assert ("ssh_login_after_bruteforce", "203.0.113.45") in found
    assert ("ssh_user_enumeration", "203.0.113.45") in found
    assert ("ssh_bruteforce", "198.51.100.77") in found
    # a single typo from a legit user must not trigger anything
    assert not any(a.ip == "192.0.2.11" for a in alerts)
    assert alerts[0].severity == "critical"


def test_slow_bruteforce_respects_window():
    # 8 failures 6s apart = 42s, so a 10s window with threshold 5 must NOT alert
    alerts, _ = analyze(read_lines(str(SAMPLES / "auth.log")), "auth",
                        Settings(bruteforce_window=10), year=2026)
    assert ("ssh_bruteforce", "198.51.100.77") not in rules(alerts)


def test_web_sample():
    alerts, stats = analyze(read_lines(str(SAMPLES / "access.log")), "auto", Settings())
    assert stats["format"] == "web"
    found = rules(alerts)
    for expected in [("sql_injection", "203.0.113.80"), ("xss", "203.0.113.80"),
                     ("scanner_user_agent", "203.0.113.80"), ("directory_scan", "198.51.100.23"),
                     ("sensitive_file", "198.51.100.23"), ("path_traversal", "203.0.113.99"),
                     ("log4shell", "203.0.113.99")]:
        assert expected in found, expected
    assert not any(a.ip == "192.0.2.20" for a in alerts)
