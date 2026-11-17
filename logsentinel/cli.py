"""logsentinel command line."""

from __future__ import annotations

import argparse
import gzip
import sys
import time

from . import __version__
from .detectors import Settings, detect_ssh, detect_web, sort_alerts
from .parsers import detect_format, parse_auth_line, parse_web_line
from .report import to_html, to_json, to_text


def read_lines(path: str) -> list[str]:
    opener = gzip.open if path.endswith(".gz") else open
    with opener(path, "rt", encoding="utf-8", errors="replace") as fh:
        return fh.readlines()


def analyze(lines: list[str], fmt: str, cfg: Settings, year: int | None = None):
    if fmt == "auto":
        fmt = detect_format(lines)
    if fmt == "auth":
        events = [e for e in (parse_auth_line(l, year) for l in lines) if e]
        alerts = detect_ssh(events, cfg)
    else:
        events = [e for e in (parse_web_line(l) for l in lines) if e]
        alerts = detect_web(events, cfg)
    return sort_alerts(alerts), {"lines": len(lines), "events": len(events), "format": fmt}


def follow(path: str, fmt: str, cfg: Settings, interval: float) -> None:
    """Re-analyse the file regularly and print only new alerts (like tail -f)."""
    print(f"Watching {path} (Ctrl+C to stop)...")
    known: set[tuple[str, str]] = set()
    while True:
        alerts, _ = analyze(read_lines(path), fmt, cfg)
        for a in alerts:
            key = (a.rule, a.ip)
            if key not in known:
                known.add(key)
                print(f"[{time.strftime('%H:%M:%S')}] NEW {a.severity.upper()} {a.rule} {a.ip}: {a.description}",
                      flush=True)
        time.sleep(interval)


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="logsentinel",
                                description="Detect attacks in SSH auth logs and Apache/Nginx access logs.")
    p.add_argument("logfile", help="log file (.log or .gz)")
    p.add_argument("--format", choices=["auto", "auth", "web"], default="auto", help="log type (default: auto)")
    p.add_argument("--json", action="store_true", help="JSON output")
    p.add_argument("--html", metavar="FILE", help="write an HTML report")
    p.add_argument("--follow", action="store_true", help="keep watching the file for new attacks")
    p.add_argument("--interval", type=float, default=5, help="seconds between checks with --follow")
    p.add_argument("--threshold", type=int, default=5, help="failed SSH logins before alerting (default 5)")
    p.add_argument("--window", type=int, default=60, help="time window in seconds (default 60)")
    p.add_argument("--year", type=int, help="year for syslog dates without a year (default: current)")
    p.add_argument("--no-color", action="store_true")
    p.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    args = p.parse_args(argv)

    cfg = Settings(bruteforce_threshold=args.threshold, bruteforce_window=args.window)
    try:
        if args.follow:
            follow(args.logfile, args.format, cfg, args.interval)
            return 0
        lines = read_lines(args.logfile)
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"error: {exc}", file=sys.stderr)
        print("hint: /var/log/auth.log usually needs sudo", file=sys.stderr)
        return 2

    alerts, stats = analyze(lines, args.format, cfg, args.year)
    if args.json:
        print(to_json(alerts, stats))
    else:
        print(to_text(alerts, stats, color=not args.no_color and sys.stdout.isatty()))
    if args.html:
        with open(args.html, "w", encoding="utf-8") as fh:
            fh.write(to_html(alerts, stats))
    return 1 if alerts else 0


if __name__ == "__main__":
    sys.exit(main())
