"""Text, JSON and HTML output."""

from __future__ import annotations

import html
import json
from collections import Counter
from datetime import datetime

from .detectors import Alert

SEV_COLOR = {"critical": "\033[95m", "high": "\033[91m", "medium": "\033[93m", "low": "\033[94m"}


def top_ips(alerts: list[Alert], n: int = 10) -> list[tuple[str, int]]:
    c: Counter = Counter()
    for a in alerts:
        c[a.ip] += a.count
    return c.most_common(n)


def to_text(alerts: list[Alert], stats: dict, color: bool = True) -> str:
    out = [f"Lines read: {stats['lines']}  |  events parsed: {stats['events']}  |  alerts: {len(alerts)}", ""]
    for a in alerts:
        c, r = (SEV_COLOR.get(a.severity, ""), "\033[0m") if color else ("", "")
        out.append(f"{c}[{a.severity.upper():<8}]{r} {a.rule:<28} {a.ip:<16} x{a.count:<5} {a.description}")
        out.append(f"           {a.first_seen:%Y-%m-%d %H:%M:%S} -> {a.last_seen:%H:%M:%S}")
    if alerts:
        out += ["", "Top offending IPs:"]
        out += [f"   {ip:<18} {count}" for ip, count in top_ips(alerts)]
    else:
        out.append("No suspicious activity detected.")
    return "\n".join(out)


def to_json(alerts: list[Alert], stats: dict) -> str:
    return json.dumps({"stats": stats, "alerts": [a.to_dict() for a in alerts],
                       "top_ips": top_ips(alerts)}, indent=2)


def to_html(alerts: list[Alert], stats: dict) -> str:
    rows = "\n".join(
        f"<tr class='{a.severity}'><td>{a.severity}</td><td>{a.rule}</td><td>{html.escape(a.ip)}</td>"
        f"<td>{a.count}</td><td>{a.first_seen:%Y-%m-%d %H:%M:%S}</td><td>{html.escape(a.description)}</td>"
        f"<td><pre>{html.escape(chr(10).join(a.samples))}</pre></td></tr>"
        for a in alerts)
    ips = "".join(f"<li><code>{html.escape(ip)}</code> - {n}</li>" for ip, n in top_ips(alerts))
    return f"""<!DOCTYPE html><html lang="en"><head><meta charset="utf-8"><title>logsentinel report</title>
<style>body{{font-family:system-ui,sans-serif;margin:2rem}}table{{border-collapse:collapse;width:100%}}
td,th{{border:1px solid #ddd;padding:6px;vertical-align:top;text-align:left}}th{{background:#f4f4f4}}
pre{{margin:0;font-size:11px;white-space:pre-wrap;max-width:500px}}
.critical td:first-child{{color:#8250df;font-weight:bold}}.high td:first-child{{color:#cf222e}}
.medium td:first-child{{color:#9a6700}}</style></head><body>
<h1>logsentinel report</h1><p>Generated {datetime.now():%Y-%m-%d %H:%M} - {stats['lines']} lines,
{stats['events']} events, <b>{len(alerts)} alerts</b></p>
<h2>Top IPs</h2><ul>{ips or '<li>none</li>'}</ul>
<h2>Alerts</h2><table><tr><th>Severity</th><th>Rule</th><th>IP</th><th>Count</th><th>First seen</th>
<th>Description</th><th>Samples</th></tr>{rows}</table></body></html>"""
