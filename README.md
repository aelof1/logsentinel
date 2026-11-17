# logsentinel

Log analyzer that spots attacks in:

- SSH logs (`/var/log/auth.log`, `/var/log/secure`)
- Apache and Nginx web logs ("combined" format, the default one)

It prints a report in the terminal, as JSON or HTML, and can watch a file continuously.

## Why I built this

As soon as a server is on the Internet with port 22 open, login attempts start within minutes. I wanted to understand what these attacks look like in the logs and write my own detection rules, the way a SOC does with a SIEM.

## Detections

### SSH

| Rule | Trigger | Severity |
|---|---|---|
| `ssh_bruteforce` | 5 or more failed logins in 60 s from the same IP (configurable) | high |
| `ssh_login_after_bruteforce` | **successful login** from an IP that was brute forcing | critical |
| `ssh_user_enumeration` | one IP tries 5 or more different usernames | medium |

### Web

| Rule | Example detected | Severity |
|---|---|---|
| `sql_injection` | `?id=1' OR '1'='1`, `UNION SELECT`, `SLEEP(5)` | high |
| `xss` | `<script>alert(1)</script>`, `onerror=` | medium |
| `path_traversal` | `../../etc/passwd` | high |
| `command_injection` | `;cat /etc/passwd`, `$(id)` | high |
| `sensitive_file` | `/.env`, `/.git/config`, `/wp-config.php`, `/backup.zip` | medium |
| `log4shell` | `${jndi:ldap://...}` | critical |
| `scanner_user_agent` | sqlmap, nikto, gobuster, nmap, nuclei, wpscan… | medium |
| `directory_scan` | 20 or more 404 errors in 60 s from the same IP | medium |

URLs are decoded before analysis (`%27` becomes `'`); otherwise most attacks would go unnoticed.

## Compatibility

| System | Works? |
|---|---|
| Linux (all distributions) | Yes |
| macOS | Yes (to analyse logs copied from a server) |
| Windows 10 / 11 | Yes (same) |

Where to find the logs on a server:

| Distribution | SSH logs | Web logs |
|---|---|---|
| Debian, Ubuntu, Kali | `/var/log/auth.log` | `/var/log/apache2/access.log` or `/var/log/nginx/access.log` |
| Fedora, RHEL, Rocky | `/var/log/secure` | `/var/log/httpd/access_log` or `/var/log/nginx/access.log` |

> On recent systems that only use **journald** (no `auth.log`), you can export the SSH logs:
> `journalctl -u ssh --no-pager -o short-iso > ssh.log` (or `-u sshd` on Fedora), then analyse `ssh.log`.

## Requirements

- **Python 3.10 or newer**
- No external libraries.
- `sudo` to read files in `/var/log` (or copy them first).

## Installation

### Debian / Ubuntu / Kali

```bash
sudo apt update
sudo apt install -y python3 python3-pip python3-venv pipx git
git clone https://github.com/aelof1/logsentinel.git
cd logsentinel
pipx install .
```

### Fedora / Rocky

```bash
sudo dnf install -y python3 pipx git
```

### macOS

```bash
brew install python pipx git
```

### Windows

Install Python from [python.org](https://www.python.org/downloads/) (tick "Add python.exe to PATH"), then in the project folder: `pip install .`

## Usage

```bash
logsentinel samples/auth.log                      # example SSH logs
logsentinel samples/access.log                    # example web logs
sudo logsentinel /var/log/auth.log                # real logs
logsentinel access.log.2.gz                       # compressed files work too
logsentinel auth.log --threshold 10 --window 120  # more tolerant brute force rule
logsentinel access.log --html report.html         # HTML report
logsentinel access.log --json                     # JSON (for a SIEM or a script)
sudo logsentinel /var/log/auth.log --follow       # real-time monitoring
```

The log type is detected automatically. You can force it with `--format auth` or `--format web`.

### Example

```
$ logsentinel samples/auth.log
Lines read: 47  |  events parsed: 41  |  alerts: 4

[CRITICAL] ssh_login_after_bruteforce   203.0.113.45     x1     Successful login as 'root' from an IP that was brute forcing. Possible compromise!
[HIGH    ] ssh_bruteforce               203.0.113.45     x18    18 failed SSH logins (threshold 5 in 60s)
[HIGH    ] ssh_bruteforce               198.51.100.77    x8     8 failed SSH logins (threshold 5 in 60s)
[MEDIUM  ] ssh_user_enumeration         203.0.113.45     x7     Tried 7 different usernames: admin, oracle, pi, ...

Top offending IPs:
   203.0.113.45       26
   198.51.100.77      8
```

## Example logs

The `samples/` folder contains fake logs with realistic attacks: brute force followed by a successful login, sqlmap, gobuster, Log4Shell… The IP addresses come from the ranges reserved for documentation (RFC 5737), so they don't belong to anyone.

To regenerate them: `python3 tools/generate_samples.py`

## Project layout

```
logsentinel/
├── logsentinel/
│   ├── parsers.py     # reading log lines
│   ├── detectors.py   # detection rules
│   ├── report.py      # text / JSON / HTML output
│   └── cli.py
├── samples/           # fake logs for testing
├── tools/             # generator for the example logs
└── tests/
```

## Tests

```bash
pip install pytest
python3 -m pytest
```

## Limitations

- Signature-based detection: a well-encoded or unusual attack can slip through.
- `--follow` mode rereads the whole file each time. Fine for a small server, not for gigabytes of logs.
- Syslog dates have no year: the current year is used by default (`--year` option).

## Ideas for later

- Rules in a YAML file, so new ones can be added without touching the code
- Discord or email alerts
- IP geolocation
- Windows log support (event 4625, failed logon)

## License

MIT
