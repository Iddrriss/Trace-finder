# Trace-finder (v2.0)

A professional, modular forensic triage tool for Windows systems. TraceFinder helps incident responders, digital forensic examiners, and security analysts quickly detect user and system activity within a configurable time window (default: 180 minutes). Built with forensic best practices and **zero external dependencies**.

---

## 🚀 What's New in v2.0 (Upgrade Notes)

TraceFinder has received a major upgrade from **v2.0** to **v2.0**. Here is a breakdown of what was added, improved, and fixed:

### 1. Windows Event Log Collector (`collectors/events.py`)
- **System Event Logs**: Captures newly installed services (Event 7045), system shutdowns/reboots (Event 1074), OS boot and clean shutdown timestamps (Events 6005/6006), service startup configuration changes (Event 7040), and system log cleared events (Event 104 - anti-forensics alert).
- **Security Event Logs** *(when running as Administrator)*: Captures process creation with command-line arguments and parent processes (Event 4688), successful/failed user logons (Events 4624/4625), user account creation/deletion (Events 4720/4726), and audit log cleared events (Event 1102).
- **PowerShell ScriptBlock Logs**: Captures script code executed via PowerShell ScriptBlock logging (Event 4104), providing visibility into in-memory scripts and malicious commands.
- Implemented natively using Windows `wevtutil.exe` and `xml.etree.ElementTree` without any third-party dependencies.

### 2. Multi-Profile & Multi-Browser Enumeration (`collectors/network.py`)
- **Multi-Profile Support**: Automatically discovers and parses all user profiles (`Default`, `Profile 1`, `Profile 2`, `Guest Profile`, etc.) instead of assuming a single default profile.
- **Broad Browser Coverage**: Added support across Chromium browsers: **Google Chrome**, **Microsoft Edge**, **Brave Browser**, **Opera**, **Opera GX**, and **Vivaldi**.
- **Firefox Profiles**: Scans all active profile directories containing `places.sqlite` rather than stopping at the first profile.
- Sources are now labeled with their exact profile for precise forensic attribution (e.g., `Chrome (Profile 1)`).

### 3. Structured SIEM JSON Report Exporter (`reporters/json_exporter.py`)
- Added structured JSON export (`tracefinder_report_YYYYMMDD_HHMMSS.json`) alongside CSV.
- Includes scan metadata, triage window bounds, system timezone offsets, statistical breakdown, and standardized chronological findings.

### 4. Advanced CLI Interface (`tracefinder.py`)
- Replaced basic positional arguments with standard Python `argparse`.
- Added flags: `-w/--window`, `-o/--output`, `-f/--format {csv,json,both,none}`, `--json`, `--no-export`, `-q/--quiet`, `-y/--yes`, and `-v/--verbose`.
- Fully backwards compatible with positional shorthand syntax (e.g., `python tracefinder.py 60`).

### 5. Forensic Accuracy & Reliability Fixes
- **RunMRU**: Fixed trailing delimiter stripping bug (`.rstrip('\\1')` stripped trailing `1`s from commands like `ping 192.168.1.1`; now cleanly removes the exact delimiter).
- **RecentDocs**: Fixed UTF-16LE binary parsing to cleanly extract null-terminated filenames without trailing binary metadata junk.
- **Prefetch**: Path resolves dynamically via `%SYSTEMROOT%` rather than hardcoding `C:\Windows`.
- **Diagnostic Suite**: Added `tests/test_all.py` (unit tests) and `check.py` (system diagnostic health check).

---

## Features

- **Execution Evidence**: UserAssist, Prefetch files, Security Process Creation events (4688)
- **File Activity**: Recent files (`.lnk`), RecentDocs registry
- **Network & Browsing**: Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Firefox browser history & downloads across **all user profiles**
- **Hardware Tracking**: USB device connection history (`USBSTOR`)
- **Command Line**: PowerShell history (`ConsoleHost_history.txt`), Run dialog (`RunMRU`), PowerShell ScriptBlock logs (4104)
- **Windows Event Logs**: Service installation (7045), system shutdowns/reboots (1074), logons (4624/4625), log clears (104/1102)
- **Registry Artifacts**: TypedPaths (Explorer address bar navigation)
- **Flexible Export**: Dual timezone display (UTC + Local), SIEM-ready CSV and JSON reports

---

## Requirements

- **Operating System**: Windows 10/11 or Windows Server 2019/2022
- **Python**: 3.8+ (Pure standard library — **zero third-party dependencies required**)
- **Privileges**: Administrator recommended for full coverage (Prefetch, USBSTOR, Security Event Logs); standard user access works with graceful degradation.

---

## Installation & Usage

1. Clone the repository:
   ```cmd
   git clone https://github.com/Iddrriss/Trace-finder.git
   cd Trace-finder
   ```

2. Basic run (default 180-minute window, exports CSV):
   ```cmd
   python tracefinder.py
   ```

3. Custom triage window (e.g., last 60 minutes or last 24 hours):
   ```cmd
   python tracefinder.py 60
   python tracefinder.py -w 1440
   ```

4. Export to JSON (or both CSV and JSON):
   ```cmd
   python tracefinder.py -f json
   python tracefinder.py -f both -o case_report
   ```

5. Non-interactive & quiet execution (ideal for scripts and automated triage):
   ```cmd
   python tracefinder.py --yes --quiet -f both
   ```

---

## Command Line Options

```text
usage: tracefinder [-h] [-w WINDOW] [-o OUTPUT] [-f {csv,json,both,none}]
                   [--json] [--no-export] [-q] [-y] [-v]
                   [positional_window]

positional arguments:
  positional_window     Triage window in minutes (positional shorthand for -w)

options:
  -h, --help            Show this help message and exit
  -w, --window WINDOW   Triage window size in minutes (default: 180)
  -o, --output OUTPUT   Custom output filename or base prefix for exported reports
  -f, --format FORMAT   Report export format: csv, json, both, or none (default: csv)
  --json                Shorthand flag to export JSON report
  --no-export           Suppress writing report files to disk (console display only)
  -q, --quiet           Quiet mode: suppress detailed console timeline table
  -y, --yes             Non-interactive mode: skip administrator confirmation prompt
  -v, --verbose         Enable verbose error output and tracebacks
```

---

## Verification & Tests

Run the built-in diagnostic suite:
```cmd
python -m unittest discover tests
python check.py
```

Happy Forensics!
