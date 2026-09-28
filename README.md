# Trace-finder (v1.1.0)

A professional, modular forensic triage tool for Windows systems. TraceFinder helps incident responders, digital forensic examiners, and security analysts quickly detect user and system activity within a configurable time window (default: 180 minutes). Built with forensic best practices and **zero external dependencies**.

---

## Features

- **Execution Evidence**: UserAssist, Prefetch files, Process Creation events (4688)
- **File Activity**: Recent files (`.lnk`), RecentDocs registry
- **Network & Browsing**: Chrome, Edge, Brave, Opera, Vivaldi, Firefox browser history & downloads across **all user profiles**
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

Happy Forensics!
