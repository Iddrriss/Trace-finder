# TraceFinder (v2.0)

A lightweight, modular Windows forensic triage tool designed for incident responders, digital forensic examiners, and security analysts. TraceFinder gathers and correlates evidence of user and system activity within a configurable time window (default: 180 minutes), with **zero external dependencies**.

---

## Artifact Coverage

TraceFinder parses the following evidence sources across the triage window:

| Category | Artifacts | Admin Required? | Description |
| :--- | :--- | :---: | :--- |
| **Execution** | UserAssist, Prefetch, Security 4688 | Partial | GUI executions (with run count and focus time), Prefetch binaries, and process creation events with command lines. |
| **File Activity** | Recent Files (`.lnk`), RecentDocs | No | Recently opened files, shortcuts, and document extensions from the user registry. |
| **Network** | Chrome, Edge, Brave, Opera, Opera GX, Vivaldi, Firefox | No | Browsing history and downloaded files across all discovered browser profiles. |
| **Hardware** | USB Devices (`USBSTOR`) | Yes | First-install and connection timestamps for USB storage devices. |
| **Command Line** | PowerShell history, RunMRU, ScriptBlock (4104) | No | Console history, Run dialog entries, and logged PowerShell script blocks. |
| **System Events** | System & Security Event Logs | Partial | Service installations (7045/7040), shutdowns/reboots (1074, 6005/6006), account changes (4720/4726), and audit log clears (104/1102). |
| **Registry** | TypedPaths | No | Paths manually typed into Windows Explorer address bar. |

---

## Requirements

- **Operating System**: Windows 10, Windows 11, Windows Server 2019/2022
- **Python**: 3.8+ (uses only Python standard library)
- **Privileges**: Administrator recommended for full coverage (Prefetch, USBSTOR, Security Event Logs). Standard user access collects all user-level artifacts with graceful degradation.

---

## Quick Start

```cmd
git clone https://github.com/Iddrriss/Trace-finder.git
cd Trace-finder

# Run with default 180-minute window (Administrator recommended)
python tracefinder.py
```

---

## Usage Examples

```cmd
# Scan the default 3-hour window and export to CSV
python tracefinder.py

# Shorthand for a custom time window (e.g., last 60 minutes)
python tracefinder.py 60

# Specify window size with flag (e.g., last 24 hours)
python tracefinder.py -w 1440

# Export to JSON instead of CSV
python tracefinder.py -f json

# Export both CSV and JSON with a custom output prefix
python tracefinder.py -f both -o incident_404

# Scripting / automated run: skip prompts and suppress the wide console table
python tracefinder.py --yes --quiet -f both
```

### Command Line Options

```text
usage: tracefinder [-h] [-w WINDOW] [-o OUTPUT] [-f {csv,json,both,none}]
                   [--json] [--no-export] [-q] [-y] [-v]
                   [positional_window]

positional arguments:
  positional_window     Triage window in minutes (shorthand for -w)

options:
  -h, --help            Show help message and exit
  -w, --window WINDOW   Triage window size in minutes (default: 180)
  -o, --output OUTPUT   Output filename or base prefix for exported reports
  -f, --format FORMAT   Report format: csv, json, both, or none (default: csv)
  --json                Export JSON report (shorthand for -f json or -f both)
  --no-export           Display findings in console only (do not write files)
  -q, --quiet           Suppress timeline table (print statistics only)
  -y, --yes             Skip confirmation prompts (non-interactive mode)
  -v, --verbose         Print error tracebacks if a collector encounters an issue
```

---

## Project Structure

```text
TraceFinder/
├── tracefinder.py              # CLI entry point and triage orchestrator
├── check.py                    # Environment and collector diagnostic checks
├── requirements.txt            # Dependency list (standard library only)
├── README.md                   # Documentation
│
├── core/
│   ├── privileges.py           # Administrator token verification
│   └── time_window.py          # Triage window calculation & FILETIME conversion
│
├── collectors/
│   ├── execution.py            # UserAssist and Prefetch collectors
│   ├── files.py                # Recent files (.lnk) and RecentDocs
│   ├── hardware.py             # USBSTOR registry device enumeration
│   ├── commands.py             # PSReadLine history and RunMRU
│   ├── network.py              # Multi-profile browser history and downloads
│   ├── registry.py             # TypedPaths address bar entries
│   └── events.py               # Windows Event Logs (System, Security, PowerShell)
│
├── reporters/
│   ├── console.py              # Formatted timeline table and summary statistics
│   ├── csv_exporter.py         # SIEM-compatible CSV report exporter
│   └── json_exporter.py        # Structured JSON report exporter
│
└── tests/
    └── test_all.py             # Unit tests for time, conversion, and export logic
```

---

## Output Formats

1. **Console Table**: Displays chronological timeline with dual timezones (UTC for forensic standards, and local system timezone for analyst convenience).
2. **CSV Export**: SIEM-ready spreadsheet with standardized columns:
   `Timestamp (UTC)`, `Timestamp (Local)`, `Artifact Type`, `Source`, `Description`, `Details`.
3. **JSON Export**: Structured report containing scan metadata, triage parameters, statistical aggregations, and individual findings.

---

## Use Cases

- **Incident Response**: Quickly establish an initial timeline of what ran, what was downloaded, and what was accessed on a suspect machine.
- **Insider Threat Detection**: Identify USB storage connections paired with recent file access or cloud storage navigation.
- **System Auditing**: Verify recent software installations, admin logons, or anti-forensic log-clearing attempts.
- **Triage Automation**: Run non-interactively (`--yes --quiet -f json`) in IR playbooks or live-response scripts.
- **General Check**: Quickly check recent system activity when stepping back to an unattended workstation.

---

## Testing & Diagnostics

Run the diagnostic suite to verify syntax, permissions, and collector reachability:

```cmd
# Run diagnostic health check
python check.py

# Run unit tests
python -m unittest discover tests
```

---

## Acknowledgments

TraceFinder draws inspiration from research and tooling in the digital forensics community:
- Eric Zimmerman for Prefetch and forensic parser research
- Didier Stevens for UserAssist registry analysis
- Harlan Carvey for Windows Registry forensics
- SANS Digital Forensics and Incident Response (DFIR) methodologies

---

## Disclaimer

This tool is intended for authorized digital forensics, incident response, and security auditing on systems you own or have explicit authorization to examine. Unauthorized monitoring may violate applicable privacy and computer security laws.
