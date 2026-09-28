"""Console output formatting and summary statistics."""

import sys
import time
from datetime import datetime

if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def print_banner(window_minutes=180):
    """Display TraceFinder startup banner."""
    window_text = f"{window_minutes}-Minute Triage Window Analysis"
    print()
    print("=" * 70)
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                         TraceFinder v2.0                           ║")
    print("║            Windows Forensic Activity Detection & Triage            ║")
    print("║                                                                    ║")
    print(f"║{window_text.center(68)}║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print("=" * 70)
    print()


def get_local_timezone_name():
    """Return local timezone name or offset string."""
    offset_seconds = -time.timezone
    offset_hours = offset_seconds / 3600

    if time.daylight and time.localtime().tm_isdst:
        tz_name = time.tzname[1]
    else:
        tz_name = time.tzname[0]

    if tz_name in ['GMT', 'UTC'] or len(tz_name) > 5:
        return f"UTC{offset_hours:+.0f}"

    return tz_name


def print_findings_table(findings):
    """Render findings in a console table with UTC and local timestamps."""
    if not findings:
        print("[!] No findings to display")
        return

    local_tz = get_local_timezone_name()
    col_widths = {
        'timestamp_utc': 19,
        'timestamp_local': 19,
        'artifact_type': 15,
        'source': 18,
        'description': 45,
        'details': 50
    }

    print("=" * 180)
    print("TraceFinder - Forensic Timeline Report".center(180))
    print("=" * 180)
    print()

    header = (
        f"{'TIMESTAMP (UTC)':<{col_widths['timestamp_utc']}} | "
        f"{'TIMESTAMP (' + local_tz + ')':<{col_widths['timestamp_local']}} | "
        f"{'ARTIFACT TYPE':<{col_widths['artifact_type']}} | "
        f"{'SOURCE':<{col_widths['source']}} | "
        f"{'DESCRIPTION':<{col_widths['description']}} | "
        f"{'DETAILS':<{col_widths['details']}}"
    )
    print(header)
    print("-" * 180)

    for finding in findings:
        timestamp_utc = finding['timestamp']
        try:
            utc_dt = finding['timestamp_dt']
            local_dt = utc_dt.astimezone()
            timestamp_local = local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            timestamp_local = "Conversion Error"

        artifact_type = finding['artifact_type'][:col_widths['artifact_type']]
        source = finding['source'][:col_widths['source']]
        description = finding['description'][:col_widths['description']]
        details = finding['details'][:col_widths['details']]

        row = (
            f"{timestamp_utc:<{col_widths['timestamp_utc']}} | "
            f"{timestamp_local:<{col_widths['timestamp_local']}} | "
            f"{artifact_type:<{col_widths['artifact_type']}} | "
            f"{source:<{col_widths['source']}} | "
            f"{description:<{col_widths['description']}} | "
            f"{details:<{col_widths['details']}}"
        )
        print(row)

    print("-" * 180)
    print(f"Total Findings: {len(findings)}")
    print(f"Timezone: Timestamps displayed in UTC and local ({local_tz})")
    print("=" * 180)


def print_statistics(findings):
    """Print count breakdown of collected artifacts by type and source."""
    if not findings:
        return

    type_counts = {}
    source_counts = {}

    for finding in findings:
        art_type = finding['artifact_type']
        src = finding['source']
        type_counts[art_type] = type_counts.get(art_type, 0) + 1
        source_counts[src] = source_counts.get(src, 0) + 1

    print()
    print("=" * 65)
    print("Artifact Summary".center(65))
    print("=" * 65)
    print()

    print("[*] By Artifact Type:")
    for artifact_type, count in sorted(type_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {artifact_type:<20} : {count:>5} entries")

    print()
    print("[*] By Source:")
    for source, count in sorted(source_counts.items(), key=lambda x: x[1], reverse=True):
        print(f"    {source:<20} : {count:>5} entries")

    print()
    print("=" * 65)