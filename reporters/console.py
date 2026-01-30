"""
TraceFinder - Console Reporting Module
reporters/console.py

Author: Senior Cyber Security and Forensic Engineer
Python Version: 3.12
Compliance: PEP8

Updated: Added local timezone display alongside UTC
"""

from datetime import datetime


def print_banner():
    """Display TraceFinder ASCII banner."""
    print()
    print("=" * 70)
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                          TraceFinder v1.0                          ║")
    print("║            Windows 11 Forensic Activity Detection Tool             ║")
    print("║                                                                    ║")
    print("║              180-Minute Triage Window Analysis                     ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print("=" * 70)
    print()


def get_local_timezone_name():
    """
    Get the local timezone name/offset for display.
    
    Returns:
        str: Timezone name or offset (e.g., "UTC+1" or "WAT")
    """
    import time
    
    # Get timezone offset
    offset_seconds = -time.timezone
    offset_hours = offset_seconds / 3600
    
    # Try to get timezone name
    if time.daylight and time.localtime().tm_isdst:
        tz_name = time.tzname[1]  # DST name
    else:
        tz_name = time.tzname[0]  # Standard time name
    
    # If timezone name is generic, use offset
    if tz_name in ['GMT', 'UTC'] or len(tz_name) > 5:
        return f"UTC{offset_hours:+.0f}"
    
    return tz_name


def print_findings_table(findings):
    """
    Print findings in a beautifully formatted console table.
    Shows both UTC and Local timestamps.
    
    Args:
        findings (list): List of finding dictionaries.
    """
    if not findings:
        print("[!] No findings to display")
        return
    
    # Get local timezone name for header
    local_tz = get_local_timezone_name()
    
    # Updated column widths to accommodate both timestamps
    col_widths = {
        'timestamp_utc': 19,      # UTC timestamp
        'timestamp_local': 19,     # Local timestamp
        'artifact_type': 15,
        'source': 18,
        'description': 45,
        'details': 50
    }
    
    print("=" * 180)
    print("TraceFinder - Forensic Timeline Report (Dual Timezone Display)".center(180))
    print("=" * 180)
    print()
    
    # Header with timezone names
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
    
    # Print each finding with both timestamps
    for finding in findings:
        # UTC timestamp (already formatted)
        timestamp_utc = finding['timestamp']
        
        # Convert to local timezone
        try:
            utc_dt = finding['timestamp_dt']
            local_dt = utc_dt.astimezone()  # Converts to system local timezone
            timestamp_local = local_dt.strftime('%Y-%m-%d %H:%M:%S')
        except Exception:
            timestamp_local = "Conversion Error"
        
        # Truncate other fields
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
    print(f"Timezone: All times shown in UTC and {local_tz} (local system time)")
    print("=" * 180)


def print_statistics(findings):
    """
    Print statistical summary of collected artifacts.
    
    Args:
        findings (list): List of finding dictionaries.
    """
    if not findings:
        return
    
    type_counts = {}
    source_counts = {}
    
    for finding in findings:
        artifact_type = finding['artifact_type']
        source = finding['source']
        
        type_counts[artifact_type] = type_counts.get(artifact_type, 0) + 1
        source_counts[source] = source_counts.get(source, 0) + 1
    
    print()
    print("=" * 70)
    print("Statistical Summary".center(70))
    print("=" * 70)
    print()
    
    print("[*] Artifacts by Type:")
    for artifact_type, count in sorted(
        type_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"    {artifact_type:<20} : {count:>5} entries")
    
    print()
    print("[*] Artifacts by Source:")
    for source, count in sorted(
        source_counts.items(),
        key=lambda x: x[1],
        reverse=True
    ):
        print(f"    {source:<20} : {count:>5} entries")
    
    print()
    print("=" * 70)