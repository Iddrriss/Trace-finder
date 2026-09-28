"""CSV report generation for collected forensic artifacts."""

import csv
import time
from pathlib import Path
from datetime import datetime


def get_timezone_name():
    """Return local timezone name or offset for CSV headers."""
    offset_seconds = -time.timezone
    offset_hours = offset_seconds / 3600

    if time.daylight and time.localtime().tm_isdst:
        tz_name = time.tzname[1]
    else:
        tz_name = time.tzname[0]

    if tz_name in ['GMT', 'UTC'] or len(tz_name) > 5:
        return f"UTC{offset_hours:+.0f}"

    return tz_name


def generate_unique_filename(base_name='tracefinder_report', extension='csv'):
    """Generate timestamped filename to prevent overwriting prior scans."""
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{base_name}_{timestamp}.{extension}"


def export_to_csv(findings, output_file=None, use_timestamp=True):
    """Export findings list to a CSV spreadsheet."""
    if not findings:
        print("[!] No findings to export")
        return None

    try:
        if output_file is None:
            filename = generate_unique_filename()
        elif use_timestamp:
            base_name = Path(output_file).stem
            extension = Path(output_file).suffix.lstrip('.') or 'csv'
            filename = generate_unique_filename(base_name, extension)
        else:
            filename = output_file

        csv_path = Path.cwd() / filename

        if csv_path.exists() and not use_timestamp:
            print(f"[!] Warning: '{filename}' already exists and will be overwritten")

        local_tz = get_timezone_name()

        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            fieldnames = [
                'Timestamp (UTC)',
                f'Timestamp ({local_tz})',
                'Artifact Type',
                'Source',
                'Description',
                'Details'
            ]

            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            for finding in findings:
                try:
                    utc_dt = finding['timestamp_dt']
                    local_dt = utc_dt.astimezone()
                    local_timestamp = local_dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    local_timestamp = "Conversion Error"

                writer.writerow({
                    'Timestamp (UTC)': finding['timestamp'],
                    f'Timestamp ({local_tz})': local_timestamp,
                    'Artifact Type': finding['artifact_type'],
                    'Source': finding['source'],
                    'Description': finding['description'],
                    'Details': finding['details']
                })

        return str(csv_path)

    except Exception as e:
        print(f"[!] Error exporting to CSV: {e}")
        return None