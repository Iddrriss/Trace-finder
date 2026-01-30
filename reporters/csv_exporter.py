"""
TraceFinder - CSV Export Module
reporters/csv_exporter.py


"""

import csv
import time
from pathlib import Path
from datetime import datetime


def get_timezone_name():
    """
    Get timezone name or offset for CSV header.
    
    Returns:
        str: Timezone name (e.g., "WAT" or "UTC+1")
    """
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
    """
    Generate a unique filename with timestamp to avoid overwriting.
    
    Args:
        base_name (str): Base filename without extension.
        extension (str): File extension without dot.
    
    Returns:
        str: Unique filename with timestamp.
    
    """
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    return f"{base_name}_{timestamp}.{extension}"


def export_to_csv(findings, output_file=None, use_timestamp=True):
    """
    Export findings to CSV file with both UTC and local timestamps.
    
    Args:
        findings (list): List of finding dictionaries.
        output_file (str): Output CSV filename. If None, auto-generates.
        use_timestamp (bool): If True, adds timestamp to filename to prevent 
                             overwriting. If False, uses exact filename provided.
    
    Returns:
        str: Path to created CSV file, or None if export fails.
    
    """
    if not findings:
        print("[!] No findings to export")
        return None
    
    try:
        # Determine output filename
        if output_file is None:
            # No filename provided, use default with timestamp
            filename = generate_unique_filename()
        elif use_timestamp:
            # Filename provided, but add timestamp
            base_name = Path(output_file).stem  # Remove extension
            extension = Path(output_file).suffix.lstrip('.')  # Get extension
            if not extension:
                extension = 'csv'
            filename = generate_unique_filename(base_name, extension)
        else:
            # Use exact filename (may overwrite)
            filename = output_file
        
        csv_path = Path.cwd() / filename
        
        # Check if file exists and warn user
        if csv_path.exists() and not use_timestamp:
            print(f"[!] Warning: File '{filename}' already exists and will be overwritten")
        
        local_tz = get_timezone_name()
        
        with open(csv_path, 'w', newline='', encoding='utf-8') as csvfile:
            # Define CSV columns with both timestamps
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
                # Get local timestamp
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