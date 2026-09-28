"""
TraceFinder v1.1.0 - Windows Forensic Activity Detection Tool
Main Entry Point

Author: Oxseeker
Compliance: PEP8

Description:
    Main orchestration script for TraceFinder forensic collection.
    Coordinates all collection modules and generates unified reports
    in CSV, JSON, or console table formats.
"""

import sys
import argparse
from datetime import datetime, timezone

# Ensure UTF-8 output encoding on Windows consoles to prevent charmap encoding errors
if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

# Import core utilities
from core.privileges import check_admin_privileges
from core.time_window import TriageWindow

# Import collectors
from collectors.execution import parse_userassist, parse_prefetch
from collectors.files import parse_recent_files, parse_recentdocs
from collectors.hardware import parse_usb_devices
from collectors.commands import parse_powershell_history, parse_runmru
from collectors.network import parse_browser_history, parse_downloads
from collectors.registry import parse_typed_paths
from collectors.events import parse_event_logs

# Import reporters
from reporters.console import print_banner, print_findings_table, print_statistics
from reporters.csv_exporter import export_to_csv
from reporters.json_exporter import export_to_json


def parse_arguments():
    """
    Parse command line arguments with argparse.
    
    Returns:
        argparse.Namespace: Parsed arguments.
    """
    parser = argparse.ArgumentParser(
        prog="tracefinder",
        description="TraceFinder v1.1.0 - Windows Forensic Activity Detection Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tracefinder.py                     # Scan default 180-minute window, export to CSV
  python tracefinder.py 60                  # Scan last 60 minutes (positional shorthand)
  python tracefinder.py -w 360 -f json      # Scan last 6 hours, export to JSON
  python tracefinder.py -f both -o case101  # Export both CSV and JSON with prefix 'case101'
  python tracefinder.py --quiet --yes       # Non-interactive, summary-only execution
        """
    )
    
    parser.add_argument(
        'positional_window',
        nargs='?',
        type=int,
        default=None,
        help='Triage window in minutes (positional shorthand for -w)'
    )
    parser.add_argument(
        '-w', '--window',
        type=int,
        default=None,
        dest='window',
        help='Triage window size in minutes (default: 180)'
    )
    parser.add_argument(
        '-o', '--output',
        type=str,
        default=None,
        help='Custom output filename or base prefix for exported reports'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['csv', 'json', 'both', 'none'],
        default='csv',
        help='Report export format: csv, json, both, or none (default: csv)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Shorthand flag to export JSON report (equivalent to -f json or -f both)'
    )
    parser.add_argument(
        '--no-export',
        action='store_true',
        help='Suppress writing report files to disk (display in console only)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Quiet mode: suppress detailed console timeline table'
    )
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Non-interactive mode: skip administrator confirmation prompt'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Enable verbose error output and tracebacks'
    )
    
    return parser.parse_args()


def collect_all_artifacts(triage_window, verbose=False):
    """
    Orchestrate collection from all forensic modules.
    
    Args:
        triage_window (TriageWindow): Time window for filtering results.
        verbose (bool): Whether to output verbose error traces.
    
    Returns:
        list: Aggregated list of all findings.
    """
    all_findings = []
    
    print("=" * 70)
    print("ARTIFACT COLLECTION PHASE")
    print("=" * 70)
    print()
    
    # Define all collection modules
    collectors = [
        ("UserAssist", parse_userassist),
        ("Prefetch", parse_prefetch),
        ("Recent Files", parse_recent_files),
        ("USB Devices", parse_usb_devices),
        ("PowerShell History", parse_powershell_history),
        ("Browser History", parse_browser_history),
        ("Downloads", parse_downloads),
        ("RecentDocs", parse_recentdocs),
        ("TypedPaths", parse_typed_paths),
        ("RunMRU", parse_runmru),
        ("Windows Event Logs", parse_event_logs),
    ]
    
    # Execute each collector with error handling
    for collector_name, collector_func in collectors:
        print(f"[*] Collecting {collector_name}...", end=" ")
        
        try:
            results = collector_func(triage_window)
            
            if results:
                all_findings.extend(results)
                print(f"✓ ({len(results)} entries)")
            else:
                print("✓ (0 entries)")
        
        except Exception as e:
            print(f"✗ Error: {str(e)[:50]}")
            if verbose:
                import traceback
                print(f"    Details: {e}")
                traceback.print_exc()
    
    print()
    return all_findings


def sort_findings_by_timestamp(findings):
    """
    Sort findings by timestamp in descending order (most recent first).
    
    Args:
        findings (list): List of finding dictionaries.
    
    Returns:
        list: Sorted findings list.
    """
    print("[*] Sorting findings by timestamp (most recent first)...")
    
    try:
        sorted_findings = sorted(
            findings,
            key=lambda x: x.get('timestamp_dt', datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True
        )
        print(f"[✓] Sorted {len(sorted_findings)} findings")
        return sorted_findings
    
    except Exception as e:
        print(f"[!] Error sorting findings: {e}")
        return findings


def main():
    """
    Main entry point for TraceFinder.
    """
    args = parse_arguments()
    
    # Determine window minutes
    if args.positional_window is not None:
        window_minutes = args.positional_window
    elif args.window is not None:
        window_minutes = args.window
    else:
        window_minutes = 180
    
    # Determine export format
    export_format = args.format
    if args.no_export:
        export_format = 'none'
    elif args.json and export_format == 'csv':
        export_format = 'both'
    
    # Display banner with active window
    print_banner(window_minutes=window_minutes)
    
    # Check administrator privileges
    print("[*] Checking Administrator privileges...")
    if check_admin_privileges():
        print("[✓] Running with Administrator privileges")
    else:
        print("[!] WARNING: Not running as Administrator")
        print("[!] Some forensic artifacts will be inaccessible or partial:")
        print("    - Prefetch files (execution tracking)")
        print("    - USB device history (hardware tracking)")
        print("    - Security Event Logs (process creation 4688, logons 4624)")
        print()
        
        if args.yes:
            print("[*] Non-interactive mode (-y/--yes): continuing without Administrator privileges...")
        else:
            try:
                response = input("[?] Continue anyway? (y/n): ")
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Exiting...")
                sys.exit(1)
            
            if response.lower() != 'y':
                print("[!] Exiting...")
                sys.exit(1)
    
    print()
    
    # Initialize triage window
    print(f"[*] Initializing {window_minutes}-minute triage window...")
    triage = TriageWindow(window_minutes=window_minutes)
    window_info = triage.get_window_info()
    
    print(f"[✓] Triage window configured:")
    print(f"    Window Size : {window_info['window_minutes']} minutes")
    print(f"    Start Time  : {window_info['window_start']}")
    print(f"    End Time    : {window_info['window_end']}")
    print()
    
    # Collect all artifacts
    all_findings = collect_all_artifacts(triage, verbose=args.verbose)
    
    # Sort findings
    sorted_findings = sort_findings_by_timestamp(all_findings)
    
    # Display results
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print()
    
    csv_path = None
    json_path = None
    
    if sorted_findings:
        # Print formatted table unless quiet mode
        if not args.quiet:
            print_findings_table(sorted_findings)
            print()
        else:
            print("[*] Quiet mode enabled: Timeline table suppressed")
            print()
        
        # Print statistics
        print_statistics(sorted_findings)
        print()
        
        # Handle exports
        if export_format in ['csv', 'both']:
            print("[*] Exporting findings to CSV...")
            csv_path = export_to_csv(sorted_findings, output_file=args.output)
            if csv_path:
                print(f"[✓] CSV report saved to: {csv_path}")
            else:
                print("[!] Failed to export CSV report")
        
        if export_format in ['json', 'both']:
            print("[*] Exporting findings to JSON...")
            json_path = export_to_json(
                sorted_findings,
                triage_window=triage,
                output_file=args.output
            )
            if json_path:
                print(f"[✓] JSON report saved to: {json_path}")
            else:
                print("[!] Failed to export JSON report")
    else:
        print("[!] No artifacts found within the triage window")
        print("[!] This could indicate:")
        print("    - No user activity in the specified time window")
        print("    - System has been powered off")
        print("    - Artifacts have been cleared/deleted")
        print("    - Insufficient privileges to access artifacts")
    
    # Print completion banner
    print()
    print("=" * 70)
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                   TraceFinder Analysis Complete                    ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print("=" * 70)
    print()
    
    if sorted_findings:
        print(f"[✓] Total artifacts collected: {len(sorted_findings)}")
        if csv_path:
            print(f"[✓] CSV Report : {csv_path}")
        if json_path:
            print(f"[✓] JSON Report: {json_path}")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        if "-v" in sys.argv or "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)