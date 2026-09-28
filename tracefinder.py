"""TraceFinder - Windows Forensic Activity Detection Tool."""

import sys
import argparse
from datetime import datetime, timezone

if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass

from core.privileges import check_admin_privileges
from core.time_window import TriageWindow

from collectors.execution import parse_userassist, parse_prefetch
from collectors.files import parse_recent_files, parse_recentdocs
from collectors.hardware import parse_usb_devices
from collectors.commands import parse_powershell_history, parse_runmru
from collectors.network import parse_browser_history, parse_downloads
from collectors.registry import parse_typed_paths
from collectors.events import parse_event_logs

from reporters.console import print_banner, print_findings_table, print_statistics
from reporters.csv_exporter import export_to_csv
from reporters.json_exporter import export_to_json


def parse_arguments():
    """Parse command-line arguments and triage options."""
    parser = argparse.ArgumentParser(
        prog="tracefinder",
        description="TraceFinder - Windows Forensic Activity Detection & Triage Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python tracefinder.py                     # Default 180-minute window, export to CSV
  python tracefinder.py 60                  # Scan last 60 minutes
  python tracefinder.py -w 360 -f json      # Scan last 6 hours, export to JSON
  python tracefinder.py -f both -o case101  # Export CSV and JSON with prefix 'case101'
  python tracefinder.py --quiet --yes       # Non-interactive summary execution
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
        help='Output filename or base prefix for reports'
    )
    parser.add_argument(
        '-f', '--format',
        choices=['csv', 'json', 'both', 'none'],
        default='csv',
        help='Report format: csv, json, both, or none (default: csv)'
    )
    parser.add_argument(
        '--json',
        action='store_true',
        help='Export JSON report (shorthand for -f json or -f both)'
    )
    parser.add_argument(
        '--no-export',
        action='store_true',
        help='Suppress saving report files to disk (console only)'
    )
    parser.add_argument(
        '-q', '--quiet',
        action='store_true',
        help='Suppress the timeline table and display summary only'
    )
    parser.add_argument(
        '-y', '--yes',
        action='store_true',
        help='Non-interactive mode: skip confirmation prompts'
    )
    parser.add_argument(
        '-v', '--verbose',
        action='store_true',
        help='Display verbose error traces'
    )

    return parser.parse_args()


def collect_all_artifacts(triage_window, verbose=False):
    """Run all forensic collection modules against the triage window."""
    all_findings = []

    print("-" * 65)
    print("Collecting Forensic Artifacts")
    print("-" * 65)

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

    for collector_name, collector_func in collectors:
        print(f"[*] {collector_name}...", end=" ", flush=True)

        try:
            results = collector_func(triage_window)
            count = len(results) if results else 0
            all_findings.extend(results or [])
            print(f"[+] ({count} entries)")

        except Exception as e:
            print(f"[-] Error: {str(e)[:50]}")
            if verbose:
                import traceback
                print(f"    Details: {e}")
                traceback.print_exc()

    print()
    return all_findings


def sort_findings_by_timestamp(findings):
    """Sort findings chronologically in descending order (newest first)."""
    try:
        return sorted(
            findings,
            key=lambda x: x.get('timestamp_dt', datetime.min.replace(tzinfo=timezone.utc)),
            reverse=True
        )
    except Exception as e:
        print(f"[!] Error sorting findings: {e}")
        return findings


def main():
    args = parse_arguments()

    if args.positional_window is not None:
        window_minutes = args.positional_window
    elif args.window is not None:
        window_minutes = args.window
    else:
        window_minutes = 180

    export_format = args.format
    if args.no_export:
        export_format = 'none'
    elif args.json and export_format == 'csv':
        export_format = 'both'

    print_banner(window_minutes=window_minutes)

    if check_admin_privileges():
        print("[+] Running with Administrator privileges")
    else:
        print("[!] Running as Standard User (Limited access)")
        print("[!] The following artifacts require elevated privileges and will be skipped/partial:")
        print("    - Prefetch files (execution tracking)")
        print("    - USB device history (hardware tracking)")
        print("    - Security Event Logs (process creation, authentication)")
        print()

        if args.yes:
            print("[*] Continuing without Administrator privileges (--yes)")
        else:
            try:
                response = input("[?] Continue anyway? [y/N]: ").strip().lower()
            except (EOFError, KeyboardInterrupt):
                print("\n[!] Exiting...")
                sys.exit(1)

            if response not in ('y', 'yes'):
                print("[!] Exiting...")
                sys.exit(1)

    print()
    triage = TriageWindow(window_minutes=window_minutes)
    window_info = triage.get_window_info()

    print(f"[*] Window bounds : {window_info['window_start']} to {window_info['window_end']}")
    print()

    all_findings = collect_all_artifacts(triage, verbose=args.verbose)
    sorted_findings = sort_findings_by_timestamp(all_findings)

    csv_path = None
    json_path = None

    if sorted_findings:
        if not args.quiet:
            print_findings_table(sorted_findings)
            print()
        else:
            print("[*] Quiet mode enabled: Timeline table suppressed\n")

        print_statistics(sorted_findings)
        print()

        if export_format in ['csv', 'both']:
            print("[*] Exporting to CSV...")
            csv_path = export_to_csv(sorted_findings, output_file=args.output)
            if csv_path:
                print(f"[+] CSV report saved: {csv_path}")
            else:
                print("[-] Failed to export CSV report")

        if export_format in ['json', 'both']:
            print("[*] Exporting to JSON...")
            json_path = export_to_json(
                sorted_findings,
                triage_window=triage,
                output_file=args.output
            )
            if json_path:
                print(f"[+] JSON report saved: {json_path}")
            else:
                print("[-] Failed to export JSON report")
    else:
        print("[!] No artifacts found within the triage window.")
        print("    - No user activity occurred in this timeframe")
        print("    - System was powered off")
        print("    - Artifacts may have been cleared")
        print("    - Access restricted by permissions")

    print()
    print("=" * 70)
    print("╔════════════════════════════════════════════════════════════════════╗")
    print("║                   TraceFinder Analysis Complete                    ║")
    print("╚════════════════════════════════════════════════════════════════════╝")
    print("=" * 70)

    if sorted_findings:
        print(f"  Artifacts collected : {len(sorted_findings)}")
        if csv_path:
            print(f"  CSV Report          : {csv_path}")
        if json_path:
            print(f"  JSON Report         : {json_path}")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Fatal error: {e}")
        if "-v" in sys.argv or "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)