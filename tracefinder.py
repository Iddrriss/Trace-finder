"""
TraceFinder v1.0 - Windows Forensic Activity Detection Tool
Main Entry Point

Author: Oxseeker
Compliance: PEP8

Description:
    Main orchestration script for TraceFinder forensic collection.
    Coordinates all collection modules and generates unified reports.
"""

import sys
from datetime import datetime, timezone

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

# Import reporters
from reporters.console import print_banner, print_findings_table, print_statistics
from reporters.csv_exporter import export_to_csv


def collect_all_artifacts(triage_window):
    """
    Orchestrate collection from all forensic modules.
    
    This function calls each collection module and aggregates results.
    If a module fails, it logs the error and continues with others.
    
    Args:
        triage_window (TriageWindow): Time window for filtering results.
    
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
        ("RunMRU", parse_runmru)
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
            # Log detailed error but continue execution
            if "--verbose" in sys.argv:
                print(f"    Details: {e}")
    
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
        # Sort by timestamp_dt field
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
    
    Workflow:
        1. Display banner and check privileges
        2. Initialize triage window
        3. Collect artifacts from all modules
        4. Sort findings by timestamp
        5. Display results (console table + statistics)
        6. Export to CSV
    """
    # Display banner
    print_banner()
    
    # Check administrator privileges
    print("[*] Checking Administrator privileges...")
    if check_admin_privileges():
        print("[✓] Running with Administrator privileges")
    else:
        print("[!] WARNING: Not running as Administrator")
        print("[!] Some forensic artifacts will be inaccessible:")
        print("    - Prefetch files (execution tracking)")
        print("    - USB device history (hardware tracking)")
        print()
        
        response = input("[?] Continue anyway? (y/n): ")
        if response.lower() != 'y':
            print("[!] Exiting...")
            sys.exit(1)
    
    print()
    
    # Initialize triage window
    print("[*] Initializing 180-minute triage window...")
    
    # Allow custom window via command line argument
    window_minutes = 180
    if len(sys.argv) > 1 and sys.argv[1].isdigit():
        window_minutes = int(sys.argv[1])
    
    triage = TriageWindow(window_minutes=window_minutes)
    window_info = triage.get_window_info()
    
    print(f"[✓] Triage window configured:")
    print(f"    Window Size : {window_info['window_minutes']} minutes")
    print(f"    Start Time  : {window_info['window_start']}")
    print(f"    End Time    : {window_info['window_end']}")
    print()
    
    # Collect all artifacts
    all_findings = collect_all_artifacts(triage)
    
    # Sort findings
    sorted_findings = sort_findings_by_timestamp(all_findings)
    
    # Display results
    print("=" * 70)
    print("RESULTS")
    print("=" * 70)
    print()
    
    if sorted_findings:
        # Print formatted table
        print_findings_table(sorted_findings)
        print()
        
        # Print statistics
        print_statistics(sorted_findings)
        print()
        
        # Export to CSV
        print("[*] Exporting findings to CSV...")
        csv_path = export_to_csv(sorted_findings)
        
        if csv_path:
            print(f"[✓] CSV report saved to: {csv_path}")
        else:
            print("[!] Failed to export CSV report")
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
        print(f"[✓] Report available at: {csv_path}")
        print()


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Collection interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"\n[!] Critical error: {e}")
        if "--verbose" in sys.argv:
            import traceback
            traceback.print_exc()
        sys.exit(1)