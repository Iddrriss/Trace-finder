"""
TraceFinder - Diagnostic & Health Check Script
check.py

Runs complete diagnostics across the TraceFinder codebase:
1. Syntax & Bytecode Compilation
2. Package & Module Imports
3. Unit Test Suite (python -m unittest)
4. Runtime Environment & Privileges
5. Individual Collector Smoke Tests
"""

import sys
import os
import platform
import compileall
import unittest
from datetime import datetime

# Ensure UTF-8 output on Windows consoles
if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def run_checks():
    print("=" * 70)
    print("           TraceFinder System & Diagnostic Health Check")
    print("=" * 70)
    print()

    # 1. Environment Check
    print("[*] 1. Environment & Runtime:")
    print(f"    - OS Platform     : {platform.system()} {platform.release()} ({platform.version()})")
    print(f"    - Python Version  : {sys.version.split()[0]} ({sys.executable})")
    print(f"    - Working Dir     : {os.getcwd()}")
    
    from core.privileges import check_admin_privileges
    is_admin = check_admin_privileges()
    status_str = "Administrator (Full access)" if is_admin else "Standard User (Limited access)"
    print(f"    - Privileges      : {status_str}")
    print()

    # 2. Compilation Check
    print("[*] 2. Syntax & Compilation Check:")
    compile_success = compileall.compile_dir(".", quiet=1)
    if compile_success:
        print("    [✓] All Python source files compiled successfully with 0 syntax errors.")
    else:
        print("    [!] Compilation encountered errors.")
    print()

    # 3. Unit Tests
    print("[*] 3. Running Unit Test Suite:")
    loader = unittest.TestLoader()
    suite = loader.discover('tests')
    runner = unittest.TextTestRunner(verbosity=1)
    test_result = runner.run(suite)
    if test_result.wasSuccessful():
        print(f"    [✓] All {test_result.testsRun} unit tests passed successfully.")
    else:
        print(f"    [!] {len(test_result.failures)} failure(s), {len(test_result.errors)} error(s).")
    print()

    # 4. Collector Diagnostics (Smoke Test with 180 min window)
    print("[*] 4. Collector Health & Smoke Tests (180 min window):")
    from core.time_window import TriageWindow
    from collectors.execution import parse_userassist, parse_prefetch
    from collectors.files import parse_recent_files, parse_recentdocs
    from collectors.hardware import parse_usb_devices
    from collectors.commands import parse_powershell_history, parse_runmru
    from collectors.network import parse_browser_history, parse_downloads
    from collectors.registry import parse_typed_paths
    from collectors.events import parse_event_logs

    triage = TriageWindow(180)
    collectors = [
        ("UserAssist", parse_userassist, False),
        ("Prefetch", parse_prefetch, True),
        ("Recent Files", parse_recent_files, False),
        ("USB Devices", parse_usb_devices, True),
        ("PowerShell History", parse_powershell_history, False),
        ("Browser History", parse_browser_history, False),
        ("Downloads", parse_downloads, False),
        ("RecentDocs", parse_recentdocs, False),
        ("TypedPaths", parse_typed_paths, False),
        ("RunMRU", parse_runmru, False),
        ("Event Logs", parse_event_logs, False),
    ]

    all_ok = True
    total_found = 0
    for name, func, requires_admin in collectors:
        note = " (requires Admin)" if requires_admin and not is_admin else ""
        try:
            results = func(triage)
            count = len(results) if results else 0
            total_found += count
            print(f"    [✓] {name:<22}: OK ({count:>3} artifacts collected){note}")
        except Exception as e:
            all_ok = False
            print(f"    [✗] {name:<22}: ERROR ({e})")

    print()
    print(f"    Total artifacts reachable in smoke test: {total_found}")
    print()

    # Summary
    print("=" * 70)
    if compile_success and test_result.wasSuccessful() and all_ok:
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                   ALL SYSTEM CHECKS PASSED                         ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        print("TraceFinder is healthy, fully operational, and ready for deployment.")
        return 0
    else:
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                   SOME CHECKS REQUIRE ATTENTION                   ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        return 1


if __name__ == '__main__':
    exit_code = run_checks()
    sys.exit(exit_code)
