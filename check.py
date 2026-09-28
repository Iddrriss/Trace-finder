"""Diagnostic and sanity check script for TraceFinder."""

import sys
import os
import platform
import compileall
import unittest

if sys.platform == 'win32':
    try:
        if hasattr(sys.stdout, 'reconfigure'):
            sys.stdout.reconfigure(encoding='utf-8', errors='replace')
        if hasattr(sys.stderr, 'reconfigure'):
            sys.stderr.reconfigure(encoding='utf-8', errors='replace')
    except Exception:
        pass


def run_checks():
    print("=" * 65)
    print("TraceFinder System Diagnostic Check")
    print("=" * 65)
    print()

    # Environment
    print("[*] Runtime Environment:")
    print(f"    Platform    : {platform.system()} {platform.release()} ({platform.version()})")
    print(f"    Python      : {sys.version.split()[0]} ({sys.executable})")
    print(f"    Working Dir : {os.getcwd()}")

    from core.privileges import check_admin_privileges
    is_admin = check_admin_privileges()
    priv_str = "Administrator" if is_admin else "Standard User"
    print(f"    Privileges  : {priv_str}")
    print()

    # Bytecode compilation
    print("[*] Syntax & Compilation:")
    compile_success = compileall.compile_dir(".", quiet=1)
    if compile_success:
        print("    [+] Python source files compiled with 0 syntax errors.")
    else:
        print("    [!] Compilation encountered errors.")
    print()

    # Unit tests
    print("[*] Unit Tests:")
    loader = unittest.TestLoader()
    suite = loader.discover('tests')
    runner = unittest.TextTestRunner(verbosity=1)
    test_result = runner.run(suite)
    if test_result.wasSuccessful():
        print(f"    [+] {test_result.testsRun} tests passed.")
    else:
        print(f"    [!] {len(test_result.failures)} failure(s), {len(test_result.errors)} error(s).")
    print()

    # Collector smoke tests
    print("[*] Collector Smoke Tests (180-min window):")
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
        note = " (skipped - requires admin)" if requires_admin and not is_admin else ""
        try:
            results = func(triage)
            count = len(results) if results else 0
            total_found += count
            print(f"    [+] {name:<22}: OK ({count:>3} artifacts){note}")
        except Exception as e:
            all_ok = False
            print(f"    [-] {name:<22}: FAILED ({e})")

    print()
    print(f"    Total artifacts collected in smoke test: {total_found}")
    print()

    print("=" * 70)
    if compile_success and test_result.wasSuccessful() and all_ok:
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                   ALL SYSTEM CHECKS PASSED                         ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        return 0
    else:
        print("╔════════════════════════════════════════════════════════════════════╗")
        print("║                   SOME CHECKS REQUIRE ATTENTION                   ║")
        print("╚════════════════════════════════════════════════════════════════════╝")
        return 1


if __name__ == '__main__':
    sys.exit(run_checks())
