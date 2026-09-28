"""Registry artifact collectors (TypedPaths)."""

import winreg
from core.time_window import filetime_to_datetime


def parse_typed_paths(triage_window):
    """Parse TypedPaths registry key for Explorer address bar history."""
    findings = []
    registry_path = r'Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths'

    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry_path, 0, winreg.KEY_READ)
        _, _, last_modified = winreg.QueryInfoKey(key)
        key_modified = filetime_to_datetime(last_modified)

        if key_modified and triage_window.is_within_window(key_modified):
            index = 0
            while True:
                try:
                    val_name, val_data, _ = winreg.EnumValue(key, index)
                    if val_data:
                        findings.append({
                            'timestamp': key_modified.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'timestamp_dt': key_modified,
                            'artifact_type': 'Registry',
                            'source': 'TypedPaths',
                            'description': val_data,
                            'details': f"Entry: {val_name}"
                        })
                    index += 1
                except OSError:
                    break

        winreg.CloseKey(key)
    except (FileNotFoundError, PermissionError, OSError):
        pass

    return findings