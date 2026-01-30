"""
TraceFinder - Command Line Evidence Collectors
collectors/commands.py

"""

import os
import winreg
from pathlib import Path
from datetime import datetime, timezone

from core.time_window import filetime_to_datetime


def parse_powershell_history(triage_window):
    """
    Parse PowerShell command history from ConsoleHost_history.txt.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    
    appdata_path = os.getenv('APPDATA')
    if not appdata_path:
        return findings
    
    history_path = Path(appdata_path) / 'Microsoft' / 'Windows' / \
                   'PowerShell' / 'PSReadLine' / 'ConsoleHost_history.txt'
    
    try:
        if not history_path.exists():
            return findings
        
        stat_info = history_path.stat()
        mod_time = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)
        
        if triage_window.is_within_window(mod_time):
            try:
                with open(history_path, 'r', encoding='utf-8', errors='ignore') as f:
                    commands = f.readlines()
                
                commands = [cmd.rstrip('\n\r') for cmd in commands if cmd.strip()]
                
                if commands:
                    findings.append({
                        'timestamp': mod_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'timestamp_dt': mod_time,
                        'artifact_type': 'Command Line',
                        'source': 'PowerShell',
                        'description': f"History file modified ({len(commands)} commands)",
                        'details': f"Last 5 commands: {'; '.join(commands[-5:])}"
                    })
            
            except (PermissionError, Exception):
                pass
    
    except Exception:
        pass
    
    return findings


def parse_runmru(triage_window):
    """
    Parse RunMRU registry for Run dialog command history.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    registry_path = r'Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU'
    
    try:
        key = winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            registry_path,
            0,
            winreg.KEY_READ
        )
        
        num_subkeys, num_values, last_modified = winreg.QueryInfoKey(key)
        key_modified = filetime_to_datetime(last_modified)
        
        if key_modified and triage_window.is_within_window(key_modified):
            index = 0
            while True:
                try:
                    val_name, val_data, val_type = winreg.EnumValue(key, index)
                    
                    if val_name != 'MRUList' and val_data:
                        command = val_data.rstrip('\\1')
                        
                        findings.append({
                            'timestamp': key_modified.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'timestamp_dt': key_modified,
                            'artifact_type': 'Command Line',
                            'source': 'RunMRU',
                            'description': command,
                            'details': f"Entry: {val_name}"
                        })
                    
                    index += 1
                except OSError:
                    break
        
        winreg.CloseKey(key)
    
    except (FileNotFoundError, PermissionError, Exception):
        pass
    
    return findings