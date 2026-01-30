"""
TraceFinder - Execution Evidence Collectors
collectors/execution.py

"""

import winreg
import struct
import codecs
from pathlib import Path
from datetime import datetime, timezone

from core.time_window import filetime_to_datetime


def parse_userassist(triage_window):
    """
    Parse UserAssist registry entries for GUI program executions.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    
    guids = [
        '{CEBFF5CD-ACE2-4F4F-9178-9926F41749EA}',
        '{F4E57C4B-2036-45F0-A9AB-443BCFE33D9F}'
    ]
    
    base_path = r'Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist'
    
    try:
        for guid in guids:
            registry_path = f"{base_path}\\{guid}\\Count"
            
            try:
                key = winreg.OpenKey(
                    winreg.HKEY_CURRENT_USER,
                    registry_path,
                    0,
                    winreg.KEY_READ
                )
                
                index = 0
                while True:
                    try:
                        val_name, val_data, val_type = winreg.EnumValue(key, index)
                        decoded_name = codecs.decode(val_name, 'rot_13')
                        
                        if len(val_data) >= 72:
                            last_run_filetime = struct.unpack('<Q', val_data[60:68])[0]
                            run_count = struct.unpack('<I', val_data[4:8])[0]
                            focus_time = struct.unpack('<I', val_data[8:12])[0]
                            
                            last_run_dt = filetime_to_datetime(last_run_filetime)
                            
                            if last_run_dt and triage_window.is_within_window(last_run_dt):
                                findings.append({
                                    'timestamp': last_run_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                    'timestamp_dt': last_run_dt,
                                    'artifact_type': 'Execution',
                                    'source': 'UserAssist',
                                    'description': decoded_name,
                                    'details': f"Run Count: {run_count}, Focus Time: {focus_time}ms"
                                })
                        
                        index += 1
                    except OSError:
                        break
                
                winreg.CloseKey(key)
            
            except (FileNotFoundError, PermissionError):
                continue
    
    except Exception:
        pass
    
    return findings


def parse_prefetch(triage_window):
    """
    Parse Prefetch files for program execution evidence.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    prefetch_path = Path(r'C:\Windows\Prefetch')
    
    try:
        if not prefetch_path.exists():
            return findings
        
        for pf_file in prefetch_path.glob('*.pf'):
            try:
                mod_time_timestamp = pf_file.stat().st_mtime
                mod_time = datetime.fromtimestamp(mod_time_timestamp, tz=timezone.utc)
                
                if triage_window.is_within_window(mod_time):
                    file_name = pf_file.stem
                    
                    if '-' in file_name:
                        executable_name = '-'.join(file_name.split('-')[:-1]).upper()
                    else:
                        executable_name = file_name.upper()
                    
                    findings.append({
                        'timestamp': mod_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'timestamp_dt': mod_time,
                        'artifact_type': 'Execution',
                        'source': 'Prefetch',
                        'description': executable_name,
                        'details': f"File: {pf_file}"
                    })
            
            except (OSError, PermissionError):
                continue
    
    except PermissionError:
        pass
    
    return findings