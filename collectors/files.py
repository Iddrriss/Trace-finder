"""
TraceFinder - File Activity Collectors
collectors/files.py

"""

import os
import re
import winreg
from pathlib import Path
from datetime import datetime, timezone

from core.time_window import filetime_to_datetime


def parse_recent_files(triage_window):
    """
    Parse Recent folder for recently accessed file shortcuts.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    
    appdata_path = os.getenv('APPDATA')
    if not appdata_path:
        return findings
    
    recent_path = Path(appdata_path) / 'Microsoft' / 'Windows' / 'Recent'
    
    try:
        if not recent_path.exists():
            return findings
        
        for lnk_file in recent_path.glob('*.lnk'):
            try:
                stat_info = lnk_file.stat()
                mod_time = datetime.fromtimestamp(stat_info.st_mtime, tz=timezone.utc)
                create_time = datetime.fromtimestamp(stat_info.st_ctime, tz=timezone.utc)
                last_accessed = max(mod_time, create_time)
                
                if triage_window.is_within_window(last_accessed):
                    target_path = extract_lnk_target(lnk_file)
                    
                    findings.append({
                        'timestamp': last_accessed.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'timestamp_dt': last_accessed,
                        'artifact_type': 'File Access',
                        'source': 'Recent Folder',
                        'description': lnk_file.name,
                        'details': f"Target: {target_path}"
                    })
            
            except (OSError, PermissionError):
                continue
    
    except Exception:
        pass
    
    return findings


def extract_lnk_target(lnk_path):
    """
    Extract target file path from Windows .lnk (shortcut) file.
    
    Args:
        lnk_path (Path): Path to the .lnk file.
    
    Returns:
        str: Target file path, or error message if extraction fails.
    """
    try:
        with open(lnk_path, 'rb') as f:
            content = f.read()
            
            if len(content) < 4 or content[0] != 0x4C:
                return "Invalid .lnk file"
            
            content_str = content.decode('latin-1', errors='ignore')
            
            path_patterns = [
                r'([A-Z]:\\[^\x00]+)',
                r'(\\\\[^\\]+\\[^\x00]+)',
            ]
            
            for pattern in path_patterns:
                matches = re.findall(pattern, content_str)
                if matches:
                    for match in matches:
                        cleaned_path = match.split('\x00')[0]
                        if len(cleaned_path) > 3:
                            return cleaned_path
            
            return "Unable to parse target path"
    
    except Exception:
        return "Error parsing .lnk file"


def parse_recentdocs(triage_window):
    """
    Parse RecentDocs registry for recently accessed documents.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    base_path = r'Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs'
    
    try:
        key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, base_path, 0, winreg.KEY_READ)
        
        try:
            num_subkeys, num_values, last_modified = winreg.QueryInfoKey(key)
            key_modified = filetime_to_datetime(last_modified)
            
            if key_modified and triage_window.is_within_window(key_modified):
                index = 0
                while True:
                    try:
                        extension = winreg.EnumKey(key, index)
                        ext_path = f"{base_path}\\{extension}"
                        
                        ext_key = winreg.OpenKey(
                            winreg.HKEY_CURRENT_USER,
                            ext_path,
                            0,
                            winreg.KEY_READ
                        )
                        
                        val_index = 0
                        while True:
                            try:
                                val_name, val_data, val_type = winreg.EnumValue(
                                    ext_key, val_index
                                )
                                
                                if val_name != 'MRUListEx' and isinstance(val_data, bytes):
                                    try:
                                        filename = val_data.decode(
                                            'utf-16-le',
                                            errors='ignore'
                                        ).rstrip('\x00')
                                        
                                        if filename:
                                            findings.append({
                                                'timestamp': key_modified.strftime(
                                                    '%Y-%m-%d %H:%M:%S UTC'
                                                ),
                                                'timestamp_dt': key_modified,
                                                'artifact_type': 'File Access',
                                                'source': 'RecentDocs',
                                                'description': filename,
                                                'details': f"Extension: .{extension}"
                                            })
                                    except:
                                        pass
                                
                                val_index += 1
                            except OSError:
                                break
                        
                        winreg.CloseKey(ext_key)
                        index += 1
                    except OSError:
                        break
        except:
            pass
        
        winreg.CloseKey(key)
    
    except Exception:
        pass
    
    return findings