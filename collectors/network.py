"""
TraceFinder - Network & Browser Activity Collectors
collectors/network.py

"""

import os
import sqlite3
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone


def parse_browser_history(triage_window):
    """
    Parse browser history from Chrome, Edge, and Firefox.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    localappdata = os.getenv('LOCALAPPDATA')
    appdata = os.getenv('APPDATA')
    
    if not localappdata or not appdata:
        return findings
    
    browsers = {
        'Chrome': Path(localappdata) / 'Google' / 'Chrome' / 'User Data' / 'Default' / 'History',
        'Edge': Path(localappdata) / 'Microsoft' / 'Edge' / 'User Data' / 'Default' / 'History',
    }
    
    # Chrome and Edge
    for browser_name, history_path in browsers.items():
        try:
            if not history_path.exists():
                continue
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            
            try:
                shutil.copy2(history_path, tmp_path)
                conn = sqlite3.connect(tmp_path)
                cursor = conn.cursor()
                
                query = """
                    SELECT urls.url, urls.title, urls.visit_count, visits.visit_time
                    FROM urls
                    INNER JOIN visits ON urls.id = visits.url
                    ORDER BY visits.visit_time DESC
                """
                
                cursor.execute(query)
                rows = cursor.fetchall()
                
                for row in rows:
                    url, title, visit_count, visit_time = row
                    
                    chrome_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                    visit_dt = chrome_epoch + timedelta(microseconds=visit_time)
                    
                    if triage_window.is_within_window(visit_dt):
                        findings.append({
                            'timestamp': visit_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'timestamp_dt': visit_dt,
                            'artifact_type': 'Web Activity',
                            'source': f'{browser_name} Browser',
                            'description': title[:100] if title else 'No Title',
                            'details': f"URL: {url}"
                        })
                
                conn.close()
            
            finally:
                try:
                    os.unlink(tmp_path)
                except:
                    pass
        
        except Exception:
            continue
    
    # Firefox
    try:
        firefox_profiles = Path(appdata) / 'Mozilla' / 'Firefox' / 'Profiles'
        
        if firefox_profiles.exists():
            for profile_dir in firefox_profiles.glob('*.default*'):
                places_db = profile_dir / 'places.sqlite'
                
                if not places_db.exists():
                    continue
                
                with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                    tmp_path = tmp.name
                
                try:
                    shutil.copy2(places_db, tmp_path)
                    conn = sqlite3.connect(tmp_path)
                    cursor = conn.cursor()
                    
                    query = """
                        SELECT moz_places.url, moz_places.title, 
                               moz_places.visit_count, moz_historyvisits.visit_date
                        FROM moz_places
                        INNER JOIN moz_historyvisits 
                            ON moz_places.id = moz_historyvisits.place_id
                        ORDER BY moz_historyvisits.visit_date DESC
                    """
                    
                    cursor.execute(query)
                    rows = cursor.fetchall()
                    
                    for row in rows:
                        url, title, visit_count, visit_date = row
                        
                        visit_dt = datetime.fromtimestamp(
                            visit_date / 1000000,
                            tz=timezone.utc
                        )
                        
                        if triage_window.is_within_window(visit_dt):
                            findings.append({
                                'timestamp': visit_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'timestamp_dt': visit_dt,
                                'artifact_type': 'Web Activity',
                                'source': 'Firefox Browser',
                                'description': title[:100] if title else 'No Title',
                                'details': f"URL: {url}"
                            })
                    
                    conn.close()
                
                finally:
                    try:
                        os.unlink(tmp_path)
                    except:
                        pass
                
                break
    
    except Exception:
        pass
    
    return findings


def parse_downloads(triage_window):
    """
    Parse browser download history.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    localappdata = os.getenv('LOCALAPPDATA')
    
    if not localappdata:
        return findings
    
    browsers = {
        'Chrome': Path(localappdata) / 'Google' / 'Chrome' / 'User Data' / 'Default' / 'History',
        'Edge': Path(localappdata) / 'Microsoft' / 'Edge' / 'User Data' / 'Default' / 'History',
    }
    
    for browser_name, history_path in browsers.items():
        try:
            if not history_path.exists():
                continue
            
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name
            
            try:
                shutil.copy2(history_path, tmp_path)
                conn = sqlite3.connect(tmp_path)
                cursor = conn.cursor()
                
                query = """
                    SELECT target_path, tab_url, start_time, total_bytes, mime_type
                    FROM downloads
                    ORDER BY start_time DESC
                """
                
                cursor.execute(query)
                rows = cursor.fetchall()
                
                for row in rows:
                    target_path, source_url, start_time, file_size, mime_type = row
                    
                    chrome_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
                    download_dt = chrome_epoch + timedelta(microseconds=start_time)
                    
                    if triage_window.is_within_window(download_dt):
                        findings.append({
                            'timestamp': download_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                            'timestamp_dt': download_dt,
                            'artifact_type': 'Download',
                            'source': f'{browser_name} Browser',
                            'description': Path(target_path).name,
                            'details': f"Size: {file_size} bytes, Source: {source_url}"
                        })
                
                conn.close()
            
            finally:
                try:
                    os.unlink(tmp_path)
                except:
                    pass
        
        except Exception:
            continue
    
    return findings