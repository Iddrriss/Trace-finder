"""Browser history and download artifact collectors for Chromium and Firefox profiles."""

import os
import sqlite3
import tempfile
import shutil
from pathlib import Path
from datetime import datetime, timedelta, timezone


def find_chromium_profiles(user_data_dir):
    """Enumerate profile directories that contain a History database."""
    profiles = []
    if not user_data_dir.exists():
        return profiles

    try:
        for entry in user_data_dir.iterdir():
            if entry.is_dir() and (entry / 'History').is_file():
                profiles.append((entry.name, entry / 'History'))
    except (PermissionError, OSError):
        pass

    return profiles


def get_browser_targets():
    """Discover installed Chromium and Opera browser profiles."""
    targets = []
    localappdata = os.getenv('LOCALAPPDATA')
    appdata = os.getenv('APPDATA')

    chromium_browsers = {}
    if localappdata:
        chromium_browsers.update({
            'Chrome': Path(localappdata) / 'Google' / 'Chrome' / 'User Data',
            'Edge': Path(localappdata) / 'Microsoft' / 'Edge' / 'User Data',
            'Brave': Path(localappdata) / 'BraveSoftware' / 'Brave-Browser' / 'User Data',
            'Vivaldi': Path(localappdata) / 'Vivaldi' / 'User Data',
        })

    for browser_name, user_data_dir in chromium_browsers.items():
        for profile_name, history_path in find_chromium_profiles(user_data_dir):
            targets.append({
                'browser': browser_name,
                'profile': profile_name,
                'history_path': history_path,
                'type': 'chromium'
            })

    if appdata:
        opera_paths = [
            ('Opera', Path(appdata) / 'Opera Software' / 'Opera Stable' / 'History'),
            ('Opera GX', Path(appdata) / 'Opera Software' / 'Opera GX Stable' / 'History'),
        ]
        for op_name, op_history in opera_paths:
            if op_history.is_file():
                targets.append({
                    'browser': op_name,
                    'profile': 'Default',
                    'history_path': op_history,
                    'type': 'chromium'
                })

    return targets


def parse_browser_history(triage_window):
    """Parse browser navigation history across supported browser profiles."""
    findings = []
    chrome_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)

    # Chromium-based browsers
    for target in get_browser_targets():
        browser_name = target['browser']
        profile_name = target['profile']
        history_path = target['history_path']

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name

            # Copy to temp file to prevent locking conflicts with running browsers
            shutil.copy2(history_path, tmp_path)
            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()

            query = """
                SELECT urls.url, urls.title, urls.visit_count, visits.visit_time
                FROM urls
                INNER JOIN visits ON urls.id = visits.url
                ORDER BY visits.visit_time DESC
            """
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
            except sqlite3.OperationalError:
                rows = []
            conn.close()

            for url, title, visit_count, visit_time in rows:
                if not visit_time:
                    continue
                try:
                    visit_dt = chrome_epoch + timedelta(microseconds=visit_time)
                except (OverflowError, ValueError):
                    continue

                if triage_window.is_within_window(visit_dt):
                    findings.append({
                        'timestamp': visit_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'timestamp_dt': visit_dt,
                        'artifact_type': 'Web Activity',
                        'source': f"{browser_name} ({profile_name})",
                        'description': title[:100] if title else 'No Title',
                        'details': f"URL: {url} | Visits: {visit_count}"
                    })
        except Exception:
            continue
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    # Firefox profiles
    appdata = os.getenv('APPDATA')
    if appdata:
        try:
            firefox_profiles_dir = Path(appdata) / 'Mozilla' / 'Firefox' / 'Profiles'
            if firefox_profiles_dir.exists():
                for profile_dir in firefox_profiles_dir.iterdir():
                    if not profile_dir.is_dir():
                        continue

                    places_db = profile_dir / 'places.sqlite'
                    if not places_db.is_file():
                        continue

                    tmp_path = None
                    try:
                        with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                            tmp_path = tmp.name

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
                        try:
                            cursor.execute(query)
                            rows = cursor.fetchall()
                        except sqlite3.OperationalError:
                            rows = []
                        conn.close()

                        for url, title, visit_count, visit_date in rows:
                            if not visit_date:
                                continue
                            try:
                                visit_dt = datetime.fromtimestamp(visit_date / 1_000_000, tz=timezone.utc)
                            except (OverflowError, ValueError, OSError):
                                continue

                            if triage_window.is_within_window(visit_dt):
                                findings.append({
                                    'timestamp': visit_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                    'timestamp_dt': visit_dt,
                                    'artifact_type': 'Web Activity',
                                    'source': f"Firefox ({profile_dir.name})",
                                    'description': title[:100] if title else 'No Title',
                                    'details': f"URL: {url} | Visits: {visit_count}"
                                })
                    except Exception:
                        continue
                    finally:
                        if tmp_path and os.path.exists(tmp_path):
                            try:
                                os.unlink(tmp_path)
                            except OSError:
                                pass
        except Exception:
            pass

    return findings


def parse_downloads(triage_window):
    """Parse downloaded file records across Chromium browser profiles."""
    findings = []
    chrome_epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)

    for target in get_browser_targets():
        browser_name = target['browser']
        profile_name = target['profile']
        history_path = target['history_path']

        tmp_path = None
        try:
            with tempfile.NamedTemporaryFile(delete=False, suffix='.db') as tmp:
                tmp_path = tmp.name

            shutil.copy2(history_path, tmp_path)
            conn = sqlite3.connect(tmp_path)
            cursor = conn.cursor()

            query = """
                SELECT target_path, tab_url, start_time, total_bytes, mime_type
                FROM downloads
                ORDER BY start_time DESC
            """
            try:
                cursor.execute(query)
                rows = cursor.fetchall()
            except sqlite3.OperationalError:
                rows = []
            conn.close()

            for target_path, source_url, start_time, file_size, mime_type in rows:
                if not start_time:
                    continue
                try:
                    download_dt = chrome_epoch + timedelta(microseconds=start_time)
                except (OverflowError, ValueError):
                    continue

                if triage_window.is_within_window(download_dt):
                    filename = Path(target_path).name if target_path else 'Unknown'
                    findings.append({
                        'timestamp': download_dt.strftime('%Y-%m-%d %H:%M:%S UTC'),
                        'timestamp_dt': download_dt,
                        'artifact_type': 'Download',
                        'source': f"{browser_name} ({profile_name})",
                        'description': filename,
                        'details': f"Size: {file_size} bytes | Source: {source_url} | Type: {mime_type or 'N/A'}"
                    })
        except Exception:
            continue
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.unlink(tmp_path)
                except OSError:
                    pass

    return findings