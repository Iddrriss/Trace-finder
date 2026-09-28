"""
TraceFinder - Windows Event Log Collectors
collectors/events.py

Author: Oxseeker
Compliance: PEP8
Description:
    Forensic collectors for Windows Event Logs using built-in Windows
    wevtutil utility and pure standard library XML parsing.
    Captures Service Installations, System Shutdowns/Reboots, Process
    Creations, Authentication Events, and PowerShell ScriptBlock Executions.
"""

import subprocess
import xml.etree.ElementTree as ET
import re
from datetime import datetime, timezone


def parse_iso_systemtime(time_str):
    """
    Parse Windows Event SystemTime string (e.g. '2026-09-28T08:27:37.0237183Z')
    into a timezone-aware UTC datetime.
    
    Args:
        time_str (str): Raw timestamp from Event XML.
        
    Returns:
        datetime: UTC-aware datetime or None if parsing fails.
    """
    if not time_str:
        return None
    try:
        # Standardize fractional seconds to microseconds and 'Z' to '+00:00'
        # Example: 2026-09-28T08:27:37.0237183Z -> 2026-09-28T08:27:37.023718+00:00
        normalized = re.sub(r'(\.\d{1,6})\d*Z$', r'\1+00:00', time_str)
        if normalized.endswith('Z'):
            normalized = normalized[:-1] + '+00:00'
        elif not normalized.endswith('+00:00') and '+' not in normalized and '-' not in normalized[-6:]:
            normalized += '+00:00'
        
        return datetime.fromisoformat(normalized)
    except Exception:
        try:
            # Fallback parse for YYYY-MM-DDTHH:MM:SS
            base = time_str.split('.')[0]
            dt = datetime.strptime(base, '%Y-%m-%dT%H:%M:%S')
            return dt.replace(tzinfo=timezone.utc)
        except Exception:
            return None


def execute_event_query(channel, xpath_query, max_count=250):
    """
    Query Windows Event Log via wevtutil and return root XML element.
    
    Args:
        channel (str): Event log channel name (e.g. 'System', 'Security').
        xpath_query (str): XPath filter for events.
        max_count (int): Maximum number of recent events to retrieve.
        
    Returns:
        list of xml.etree.ElementTree.Element: List of Event XML elements.
    """
    events = []
    cmd = [
        'wevtutil.exe',
        'qe',
        channel,
        f'/q:{xpath_query}',
        f'/c:{max_count}',
        '/rd:true',  # Most recent first
        '/f:xml'
    ]
    
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=15,
            encoding='utf-8',
            errors='ignore'
        )
        
        if proc.returncode != 0 or not proc.stdout.strip():
            return events
        
        # wevtutil outputs multiple <Event> XML fragments without a single root
        wrapped_xml = f"<Events>{proc.stdout}</Events>"
        root = ET.fromstring(wrapped_xml)
        ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
        
        for event_elem in root.findall('ns:Event', ns):
            events.append(event_elem)
            
    except (subprocess.TimeoutExpired, subprocess.SubprocessError, ET.ParseError, OSError):
        pass
    
    return events


def extract_event_fields(event_elem):
    """
    Extract standard fields and EventData dictionary from an Event XML element.
    
    Args:
        event_elem (Element): The XML Element for <Event>.
        
    Returns:
        dict: Standardized event details.
    """
    ns = {'ns': 'http://schemas.microsoft.com/win/2004/08/events/event'}
    
    system = event_elem.find('ns:System', ns)
    if system is None:
        return None
    
    event_id_elem = system.find('ns:EventID', ns)
    event_id = int(event_id_elem.text) if event_id_elem is not None and event_id_elem.text else 0
    
    time_created = system.find('ns:TimeCreated', ns)
    time_str = time_created.get('SystemTime') if time_created is not None else None
    timestamp_dt = parse_iso_systemtime(time_str)
    
    provider_elem = system.find('ns:Provider', ns)
    provider = provider_elem.get('Name') if provider_elem is not None else 'Unknown'
    
    channel_elem = system.find('ns:Channel', ns)
    channel = channel_elem.text if channel_elem is not None else 'Unknown'
    
    # Extract EventData key-value pairs
    data_dict = {}
    data_list = []
    event_data = event_elem.find('ns:EventData', ns)
    if event_data is not None:
        for data in event_data.findall('ns:Data', ns):
            name = data.get('Name')
            val = data.text or ''
            if name:
                data_dict[name] = val
            data_list.append(val)
    
    return {
        'event_id': event_id,
        'timestamp_dt': timestamp_dt,
        'provider': provider,
        'channel': channel,
        'data_dict': data_dict,
        'data_list': data_list
    }


def parse_event_logs(triage_window):
    """
    Collect high-value forensic events from System, Security, and PowerShell logs.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
        
    Returns:
        list: Standardized finding dictionaries.
    """
    findings = []
    
    # 1. System Channel Query: Services (7045, 7040), Reboots (1074), Up/Down (6005, 6006), Cleared (104)
    system_xpath = "*[System[(EventID=7045 or EventID=7040 or EventID=1074 or EventID=6005 or EventID=6006 or EventID=104)]]"
    system_events = execute_event_query('System', system_xpath, max_count=200)
    
    for event_elem in system_events:
        ev = extract_event_fields(event_elem)
        if not ev or not ev['timestamp_dt']:
            continue
        
        # Stop early if events are older than the window (since output is sorted newest-first)
        if ev['timestamp_dt'] < triage_window.cutoff_time:
            break
        
        if not triage_window.is_within_window(ev['timestamp_dt']):
            continue
        
        dt_str = ev['timestamp_dt'].strftime('%Y-%m-%d %H:%M:%S UTC')
        eid = ev['event_id']
        data = ev['data_dict']
        
        if eid == 7045:
            svc_name = data.get('ServiceName', 'Unknown Service')
            img_path = data.get('ImagePath', 'N/A')
            svc_type = data.get('ServiceType', 'N/A')
            acct = data.get('AccountName', 'N/A')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'System Event',
                'source': 'EventLog: System (7045)',
                'description': f"New Service Installed: {svc_name}",
                'details': f"Image: {img_path} | Type: {svc_type} | Account: {acct}"
            })
        elif eid == 1074:
            action = data.get('param5', 'restart/power off')
            user = data.get('param7', 'Unknown User')
            proc = data.get('param1', 'Unknown Process')
            reason = data.get('param3', 'N/A')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'System Event',
                'source': 'EventLog: System (1074)',
                'description': f"System {action.capitalize()}",
                'details': f"User: {user} | Process: {proc} | Reason: {reason}"
            })
        elif eid == 6005:
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'System Event',
                'source': 'EventLog: System (6005)',
                'description': "System Startup (EventLog Service Started)",
                'details': "OS started up and event logging initiated"
            })
        elif eid == 6006:
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'System Event',
                'source': 'EventLog: System (6006)',
                'description': "System Shutdown (EventLog Service Stopped)",
                'details': "Clean OS shutdown initiated"
            })
        elif eid == 104:
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Anti-Forensics',
                'source': 'EventLog: System (104)',
                'description': "ALERT: System Event Log Cleared",
                'details': "System log was cleared (potential evidence destruction)"
            })
        elif eid == 7040:
            svc_name = data.get('param1', 'Unknown Service')
            start_type = data.get('param3', 'Unknown Type')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'System Event',
                'source': 'EventLog: System (7040)',
                'description': f"Service Start Type Changed: {svc_name}",
                'details': f"New Start Type: {start_type}"
            })
    
    # 2. Security Channel Query: Process Creation (4688), Logons (4624/4625), Accounts (4720/4726), Cleared (1102)
    security_xpath = "*[System[(EventID=4688 or EventID=4624 or EventID=4625 or EventID=4720 or EventID=4726 or EventID=1102)]]"
    security_events = execute_event_query('Security', security_xpath, max_count=200)
    
    for event_elem in security_events:
        ev = extract_event_fields(event_elem)
        if not ev or not ev['timestamp_dt']:
            continue
        
        if ev['timestamp_dt'] < triage_window.cutoff_time:
            break
        
        if not triage_window.is_within_window(ev['timestamp_dt']):
            continue
        
        dt_str = ev['timestamp_dt'].strftime('%Y-%m-%d %H:%M:%S UTC')
        eid = ev['event_id']
        data = ev['data_dict']
        
        if eid == 4688:
            proc_name = data.get('NewProcessName', 'Unknown Process')
            cmd_line = data.get('CommandLine', '')
            parent = data.get('ParentProcessName', 'Unknown Parent')
            user = data.get('TargetUserName') or data.get('SubjectUserName', 'N/A')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Execution',
                'source': 'EventLog: Security (4688)',
                'description': f"Process Created: {proc_name}",
                'details': f"CmdLine: {cmd_line[:120]} | Parent: {parent} | User: {user}"
            })
        elif eid == 4624:
            user = data.get('TargetUserName', 'Unknown')
            logon_type = data.get('LogonType', 'N/A')
            ip = data.get('IpAddress', '-')
            # Filter noisy computer accounts ending with $ if desired, or keep all
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Authentication',
                'source': 'EventLog: Security (4624)',
                'description': f"Successful Logon: {user}",
                'details': f"Logon Type: {logon_type} | Source IP: {ip}"
            })
        elif eid == 4625:
            user = data.get('TargetUserName', 'Unknown')
            status = data.get('Status', 'N/A')
            ip = data.get('IpAddress', '-')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Authentication',
                'source': 'EventLog: Security (4625)',
                'description': f"Failed Logon Attempt: {user}",
                'details': f"Status: {status} | Source IP: {ip}"
            })
        elif eid == 4720:
            user = data.get('TargetUserName', 'Unknown')
            actor = data.get('SubjectUserName', 'N/A')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Account Activity',
                'source': 'EventLog: Security (4720)',
                'description': f"User Account Created: {user}",
                'details': f"Created by: {actor}"
            })
        elif eid == 4726:
            user = data.get('TargetUserName', 'Unknown')
            actor = data.get('SubjectUserName', 'N/A')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Account Activity',
                'source': 'EventLog: Security (4726)',
                'description': f"User Account Deleted: {user}",
                'details': f"Deleted by: {actor}"
            })
        elif eid == 1102:
            actor = data.get('SubjectUserName', 'N/A')
            findings.append({
                'timestamp': dt_str,
                'timestamp_dt': ev['timestamp_dt'],
                'artifact_type': 'Anti-Forensics',
                'source': 'EventLog: Security (1102)',
                'description': "ALERT: Security Audit Log Cleared",
                'details': f"Cleared by user: {actor}"
            })
            
    # 3. PowerShell Operational Log: Script Block Execution (4104)
    ps_xpath = "*[System[(EventID=4104)]]"
    ps_events = execute_event_query('Microsoft-Windows-PowerShell/Operational', ps_xpath, max_count=100)
    
    for event_elem in ps_events:
        ev = extract_event_fields(event_elem)
        if not ev or not ev['timestamp_dt']:
            continue
        
        if ev['timestamp_dt'] < triage_window.cutoff_time:
            break
        
        if not triage_window.is_within_window(ev['timestamp_dt']):
            continue
        
        dt_str = ev['timestamp_dt'].strftime('%Y-%m-%d %H:%M:%S UTC')
        data = ev['data_dict']
        script_text = data.get('ScriptBlockText', '')
        # Clean newlines for single-line display
        cleaned_text = ' '.join(script_text.split())
        path = data.get('Path', '')
        
        findings.append({
            'timestamp': dt_str,
            'timestamp_dt': ev['timestamp_dt'],
            'artifact_type': 'Command Line',
            'source': 'EventLog: PowerShell (4104)',
            'description': "PowerShell ScriptBlock Execution",
            'details': f"Path: {path or 'Interactive/In-memory'} | Code: {cleaned_text[:120]}"
        })
    
    return findings
