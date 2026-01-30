"""
TraceFinder - Hardware Activity Collectors
collectors/hardware.py-Devices connected

"""

import winreg
import struct
from core.time_window import filetime_to_datetime


def parse_usb_devices(triage_window):
    """
    Parse USB device connection history from registry.
    
    Args:
        triage_window (TriageWindow): Time window for filtering.
    
    Returns:
        list: List of dictionaries with standardized finding format.
    """
    findings = []
    base_path = r'SYSTEM\CurrentControlSet\Enum\USBSTOR'
    
    try:
        usbstor_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            base_path,
            0,
            winreg.KEY_READ
        )
        
        device_index = 0
        while True:
            try:
                device_id = winreg.EnumKey(usbstor_key, device_index)
                device_path = f"{base_path}\\{device_id}"
                
                device_key = winreg.OpenKey(
                    winreg.HKEY_LOCAL_MACHINE,
                    device_path,
                    0,
                    winreg.KEY_READ
                )
                
                instance_index = 0
                while True:
                    try:
                        instance_id = winreg.EnumKey(device_key, instance_index)
                        instance_path = f"{device_path}\\{instance_id}"
                        
                        instance_key = winreg.OpenKey(
                            winreg.HKEY_LOCAL_MACHINE,
                            instance_path,
                            0,
                            winreg.KEY_READ
                        )
                        
                        friendly_name = "Unknown Device"
                        try:
                            friendly_name, _ = winreg.QueryValueEx(
                                instance_key,
                                'FriendlyName'
                            )
                        except FileNotFoundError:
                            try:
                                friendly_name, _ = winreg.QueryValueEx(
                                    instance_key,
                                    'DeviceDesc'
                                )
                            except FileNotFoundError:
                                pass
                        
                        install_time = get_device_install_time(instance_path)
                        
                        if install_time and triage_window.is_within_window(install_time):
                            findings.append({
                                'timestamp': install_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
                                'timestamp_dt': install_time,
                                'artifact_type': 'Hardware',
                                'source': 'USB Device',
                                'description': friendly_name,
                                'details': f"Instance: {instance_id}"
                            })
                        
                        winreg.CloseKey(instance_key)
                        instance_index += 1
                    
                    except OSError:
                        break
                
                winreg.CloseKey(device_key)
                device_index += 1
            
            except OSError:
                break
        
        winreg.CloseKey(usbstor_key)
    
    except (FileNotFoundError, PermissionError, Exception):
        pass
    
    return findings


def get_device_install_time(instance_path):
    """
    Extract device installation timestamp from registry Properties.
    
    Args:
        instance_path (str): Registry path to device instance.
    
    Returns:
        datetime: Installation timestamp, or None if not found.
    """
    property_guid = '{83da6326-97a6-4088-9453-a1923f573b29}'
    first_install_key = '0065'
    
    properties_path = f"{instance_path}\\Properties\\{property_guid}\\{first_install_key}"
    
    try:
        prop_key = winreg.OpenKey(
            winreg.HKEY_LOCAL_MACHINE,
            properties_path,
            0,
            winreg.KEY_READ
        )
        
        data, reg_type = winreg.QueryValueEx(prop_key, '')
        winreg.CloseKey(prop_key)
        
        if isinstance(data, bytes) and len(data) >= 8:
            filetime = struct.unpack('<Q', data[:8])[0]
            return filetime_to_datetime(filetime)
    
    except (FileNotFoundError, PermissionError, OSError):
        pass
    
    return None