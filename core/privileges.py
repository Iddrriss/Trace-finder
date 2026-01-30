"""
TraceFinder - Privilege Management Module
core/privileges.py

"""

import ctypes


def check_admin_privileges():
    """
    Check if the script is running with Administrator privileges.
    
    Administrator rights are essential for accessing:
    - HKEY_LOCAL_MACHINE registry hives
    - Prefetch directory (C:\\Windows\\Prefetch)
    - Protected system artifacts
    
    Returns:
        bool: True if running as Administrator, False otherwise.
    
    Raises:
        OSError: If privilege check fails on non-Windows systems.
    """
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        raise OSError("TraceFinder requires Windows operating system")