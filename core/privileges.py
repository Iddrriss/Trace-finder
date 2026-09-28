"""Windows privilege detection utility."""

import ctypes


def check_admin_privileges():
    """Return True if running with Administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except AttributeError:
        raise OSError("TraceFinder requires Windows operating system")