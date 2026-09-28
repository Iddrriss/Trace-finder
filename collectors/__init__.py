"""TraceFinder Collectors Package."""

from collectors.execution import parse_userassist, parse_prefetch
from collectors.files import parse_recent_files, parse_recentdocs
from collectors.hardware import parse_usb_devices
from collectors.commands import parse_powershell_history, parse_runmru
from collectors.network import parse_browser_history, parse_downloads
from collectors.registry import parse_typed_paths
from collectors.events import parse_event_logs

__all__ = [
    'parse_userassist',
    'parse_prefetch',
    'parse_recent_files',
    'parse_recentdocs',
    'parse_usb_devices',
    'parse_powershell_history',
    'parse_runmru',
    'parse_browser_history',
    'parse_downloads',
    'parse_typed_paths',
    'parse_event_logs',
]
