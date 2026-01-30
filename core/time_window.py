"""
TraceFinder - Time Window Management Module
core/time_window.py

"""

from datetime import datetime, timedelta, timezone


class TriageWindow:
    """
    Manages the forensic triage time window for artifact filtering.
    
    The triage window defines the time range for collecting forensic artifacts.
    Default window is 180 minutes (3 hours) from current time.
    
    Attributes:
        window_minutes (int): Size of the triage window in minutes.
        current_time (datetime): Timestamp when the triage window was created.
        cutoff_time (datetime): Earliest timestamp for artifact inclusion.
    """
    
    def __init__(self, window_minutes=180):
        """
        Initialize the triage window.
        
        Args:
            window_minutes (int): Size of time window in minutes. Default is 180.
        """
        self.window_minutes = window_minutes
        self.current_time = datetime.now(timezone.utc)
        self.cutoff_time = self.current_time - timedelta(
            minutes=self.window_minutes
        )
    
    def is_within_window(self, timestamp):
        """
        Check if a given timestamp falls within the triage window.
        
        Args:
            timestamp (datetime): Timestamp to check (should be timezone-aware).
        
        Returns:
            bool: True if timestamp is within window, False otherwise.
        """
        if timestamp is None:
            return False
        
        # Ensure timestamp is timezone-aware for comparison
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        
        return self.cutoff_time <= timestamp <= self.current_time
    
    def get_window_info(self):
        """
        Get human-readable information about the triage window.
        
        Returns:
            dict: Dictionary containing window parameters and timestamps.
        """
        return {
            'window_minutes': self.window_minutes,
            'current_time': self.current_time.isoformat(),
            'cutoff_time': self.cutoff_time.isoformat(),
            'window_start': self.cutoff_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'window_end': self.current_time.strftime('%Y-%m-%d %H:%M:%S UTC')
        }


def filetime_to_datetime(filetime):
    """
    Convert Windows FILETIME (64-bit integer) to Python datetime object.
    
    Windows FILETIME represents the number of 100-nanosecond intervals
    since January 1, 1601 (UTC). This is commonly found in:
    - Registry timestamps (UserAssist, RecentDocs)
    - NTFS file system metadata
    - Windows event logs
    
    Args:
        filetime (int): 64-bit Windows FILETIME value.
    
    Returns:
        datetime: Python datetime object in UTC timezone.
        Returns None if conversion fails or filetime is invalid.
    """
    FILETIME_EPOCH = datetime(1601, 1, 1, tzinfo=timezone.utc)
    FILETIME_TICKS_PER_SECOND = 10000000
    
    try:
        if filetime is None or filetime == 0:
            return None
        
        seconds_since_epoch = filetime / FILETIME_TICKS_PER_SECOND
        timestamp = FILETIME_EPOCH + timedelta(seconds=seconds_since_epoch)
        
        return timestamp
    
    except (ValueError, OverflowError, TypeError):
        return None