"""Triage time window management and Windows FILETIME conversion."""

from datetime import datetime, timedelta, timezone


class TriageWindow:
    """Manages the time window for filtering forensic artifacts."""

    def __init__(self, window_minutes=180):
        self.window_minutes = window_minutes
        self.current_time = datetime.now(timezone.utc)
        self.cutoff_time = self.current_time - timedelta(minutes=self.window_minutes)

    def is_within_window(self, timestamp):
        """Check if a timestamp falls within the triage window."""
        if timestamp is None:
            return False

        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)

        return self.cutoff_time <= timestamp <= self.current_time

    def get_window_info(self):
        """Return human-readable metadata about the active time window."""
        return {
            'window_minutes': self.window_minutes,
            'current_time': self.current_time.isoformat(),
            'cutoff_time': self.cutoff_time.isoformat(),
            'window_start': self.cutoff_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
            'window_end': self.current_time.strftime('%Y-%m-%d %H:%M:%S UTC'),
        }


def filetime_to_datetime(filetime):
    """Convert Windows 64-bit FILETIME (100-ns intervals since 1601-01-01) to UTC datetime."""
    epoch = datetime(1601, 1, 1, tzinfo=timezone.utc)
    ticks_per_second = 10_000_000

    try:
        if not filetime or filetime <= 0:
            return None
        return epoch + timedelta(seconds=filetime / ticks_per_second)
    except (ValueError, OverflowError, TypeError):
        return None