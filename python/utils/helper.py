from datetime import datetime
import os



def timestamp_to_human_readable(timestamp):
    """
    Convert a Unix timestamp (with fractional seconds) to a human-readable string.
    
    Formats the timestamp as: YYYY-MM-DD HH:MM:SS.mmm
    where mmm represents milliseconds with 3-digit precision.
    
    Args:
        timestamp: Unix timestamp (seconds since epoch), can include fractional seconds
        
    Returns:
        Formatted string with date, time, and milliseconds (e.g., "2025-11-14 15:30:45.123")
    """
    timestamp_float = float(timestamp)
    dt = datetime.fromtimestamp(timestamp_float)
    milliseconds = int((timestamp_float - int(timestamp_float)) * 1000)
    return dt.strftime('%Y-%m-%d %H:%M:%S') + f".{milliseconds:03d}"
