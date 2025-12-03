

import logging
logger = logging.getLogger(__name__)
from .helper import timestamp_to_human_readable

from config.constants import (
    FILE_ACTION_RENAMED_OLD_NAME,
    FILE_ACTION_RENAMED_NEW_NAME,
    FILE_ACTION_ADDED,
    FILE_ACTION_REMOVED,
    FILE_ACTION_MODIFIED
)


def print_total_file_actions(total_file_actions):
    """
    Process and display file system actions captured from SMB traffic.
    
    Handles special case of renames, which come as two separate events:
    - FILE_ACTION_RENAMED_OLD_NAME (old filename)
    - FILE_ACTION_RENAMED_NEW_NAME (new filename)
    These must be paired together to show the complete rename operation.
    
    Args:
        total_file_actions: List of tuples containing (timestamp, action_type, filename)
    """
    old_tmp = ""
    old_ts = ""
    for file_action in total_file_actions:
        ts = timestamp_to_human_readable(file_action[0])
        if file_action[1] == FILE_ACTION_RENAMED_OLD_NAME:
            old_tmp = file_action[2]
            old_ts = ts
        elif file_action[1] == FILE_ACTION_RENAMED_NEW_NAME:
            if ts != old_ts:
                logger.debug("Error in renaming actions")
                continue
            logger.debug_purple(f"[{ts}] rename of file {old_tmp} -> {file_action[2]}")
        elif file_action[1] == FILE_ACTION_ADDED:
            logger.debug_purple(f"[{ts}] added file {file_action[2]}")
        elif file_action[1] == FILE_ACTION_REMOVED:
            logger.debug_purple(f"[{ts}] removed file {file_action[2]}")
        elif file_action[1] == FILE_ACTION_MODIFIED:
            logger.debug_purple(f"[{ts}] modification of file {file_action[2]}")