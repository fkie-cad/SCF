import re

def normalize_path(path):
    """
    Normalize path separators for consistent display.
    Converts Windows-style paths to Unix-style while preserving UNC prefixes.
    """
    if not path:
        return path
    
    # Replace all backslashes with forward slashes
    normalized = path.replace('\\', '/')
    
    # Handle UNC paths (//server/share) - ensure double slash at start
    if normalized.startswith('//'):
        # Remove extra leading slashes and ensure exactly two
        normalized = '//' + normalized.lstrip('/')
    
    # Remove any duplicate slashes in the middle of the path
    normalized = re.sub(r'/+', '/', normalized)
    
    # Fix UNC prefix if it got mangled
    if path.startswith(('\\\\', '//')):
        if not normalized.startswith('//'):
            normalized = '//' + normalized.lstrip('/')
    
    return normalized