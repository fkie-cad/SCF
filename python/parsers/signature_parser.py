import logging
from colorama import Fore, Style
from utils.path_utils import normalize_path
from models.commands import CompSMBCommand


def unwrap_compound_commands(data):
    new_data = []

    for command in data:
        if isinstance(command, CompSMBCommand):
            new_data.extend(command.commands)
        else:
            new_data.append(command)    
    return new_data




def signature_parsing_cmd_cd(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"Changed directory (cd) to {colored_filename}"
    return "Changed directory (cd)"
def signature_parsing_cmd_dir(data):
    # First pass: try to find a filename that is NOT a share root or wildcard
    # Share roots end with a trailing slash after the share name (e.g., //server/share/)
    # Wildcards are patterns like "*" from QUERY_DIRECTORY commands
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            # Skip if this is a share root (ends with single trailing slash)
            # Pattern: //server/share/ should be skipped
            if filename.endswith('/') and filename.count('/') == 4:
                continue
            # Skip wildcard patterns (*, *.*, etc.)
            if '*' in filename or '?' in filename:
                continue
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Listing contents of directory {colored_filename}"

    # Second pass: if we only found share roots/wildcards, use share roots (fallback)
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            # Skip wildcards in fallback too
            if '*' in filename or '?' in filename:
                continue
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Listing contents of directory {colored_filename}"

    return "[cmd] Listing contents of directory"

def signature_parsing_cmd_dir_compound(data):
    # First pass: try to find a filename that is NOT a share root or wildcard
    # Share roots end with a trailing slash after the share name (e.g., //server/share/)
    # Wildcards are patterns like "*" from QUERY_DIRECTORY commands
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            # Skip if this is a share root (ends with single trailing slash)
            # Pattern: //server/share/ should be skipped
            if filename.endswith('/') and filename.count('/') == 4:
                continue
            # Skip wildcard patterns (*, *.*, etc.)
            if '*' in filename or '?' in filename:
                continue
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Listing of directory {colored_filename}"

    # Second pass: if we only found share roots/wildcards, use share roots (fallback)
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            # Skip wildcards in fallback too
            if '*' in filename or '?' in filename:
                continue
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Listing of directory {colored_filename}"

    return "[cmd] Listing of directory"

def signature_parsing_cmd_mkdir(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Creation of directory {colored_filename}"
    return "[cmd] Creation of directory"

def signature_parsing_cmd_mkdir_failed(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Failed creation of directory {colored_filename}"
    return "[cmd] Failed creation of directory"

def signature_parsing_cmd_del(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Deletion of file {colored_filename}"
    return "[cmd] Deletion of file"

def signature_parsing_cmd_more(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] View file {colored_filename}{Fore.BLUE}" #using more
    return "[cmd] View file"

def signature_parsing_cmd_rename(data):
    original_filename = None
    new_filename = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and original_filename == None and command.get_hash() == "d9a14ea22b152bd1770409a56db5ffad":
            original_filename = normalize_path(command.get_filename())
        
        if command.get_command() == "SET INFO" and new_filename == None:
            data = command.get_data()
            new_filename = data.FileName
            new_filename = normalize_path(new_filename.split("//")[-1])
    
    if original_filename and new_filename:
        colored_new_filename = f"{Fore.GREEN}{new_filename}{Style.RESET_ALL}"
        colored_filename = f"{Fore.RED}{original_filename}{Style.RESET_ALL}"

        return f"[cmd] Rename of file {colored_filename} -> {colored_new_filename}"
    return "[cmd] Rename of file"

def signature_parsing_ps_rename_file(data):
    original_filename = None
    new_filename = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and original_filename == None:
            original_filename = normalize_path(command.get_filename())
        
        if command.get_command() == "SET INFO" and new_filename == None:
            data = command.get_data()
            new_filename = data.FileName
            new_filename = normalize_path(new_filename.split("//")[-1])
    
    if original_filename and new_filename:
        colored_new_filename = f"{Fore.GREEN}{new_filename}{Style.RESET_ALL}"
        colored_filename = f"{Fore.RED}{original_filename}{Style.RESET_ALL}"

        return f"[ps] Rename of file {colored_filename} -> {colored_new_filename}"
    return "[ps] Rename of file"

def signature_parsing_ps_move_directory(data):
    old_dir_path = None
    new_dir_path = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and old_dir_path == None and command.get_hash() == "d9a14ea22b152bd1770409a56db5ffad":
            old_dir_path = normalize_path(command.get_filename())
            continue

        if command.get_command() == "SET INFO" and new_dir_path == None:
            data = command.get_data()
            new_dir_path = data.FileName
            share_path = command.get_share_path()
            # Normalize both paths before joining
            if share_path:    
                share_path = normalize_path(share_path)
                new_dir_path = normalize_path(new_dir_path)
                new_dir_path = share_path + '/' + new_dir_path
            else: 
                new_dir_path = normalize_path(new_dir_path)

    if old_dir_path and new_dir_path:
        old_base_path = '/'.join(old_dir_path.split('/')[:-1])
        new_base_path = '/'.join(new_dir_path.split('/')[:-1])

        if old_base_path == new_base_path:
            new_dir_name = new_dir_path.split('/')[-1]
            colored_new_file_path= f"{Fore.GREEN}{new_dir_name}{Style.RESET_ALL}"
        else:
            colored_new_file_path= f"{Fore.GREEN}{new_dir_path}{Style.RESET_ALL}"

        colored_file_path = f"{Fore.RED}{old_dir_path}{Style.RESET_ALL}"

        return f"[ps] Moved directory {colored_file_path} to {colored_new_file_path}"
    return "[ps] Moved directory"

def signature_parsing_ps_move_file_on_server(data):
    file_path = None
    new_file_path = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and file_path == None and command.get_hash() == "d9a14ea22b152bd1770409a56db5ffad":
            file_path = normalize_path(command.get_filename())
            continue

        if command.get_command() == "SET INFO" and new_file_path == None:
            data = command.get_data()
            new_file_path = data.FileName
            share_path = command.get_share_path()
            # Normalize both paths before joining
            share_path = normalize_path(share_path)
            new_file_path = normalize_path(new_file_path)
            if share_path:
                new_file_path = share_path + '/' + new_file_path

    if file_path and new_file_path:
        old_base_path = '/'.join(file_path.split('/')[:-1])
        new_base_path = '/'.join(new_file_path.split('/')[:-1])

        if old_base_path == new_base_path:
            new_file_name = new_file_path.split('/')[-1]
            colored_new_file_path= f"{Fore.GREEN}{new_file_name}{Style.RESET_ALL}"
        else:
            colored_new_file_path= f"{Fore.GREEN}{new_file_path}{Style.RESET_ALL}"

        colored_file_path = f"{Fore.RED}{file_path}{Style.RESET_ALL}"

        return f"[ps] Moved file {colored_file_path} to {colored_new_file_path}"
    return "[ps] Moved file"

def signature_parsing_cmd_move_directory(data):
    old_dir_path = None
    new_dir_path = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and old_dir_path == None and command.get_hash() == "d9a14ea22b152bd1770409a56db5ffad":
            old_dir_path = normalize_path(command.get_filename())
            continue

        if command.get_command() == "SET INFO" and new_dir_path == None:
            data = command.get_data()
            new_dir_path = data.FileName
            share_path = command.get_share_path()
            # Normalize both paths before joining
            new_dir_path = normalize_path(new_dir_path)
            if share_path:
                share_path = normalize_path(share_path)
                new_dir_path = share_path + '/' + new_dir_path

    if old_dir_path and new_dir_path:
        old_base_path = '/'.join(old_dir_path.split('/')[:-1])
        new_base_path = '/'.join(new_dir_path.split('/')[:-1])

        if old_base_path == new_base_path:
            new_dir_name = new_dir_path.split('/')[-1]
            colored_new_file_path= f"{Fore.GREEN}{new_dir_name}{Style.RESET_ALL}"
        else:
            colored_new_file_path= f"{Fore.GREEN}{new_dir_path}{Style.RESET_ALL}"

        colored_file_path = f"{Fore.RED}{old_dir_path}{Style.RESET_ALL}"

        return f"[cmd] Moved directory {colored_file_path} to {colored_new_file_path}"
    return "[cmd] Moved directory"
    
def signature_parsing_cmd_change_permissions(data):
    original_permissions = None
    new_permissions = None

    data = unwrap_compound_commands(data)

    first_command = data[0]
    original_filename = normalize_path(first_command.get_filename()) if first_command.get_filename() else None
    
    for command in reversed(data):
        pass
        
    if original_filename:        
        return f"[cmd | ps] Changed permissions of file {Fore.RED}{original_filename}{Style.RESET_ALL}"
    else:
        return "[cmd | ps] Changed permissions"
    
def signature_parsing_ps_change_permissions(data):
    original_permissions = None
    new_permissions = None

    data = unwrap_compound_commands(data)

    first_command = data[0]
    original_filename = normalize_path(first_command.get_filename()) if first_command.get_filename() else None
    
    for command in reversed(data):
        pass
        
    if original_filename:        
        return f"[ps] Changed permissions of file {Fore.RED}{original_filename}{Style.RESET_ALL}"
    else:
        return "[ps] Changed permissions"

def signature_parsing_ps_getcontent(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] View file {colored_filename}{Fore.BLUE}" #using more
    return "[ps] View file"

def signature_parsing_ps_del(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Deletion of file {colored_filename}"
    return "[ps] Deletion of file"

def signature_parsing_ps_echo_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Creation of file {colored_filename}"
    return "[ps] Creation of file"

def signature_parsing_ps_echo_file_append(data):
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Appending to file {colored_filename}"
    return "[ps] Appending to file"

def signature_parsing_ps_dir(data):
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and command.get_hash() == "e128601506b19689cfea77f8e57fa33d":
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Listing contents of directory {colored_filename}"
    return "[ps] Listing contents of directory"

def signature_parsing_ps_dir_old(data):
    first_path = None
    second_path = None

    first_command = data[0]
    first_path = normalize_path(first_command.get_filename()) if first_command.get_filename() else None
    
    for command in reversed(data):
        if command.get_filename() != None and not second_path and command.get_command() == "CREATE":
            second_path = normalize_path(command.get_filename())
            
    if first_path and second_path:
        if first_path == second_path:
            #assuming it was a listing
            colored_filename = f"{Fore.RED}{first_path}{Style.RESET_ALL}"
            return f"[ps] Listing contents of directory {colored_filename}"
        else:
            #assuming it was a change of directories
            colored_filename = f"{Fore.RED}{first_path}{Style.RESET_ALL}"
            return f"[ps] Changed to {colored_filename} {Fore.BLUE}from {Fore.RED}{second_path}{Style.RESET_ALL}"
    else:
        return "[ps] Listing or change of directory"

def signature_parsing_ps_dir_compound(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Listing of directory {colored_filename}"
    return "[ps] Listing of directory"

def signature_parsing_ps_rename(data):
    original_filename = None
    new_filename = None
    lookup_filename = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and original_filename == None and command.get_hash() == "d9a14ea22b152bd1770409a56db5ffad":
            original_filename = normalize_path(command.get_filename())

        if command.get_filename() != None and lookup_filename == None and command.get_hash() == "3df084742fb18607089dd93e01da07bb":
            lookup_filename = normalize_path(command.get_filename())
        
        if command.get_command() == "SET INFO" and new_filename == None:
            data = command.get_data()
            new_filename = data.FileName
            new_filename = normalize_path(new_filename.split("//")[-1])
    
    if lookup_filename != original_filename:
        logging.debug("LOOKUP FILE NAME MISMATCH")
        return None
    
    if original_filename and new_filename:
        colored_new_filename = f"{Fore.GREEN}{new_filename}{Style.RESET_ALL}"
        colored_filename = f"{Fore.RED}{original_filename}{Style.RESET_ALL}"

        return f"[ps] Rename of file {colored_filename} -> {colored_new_filename}"
    return "[ps] Rename of file"

def signature_parsing_ps_mkdir(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Creation of directory {colored_filename}"
    return "[ps] Creation of directory"

def signature_parsing_ps_rmdir(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Deletion of directory {colored_filename}"
    return "[ps] Deletion of directory"

def signature_parsing_cmd_move_file_on_server(data):
    file_path = None
    new_file_path = None
    
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None and file_path == None and command.get_hash() == "d9a14ea22b152bd1770409a56db5ffad":
            file_path = normalize_path(command.get_filename())
            continue

        if command.get_command() == "SET INFO" and new_file_path == None:
            data = command.get_data()
            new_file_path = data.FileName
            share_path = command.get_share_path()
            # Normalize both paths before joining
            share_path = normalize_path(share_path)
            new_file_path = normalize_path(new_file_path)
            if share_path:
                new_file_path = share_path + '/' + new_file_path

    if file_path and new_file_path:
        old_base_path = '/'.join(file_path.split('/')[:-1])
        new_base_path = '/'.join(new_file_path.split('/')[:-1])

        if old_base_path == new_base_path:
            new_file_name = new_file_path.split('/')[-1]
            colored_new_file_path= f"{Fore.GREEN}{new_file_name}{Style.RESET_ALL}"
        else:
            colored_new_file_path= f"{Fore.GREEN}{new_file_path}{Style.RESET_ALL}"

        colored_file_path = f"{Fore.RED}{file_path}{Style.RESET_ALL}"

        return f"[cmd] Moved file {colored_file_path} to {colored_new_file_path}"
    return "[cmd] Moved file"

def signature_parsing_cmd_copy(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Copied file to server {colored_filename}"
    return "[cmd] Copied file to server"

def signature_parsing_cmd_copy_from(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Copied file from server {colored_filename}"
    return "[cmd] Copied file from server"

def signature_parsing_ps_copy(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Copied file to server {colored_filename}"
    return "[ps] Copied file to server"

def signature_parsing_ps_copy_from(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[ps] Copied file from server {colored_filename}"
    return "[ps] Copied file from server"

def signature_parsing_cmd_rmdir(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Deletion of directory {colored_filename}"
    return "[cmd] Deletion of directory"

def signature_parsing_cmd_rmdir_failed(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Failed deletion of directory: {colored_filename}"
    return "[cmd] Failed deletion of directory"

def signature_parsing_cmd_echo_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Creation of file {colored_filename}"
    return "[cmd] Creation of file"

def signature_parsing_cmd_echo_file_append(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[cmd] Appending to file {colored_filename}"
    return "[cmd] Appending to file"

def signature_parsing_smbclient_cd(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Changed directory to {colored_filename}"
    return "Changed directory"

def signature_parsing_smbclient_ls(data):
    query_pattern = None
    first_path= None
    second_path = None
    for command in data:
        if command.get_command() == "QUERY DIRECTORY" and not query_pattern:
            query_pattern = command.get_filename()
        elif command.get_command() != "QUERY DIRECTORY" and command.get_filename() != None:
            if not first_path:
                first_path = normalize_path(command.get_filename())
            elif not second_path:
                second_path = normalize_path(command.get_filename())
    
    if query_pattern == "*":
        colored_filename = f"{Fore.RED}{first_path}{Style.RESET_ALL}"
        return f"[smbclient] Listing contents of directory {colored_filename}{Fore.BLUE}"
    elif query_pattern:
        # Normalize the joined path
        joined_path = normalize_path(first_path + '/' + query_pattern)
        colored_filename = f"{Fore.RED}{joined_path}{Style.RESET_ALL}"
        return f"[smbclient] Listing contents of directory {colored_filename}"
    else:
        return "[smbclient] Listing contents of directory"

def signature_parsing_smbclient_mkdir(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Creation of directory {colored_filename}"
    return "[smbclient] Creation of directory"

def signature_parsing_smbclient_mkdir_failed(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Failed creating directory {colored_filename}"
    return "[smbclient] Failed creating directory"

def signature_parsing_smbclient_rmdir(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Deletion of directory {colored_filename}"
    return "[smbclient] Deletion of directory"

def signature_parsing_smbclient_rmdir_failed(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Deletion of directory failed {colored_filename}"
    return "[smbclient] Deletion of directory failed"

def signature_parsing_smbclient_get(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Read file {colored_filename}"
    return "[smbclient] Read file"

def signature_parsing_smbclient_put(data):
    for command in data:
        if command.get_filename() != None:
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Copied file to server {colored_filename}"
    return "[smbclient] Copied file to server"

def signature_parsing_smbclient_move_file_or_directory_on_server(data):
    logging.debug("\n--- DEBUGGING A MATCHED SEQUENCE ---")
    for i, command in enumerate(data):
        logging.debug(f"  Command #{i}: {command}")
        if hasattr(command, 'get_data'):
             logging.debug(f"    Payload: {command.get_data()}")
    logging.debug("------------------------------------\n")
    file_path = None
    new_file_path = None

    for command in data:
        if command.get_filename() != None and file_path is None:
            file_path = normalize_path(command.get_filename())
        
        if command.get_command() == "SET INFO" and new_file_path == None:
            rename_info = command.get_data()

            # The data is already a Scapy-parsed FileRenameInformation object
            if rename_info and hasattr(rename_info, 'FileName'):
                # FileName is already decoded in the Scapy object
                new_file_path = rename_info.FileName.decode('utf-16le') if isinstance(rename_info.FileName, bytes) else rename_info.FileName
            else:
                logging.debug(f"Warning: SET INFO command has no FileName field")
                continue

            share_path = command.get_share_path()
            # Normalize both paths before joining
            share_path = normalize_path(share_path)
            new_file_path = normalize_path(new_file_path)
            if share_path:
                new_file_path = share_path + '/' + new_file_path
    
    if file_path and new_file_path:
        old_base_path = '/'.join(file_path.split('/')[:-1])
        new_base_path = '/'.join(new_file_path.split('/')[:-1])

        if old_base_path == new_base_path:
            new_file_name = new_file_path.split('/')[-1]
            colored_new_file_path= f"{Fore.GREEN}{new_file_name}{Style.RESET_ALL}"
        else:
            colored_new_file_path= f"{Fore.GREEN}{new_file_path}{Style.RESET_ALL}"

        colored_file_path = f"{Fore.RED}{file_path}{Style.RESET_ALL}"
        return f"[smbclient] Moved file or directory {colored_file_path} to {colored_new_file_path}"
    
    return "[smbclient] Moved file or directory"

def signature_parsing_smbclient_rm(data):
    for command in data:
        if command.get_filename() != None and command.get_hash() == "6b19b2a13a13f65a52652783caf5bc8e":
            filename = normalize_path(command.get_filename())
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[smbclient] Deletion of file {colored_filename}"
    return "[smbclient] Deletion of file"

def signature_parsing_cifs_terminal_more(data):
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"Reading file {colored_filename} {Fore.BLUE}using more"
    return "Reading file using more"

def signature_parsing_gedit_open(data):
    data = unwrap_compound_commands(data)

    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            if filename == "/":
                filename = None
                continue
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"Opening file {colored_filename} {Fore.BLUE}using gedit"
    return "Opening file using gedit"

def signature_parsing_explorer_mkdir(data):
    initial_name = None
    name = None

    for command in data:
        if command.get_filename() != None and initial_name == None:
            initial_name = command.get_filename()
            colored_initial_name = f"{Fore.RED}{initial_name}{Style.RESET_ALL}"
    
    for command in reversed(data):
        if command.get_filename() != None and name == None:
            name = command.get_filename()
            colored_name = f"{Fore.RED}{name}{Style.RESET_ALL}"
            return f"[explorer] Creation of directory: {colored_initial_name} -> {colored_name}"

    return "[explorer] Creation of directory"

def signature_parsing_explorer_delete_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[explorer] Secure deletion of file {colored_filename}"
    return "[explorer] Secure deletion of file"    

def signature_parsing_explorer_copy_from(data):
    for command in reversed(data):
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[explorer] Copying of file from server {colored_filename}"
    return "[explorer] Copying of file from server"

def signature_parsing_editor_open_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[editor] Opened file {colored_filename}"
    return "[editor] Opened file"

def signature_parsing_paint_open_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[paint] Opened file {colored_filename}"
    return "[paint] Opened file"

def signature_parsing_paint_save_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[paint] Saved file {colored_filename}"
    return "[paint] Saved file"

def signature_parsing_editor_save_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[editor] Saved file {colored_filename}"
    return "[editor] Saved file"

def signature_parsing_wordpad_open_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[wordpad] Opened file {colored_filename}"
    return "[wordpad] Opened file"

def signature_parsing_wordpad_save_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[wordpad] Saved file {colored_filename}"
    return "[wordpad] Saved file"

def signature_parsing_edge_open_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[edge] Opened file {colored_filename}"
    return "[edge] Opened file"

def signature_parsing_snipping_open_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[snipping-tool] Opened file {colored_filename}"
    return "[snipping-tool] Opened file"


def signature_parsing_python_win_create_file(data):
    for command in data:
        if command.get_filename() != None:
            filename = command.get_filename()
            colored_filename = f"{Fore.RED}{filename}{Style.RESET_ALL}"
            return f"[python] Creation of file {colored_filename}" #TODO: remove the echo part
    return "[python] Creation of file"
