import hashlib
import os
from colorama import Style, Fore                
from utils.formatting import timestamp_to_human_readable
from config.constants import (
    DISPOSITION_STRINGS,
    FileSystemInformationClasses
)
from config.constants import SMB_EXTRACTED_SHARES
from scapy.layers.smb2 import (
    FileInformationClasses,
    SMB2_INFO_TYPE,
    STATUS_ERREF
)


# Extend scapy's Statuserrors with missing values from Microsoft SMB2 specification

EXTENDED_STATUS_ERREF = STATUS_ERREF.copy()
EXTENDED_STATUS_ERREF.update({
    0xC0000101: "STATUS_DIRECTORY_NOT_EMPTY"
})

# Extend scapy's FileInformationClasses with missing values from Microsoft SMB2 specification
EXTENDED_FILE_INFO_CLASSES = FileInformationClasses.copy()
EXTENDED_FILE_INFO_CLASSES.update({
    8 : 'FileAccessInformation',
    17 : 'FileAlignmentInformation',
    18 : 'FileAllInformation',
    19 : 'FileAllocationInformation',
    21 : 'FileAlternateNameInformation',
    35 : 'FileAttributeTagInformation',
    4 : 'FileBasicInformation',
    3 : 'FileBothDirectoryInformation',
    28 : 'FileCompressionInformation',
    1 : 'FileDirectoryInformation',
    13 : 'FileDispositionInformation',
    64 : 'FileDispositionInformationEx',
    7 : 'FileEaInformation',
    20 : 'FileEndOfFileInformation',
    2 : 'FileFullDirectoryInformation',
    15 : 'FileFullEaInformation',
    46 : 'FileHardLinkInformation',
    79 : 'FileId64ExtdBothDirectoryInformation',
    78 : 'FileId64ExtdDirectoryInformation',
    81 : 'FileIdAllExtdBothDirectoryInformation',
    80 : 'FileIdAllExtdDirectoryInformation',
    37 : 'FileIdBothDirectoryInformation',
    60 : 'FileIdExtdDirectoryInformation',
    38 : 'FileIdFullDirectoryInformation',
    50 : 'FileIdGlobalTxDirectoryInformation',
    59 : 'FileIdInformation',
    6 : 'FileInternalInformation',
    11 : 'FileLinkInformation',
    26 : 'FileMailslotQueryInformation',
    27 : 'FileMailslotSetInformation',
    16 : 'FileModeInformation',
    31 : 'FileMoveClusterInformation',
    9 : 'FileNameInformation',
    12 : 'FileNamesInformation',
    34 : 'FileNetworkOpenInformation',
    48 : 'FileNormalizedNameInformation',
    29 : 'FileObjectIdInformation',
    23 : 'FilePipeInformation',
    24 : 'FilePipeLocalInformation',
    25 : 'FilePipeRemoteInformation',
    14 : 'FilePositionInformation',
    32 : 'FileQuotaInformation',
    10 : 'FileRenameInformation',
    65 : 'FileRenameInformationEx',
    33 : 'FileReparsePointInformation',
    44 : 'FileSfioReserveInformation',
    45 : 'FileSfioVolumeInformation',
    40 : 'FileShortNameInformation',
    5 : 'FileStandardInformation',
    54 : 'FileStandardLinkInformation',
    22 : 'FileStreamInformation',
    36 : 'FileTrackingInformation',
    39 : 'FileValidDataLengthInformation'
})

class SMBCommand:
    def __init__(self, timestamp, length, ip_src, packet_num=None):
        self.timestamp = timestamp
        self.length = length
        self.assigned = False
        self.ip_src = ip_src
        self.packet_num = packet_num

    def get_hash(self):
        return "not implemented"
    
    def is_assigned(self):
        return self.assigned
    
    def get_filename(self):
        return None
    
    def get_dynamic_part(self):
        #for CREATE requests this dynamic part is the actual path to the file
        return None
    
    def get_dynamic_part_length(self):
        return None
    
    def get_static_length(self):
        return self.length
    
    def get_length_string(self):
        if self.get_dynamic_part() != None:
            return f"{self.get_static_length()} + {self.get_dynamic_part_length()}"
        else:
            return f"{self.length}"


class CompSMBCommand(SMBCommand):
    def __init__(self, timestamp, length, ip_src, commands=[], packet_num=None):
        super().__init__(timestamp, length, ip_src, packet_num)
        self.commands = commands
        self.number_commands = len(commands)
        self.dynamic_parts = self.get_dynamic_parts()
        self.dynamic_length = sum(self.get_dynamic_parts_lengths())
        self.static_length = length - self.dynamic_length
        self.length = length

    def __str__(self):
        string = ' | '.join(str(command) for command in self.commands)
        ts = timestamp_to_human_readable(self.timestamp)
        string = f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} Compound SMB command {self.get_hash()} - {string}"
        return string
    
    def get_hash(self):
        concatenated_values = ','.join([command.get_hash() for command in self.commands])
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()
        return md5_hash
    

    def get_length_string(self):
        #TODO: this should support multiple dynamic elements and not sum them up
        return f"{self.static_length} + {self.dynamic_length}"


    def get_filename(self):
        #TODO: only returns first file name given in the compound command
        for commands in self.commands:
            if commands.get_filename() != None:
                return commands.get_filename()
            
    def get_dynamic_part(self):
        #TODO: currently, we only return the first one
        if self.dynamic_parts:
            return self.dynamic_parts[0]
        else:
            return None
    
    def get_dynamic_parts(self):
        dynamic_parts = []
        for command in self.commands:
            if command.get_dynamic_part() != None:
                dynamic_parts.append(command.get_dynamic_part())

        return dynamic_parts
    
    def get_dynamic_parts_lengths(self):
        dynamic_parts_lengths = []
        for command in self.commands:
            if command.get_dynamic_part_length() != None:
                dynamic_parts_lengths.append(command.get_dynamic_part_length())

        return dynamic_parts_lengths
            
    def get_command(self):
        return "COMPOUND"
    
    def get_static_length(self):
        return self.static_length
            
            

class SingleSMBCommand(SMBCommand):
    def __init__(self, timestamp, length, ip_src, command, connection_hash=None, TID=None, packet_num=None):
        super().__init__(timestamp, length, ip_src, packet_num)
        self.command = command
        self.connection_hash = connection_hash
        self.TID = TID

    def get_command(self):
        return self.command
    
    def get_share_path(self):
        connection_shares = SMB_EXTRACTED_SHARES.get(self.connection_hash)
        if connection_shares is None:
            return None
        share_path = connection_shares.get(self.TID)
        return share_path

class SMBCreateCommand(SingleSMBCommand):
    def __init__(self, timestamp, connection_hash, TID, length, ip_src, file_name, access_mask, file_attributes, disposition, create_options, share_access, extra_info, packet_num=None):
        super().__init__(timestamp, length, ip_src, "CREATE", connection_hash, TID, packet_num)
        self.file_name = file_name
        self.access_mask = access_mask
        self.file_attributes = file_attributes
        self.disposition = disposition
        self.create_options = create_options
        self.share_access = share_access
        self.extra_info = extra_info
        self.length = length
        self.static_length = self.length - len(self.file_name) * 2 # uses 2 bytes per character

    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} CREATE - {self.get_hash()} - {self.file_name}"
    
    def get_hash(self):
        values = [
            "CREATE",
            str(self.access_mask),
            str(self.file_attributes),
            str(self.share_access),
            str(DISPOSITION_STRINGS.get(self.disposition, "Unknown disposition")),
            str(self.create_options)]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()
        return md5_hash
    
    def get_filename(self):
        #this will create the total file path instead of only the file name
        connection_shares = SMB_EXTRACTED_SHARES.get(self.connection_hash)
        if connection_shares is None:
            return self.file_name
        share_path = connection_shares.get(self.TID)
        if share_path == None:
            return self.file_name
        else:
            full_path = os.path.join(share_path, self.file_name)
            return full_path
        
    def get_dynamic_part(self):
        #for CREATE requests this dynamic part is the actual path to the file
        return self.file_name
    
    def get_dynamic_part_length(self):
        return len(self.file_name) * 2
    
    def get_static_length(self):
        return self.static_length
    
            
class SMBCreateCommandResponse(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, status, packet_num=None):
        super().__init__(timestamp, length, ip_src, "CREATE RESPONSE", packet_num=packet_num)
        self.status = status
    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} CREATE RESPONSE - {self.get_hash()}"
    
    def get_hash(self):
        str_status = EXTENDED_STATUS_ERREF.get(self.status, "Unknown status")
        values = [
            "CREATE RESPONSE",
            str_status]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash

    
class SMBQueryInfoCommand(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, info_type, info_class, output_length, packet_num=None):
        super().__init__(timestamp, length, ip_src, "QUERY INFO", packet_num=packet_num)
        self.info_type = info_type
        self.info_class = info_class
        self.output_length = output_length

    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        str_info_type = SMB2_INFO_TYPE.get(self.info_type)
        if self.info_type == 0x01:
            str_info_class = EXTENDED_FILE_INFO_CLASSES.get(self.info_class, "Unknown")
        else:
            str_info_class = FileSystemInformationClasses.get(self.info_class, 0)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} QUERY INFO - {self.get_hash()} - {str_info_type} - {str_info_class}"
    
    def get_hash(self):
        str_info_type = SMB2_INFO_TYPE.get(self.info_type)
        if self.info_type == 0x01:
            str_info_class = EXTENDED_FILE_INFO_CLASSES.get(self.info_class, "Unknown")
        else:
            str_info_class = FileSystemInformationClasses.get(self.info_class, "Unknown")
            
        values = [
            "QUERY INFO",
            str_info_type,
            str_info_class]
        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash
    
class SMBQueryInfoCommandResponse(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, status, info_type, info_class, buffer, packet_num=None):
        super().__init__(timestamp, length, ip_src, "QUERY INFO RESPONSE", packet_num=packet_num)
        self.status = status
        self.info_type = info_type
        self.info_class = info_class
        self.dynamic_part = None
        self.length = length
        self.static_length = length

        if self.info_type == 0x01 and self.info_class == 0x30:
            if buffer and len(buffer) > 0 and len(buffer[0]) > 1:
                buffer = buffer[0][1]
                file_name_length = int.from_bytes(buffer[:4], byteorder='little')
                file_name = buffer[4:4 + file_name_length].decode('utf-16le')
                self.dynamic_part = file_name
                self.static_length = self.length - len(self.dynamic_part) * 2 # uses 2 bytes per character


    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} QUERY INFO RESPONSE - {self.get_hash()}"
    
    def get_hash(self):
        str_status = EXTENDED_STATUS_ERREF.get(self.status, "Unknown status")
        values = [
            "QUERY INFO RESPONSE",
            str_status]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash
    
    def get_dynamic_part(self):
        return self.dynamic_part
    
    def get_dynamic_part_length(self):
        #currently this only covers a file name as a dynamic part. 
        if self.info_type == 0x01 and self.info_class == 0x30:
            return len(self.dynamic_part) * 2
        else:
            return None
    
    def get_static_length(self):
        return self.static_length
    
class SMBQueryDirectoryCommand(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, info_class, file_name, packet_num=None):
        super().__init__(timestamp, length, ip_src, "QUERY DIRECTORY", packet_num=packet_num)
        self.info_class = info_class
        self.file_name = file_name

    def __str__(self):
        str_info_class = EXTENDED_FILE_INFO_CLASSES.get(self.info_class, "Unknown")
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} QUERY DIRECTORY - {self.get_hash()} - {str_info_class} - {self.file_name}"
    
    def get_hash(self):
        str_info_class = EXTENDED_FILE_INFO_CLASSES.get(self.info_class, "Unknown")      
        values = [
            "QUERY DIRECTORY",
            str_info_class]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash

    def get_filename(self):
        return self.file_name
    
class SMBSetInfoCommand(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, info_type, info_class, data, connection_hash, TID, packet_num=None):
        super().__init__(timestamp, length, ip_src, "SET INFO", connection_hash, TID, packet_num)
        self.info_type = info_type
        self.info_class = info_class
        self.data = data

    def __str__(self):
        str_info_type = SMB2_INFO_TYPE.get(self.info_type)
        ts = timestamp_to_human_readable(self.timestamp)
        if self.info_type == 0x01:
            str_info_class = EXTENDED_FILE_INFO_CLASSES.get(self.info_class, "Unknown")
        else:
            str_info_class = FileSystemInformationClasses.get(self.info_class, "Unknown")
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} SET INFO - {self.get_hash()} - {str_info_type} - {str_info_class}"
    
    def get_hash(self):
        str_info_type = SMB2_INFO_TYPE.get(self.info_type)
        if self.info_type == 0x01:
            str_info_class = EXTENDED_FILE_INFO_CLASSES.get(self.info_class, "Unknown")
        else:
            str_info_class = FileSystemInformationClasses.get(self.info_class, "Unknown")
            
        values = [
            "SET INFO",
            str_info_type,
            str_info_class]
        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()
        return md5_hash
    
    def get_data(self):
        return self.data
    
class SMBSetInfoCommandResponse(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, status, packet_num=None):
        super().__init__(timestamp, length, ip_src, "SET INFO RESPONSE", packet_num=packet_num)
        self.status = status

    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} SET INFO RESPONSE - {self.get_hash()}"
    
    def get_hash(self):
        str_status = EXTENDED_STATUS_ERREF.get(self.status, "Unknown status")
        values = [
            "SET INFO RESPONSE",
            str_status]
        
        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()
        return md5_hash
        

class SMBWriteCommand(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, packet_num=None):
        super().__init__(timestamp, length, ip_src, "WRITE", packet_num=packet_num)

    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} WRITE - {self.get_hash()}"
    
    def get_hash(self):            
        values = ["WRITE"]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash
    
class SMBWriteCommandResponse(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, status, packet_num=None):
        super().__init__(timestamp, length, ip_src, "WRITE RESPONSE", packet_num=packet_num)
        self.status = status

    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} WRITE RESPONSE - {self.get_hash()}"
    
    def get_hash(self):
        str_status = EXTENDED_STATUS_ERREF.get(self.status, "Unknown status")
        values = [
            "WRITE RESPONSE",
            str_status]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash


class SMBReadCommand(SingleSMBCommand):
    def __init__(self, timestamp, length, ip_src, packet_num=None):
        super().__init__(timestamp, length, ip_src, "READ", packet_num=packet_num)

    def __str__(self):
        ts = timestamp_to_human_readable(self.timestamp)
        return f"[{ts}] {Fore.YELLOW}[{self.get_length_string()}]{Fore.RED} READ - {self.get_hash()}"
    
    def get_hash(self):            
        values = ["READ"]

        concatenated_values = ','.join(values)
        md5_hash = hashlib.md5(concatenated_values.encode()).hexdigest()

        return md5_hash
    