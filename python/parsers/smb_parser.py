import logging
logger = logging.getLogger(__name__)

from config.constants import FILE_ACTIONS
from models.commands import *
from scapy.all import IP, TCP, Raw
from scapy.layers.smb2 import (
    SMB2_Header,
    SMB2_Create_Request,
    SMB2_Create_Response,
    SMB2_Query_Directory_Request,
    SMB2_Query_Info_Request,
    SMB2_Query_Info_Response,
    SMB2_Close_Request,
    SMB2_Read_Request,
    SMB2_Set_Info_Request,
    SMB2_Set_Info_Response,
    SMB2_Write_Request,
    SMB2_Write_Response,
    SMB2_Session_Setup_Request,
    SMB2_Tree_Connect_Request,
    SMB2_Tree_Connect_Response
)

from config.constants import (
    SMB_EXTRACTED_SHARES,
    SMB_EXTRACTED_QUERY_REQUESTS,
    SMB_SHARE_INFORMATION_TMP
)


def parse_smb2_packet(packet, packet_num):
    """
    Parse an SMB2 packet and extract relevant SMB commands.
    
    Args:
        packet: The Scapy packet to parse
        packet_num: The packet number for logging purposes
        
    Returns:
        List of extracted SMB command objects

    Problem: 
        Scapy fails to parse response layers when status != 0
    Workaround: 
        Fallback to command code check (currently only for SET_INFO_RESPONSE)
    """
    
    extracted_smb_commands = []
    
    # Check for the top-level SMB2_Header - if not present, this isn't an SMB2 packet
    if not packet.haslayer(SMB2_Header):
        return []

    # Extract basic packet metadata
    timestamp = packet.time
    length = len(packet[TCP].payload) if packet.haslayer(TCP) else len(packet)
    ip_src = packet[IP].src if packet.haslayer(IP) else "0.0.0.0" 

    # Get SMB2 header information
    current_smb2_header = packet[SMB2_Header]
    connection_hash = get_bidirectional_connection_hash(packet)
    TID = current_smb2_header.TID  # Tree ID - identifies the share being accessed


    # Handle SMB2 Create Request - used to open/create files or directories
    if packet.haslayer(SMB2_Create_Request):
        layer = packet[SMB2_Create_Request]
        temp_file_name = layer.Name if layer.NameLen != 0 else "/"
        temp_access_mask = layer.DesiredAccess
        temp_share_access = layer.ShareAccess
        temp_create_disposition = layer.CreateDisposition
        temp_create_options = layer.CreateOptions
        temp_file_attributes = layer.FileAttributes
        temp_extra_info = []

        # Extract create contexts if present (additional metadata about the create operation)
        if layer.CreateContextsLen != 0:
            for context in layer.CreateContexts:
                temp_extra_info.append(context.Name.decode())
                if context.Next == 0:
                    break
        temp = SMBCreateCommand(timestamp, connection_hash, TID, length, ip_src, temp_file_name, temp_access_mask, temp_file_attributes, temp_create_disposition, temp_create_options, temp_share_access, temp_extra_info, packet_num)
        extracted_smb_commands.append(temp)
    
    # Handle SMB2 Create Response - server's response to create request
    elif packet.haslayer(SMB2_Create_Response) or \
        (current_smb2_header.Command == 0x05 and current_smb2_header.Flags & 0x01):
        temp = SMBCreateCommandResponse(timestamp, length, ip_src, current_smb2_header.Status, packet_num)
        extracted_smb_commands.append(temp)    

    # Handle SMB2 Query Info Request - used to query file/directory metadata
    elif packet.haslayer(SMB2_Query_Info_Request):
        layer = packet[SMB2_Query_Info_Request]
        temp = SMBQueryInfoCommand(timestamp, length, ip_src, layer.InfoType, layer.FileInfoClass, layer.OutputBufferLength, packet_num)
        mid = current_smb2_header.MID  # Message ID - used to match requests with responses
        # Store query info for later matching with response
        info = dict()
        info['info_type'] = layer.InfoType
        info['info_class'] = layer.FileInfoClass
        SMB_EXTRACTED_QUERY_REQUESTS[mid] = info 
        extracted_smb_commands.append(temp)
    
    # Handle SMB2 Query Info Response - server's response with metadata
    elif packet.haslayer(SMB2_Query_Info_Response) or \
        (current_smb2_header.Command == 0x10 and current_smb2_header.Flags & 0x01):
        mid = current_smb2_header.MID
        # Match this response with the earlier request using MID
        info = SMB_EXTRACTED_QUERY_REQUESTS.get(mid) 
        if info:
            buffer_data = b''
            # Extract raw data payload if present - only if Scapy parsed the layer
            if packet.haslayer(SMB2_Query_Info_Response):
                layer = packet[SMB2_Query_Info_Response]
                if layer.haslayer(Raw): 
                    buffer_data = layer[Raw].load
            temp = SMBQueryInfoCommandResponse(timestamp, length, ip_src, current_smb2_header.Status, info.get('info_type'), info.get('info_class'), buffer_data, packet_num)
            extracted_smb_commands.append(temp)
        else:
            pass 

    # Handle SMB2 Close Request 
    elif packet.haslayer(SMB2_Close_Request):
        pass 

    # Handle SMB2 Query Directory Request - used to list directory contents
    elif packet.haslayer(SMB2_Query_Directory_Request):
        layer = packet[SMB2_Query_Directory_Request]
        temp = SMBQueryDirectoryCommand(timestamp, length, ip_src, layer.FileInformationClass, layer.FileName, packet_num)
        extracted_smb_commands.append(temp)

    # Handle SMB2 Read Request - used to read file data
    elif packet.haslayer(SMB2_Read_Request):
        temp = SMBReadCommand(timestamp, length, ip_src, packet_num)
        extracted_smb_commands.append(temp)

    # Handle SMB2 Set Info Request - used to modify file/directory metadata (e.g., rename, delete)
    elif packet.haslayer(SMB2_Set_Info_Request):
        layer = packet[SMB2_Set_Info_Request]
        
        data_payload = None
        if hasattr(layer, 'Buffer') and layer.Buffer:
            # Buffer is a list of tuple: [('Data', <FileRenameInformation ...>)]
            for item in layer.Buffer:
                if isinstance(item, tuple) and len(item) >= 2:
                    # Second element is FileRenameInformation or similar structure - keep the structured object
                    data_payload = item[1]
                    break
        

        if data_payload:
            logger.debug(f"Final data_payload: {type(data_payload)} - {hasattr(data_payload, 'FileName')}")
        else:
            logger.debug("Final data_payload: None")
        
        temp = SMBSetInfoCommand(timestamp, length, ip_src, layer.InfoType, layer.FileInfoClass, data_payload, connection_hash, TID, packet_num)
        extracted_smb_commands.append(temp)

    #  Handle SMB2 Set Info Response 
    elif packet.haslayer(SMB2_Set_Info_Response) or \
        (current_smb2_header.Command == 0x11 and current_smb2_header.Flags & 0x01):
        temp = SMBSetInfoCommandResponse(timestamp, length, ip_src, current_smb2_header.Status, packet_num)
        extracted_smb_commands.append(temp)


    # Handle SMB2 Write Request - used to write data to a file
    elif packet.haslayer(SMB2_Write_Request):
        temp = SMBWriteCommand(timestamp, length, ip_src, packet_num)
        extracted_smb_commands.append(temp)

    # Handle SMB2 Write Response - server's response to write request
    elif packet.haslayer(SMB2_Write_Response) or \
        (current_smb2_header.Command == 0x09 and current_smb2_header.Flags & 0x01):
        temp = SMBWriteCommandResponse(timestamp, length, ip_src, current_smb2_header.Status, packet_num)
        extracted_smb_commands.append(temp)

    # Handle SMB2 Session Setup Request - used to establish an authenticated session
    elif packet.haslayer(SMB2_Session_Setup_Request):
        pass 
    
    # Handle SMB2 Tree Connect Request - used to connect to a network share
    elif packet.haslayer(SMB2_Tree_Connect_Request):
        layer = packet[SMB2_Tree_Connect_Request]
        # Store the share name from the request for later matching with response
        populate_smb_share_information(connection_hash, "Request", current_smb2_header.MID, share_name=layer.Path)
        pass 
    
    # Handle SMB2 Tree Connect Response - server's response with TID for the share
    elif packet.haslayer(SMB2_Tree_Connect_Response) or \
        (current_smb2_header.Command == 0x03 and current_smb2_header.Flags & 0x01):
        # Store the TID returned by the server and complete the mapping
        populate_smb_share_information(connection_hash, "Response", current_smb2_header.MID, TID=current_smb2_header.TID)
        pass
    else:
        pass 

    # If multiple commands were extracted, wrap them in a composite command
    if len(extracted_smb_commands) > 1:
        temp = CompSMBCommand(timestamp, length, ip_src, extracted_smb_commands)
        extracted_smb_commands = [temp]
    
    # Log and return the extracted commands
    for cmd in extracted_smb_commands:
        logger.debug(f"REAL-TIME PARSE: Packet #{packet_num} -> {type(cmd).__name__}: {cmd.get_hash()}")
        return extracted_smb_commands
    


def populate_smb_share_information(connection_hash, type, MID, TID=None, share_name=None):
    """
    Track SMB share connections by matching Tree Connect requests with responses.
    This builds a mapping of TID (Tree ID) to share names for each connection.
    
    Args:
        connection_hash: Hash identifying the bidirectional TCP connection
        type: Either "Request" or "Response" to indicate which phase we're processing
        MID: Message ID used to match requests with responses
        TID: Tree ID (only provided in Response)
        share_name: Share path (only provided in Request)
    """
    if type == "Request":
        # Initialize nested dictionaries if needed
        if connection_hash not in SMB_SHARE_INFORMATION_TMP:
            SMB_SHARE_INFORMATION_TMP[connection_hash] = dict()
        if MID not in SMB_SHARE_INFORMATION_TMP[connection_hash]:
            # Store the request information - waiting for matching response
            SMB_SHARE_INFORMATION_TMP[connection_hash][MID] = dict()
            SMB_SHARE_INFORMATION_TMP[connection_hash][MID]["share_name"] = share_name
            SMB_SHARE_INFORMATION_TMP[connection_hash][MID]["complete"] = False
        else:
            logger.error(f"[-] Error: existing MID {MID} for connection hash {hex(connection_hash)}")
            return
    elif type == "Response":
        # Look up the matching request using connection_hash
        if connection_hash not in SMB_SHARE_INFORMATION_TMP:
            logger.error(f"[-] Error: connection hash {hex(connection_hash)} not found, should be already in dictionary")
            return
        else:
            # Match response with request using MID
            if MID in SMB_SHARE_INFORMATION_TMP[connection_hash]:
                # Complete the mapping by adding TID from response
                SMB_SHARE_INFORMATION_TMP[connection_hash][MID]["TID"] = TID
                SMB_SHARE_INFORMATION_TMP[connection_hash][MID]["complete"] = True
                # Store the final mapping of TID to share_name
                if connection_hash not in SMB_EXTRACTED_SHARES:
                    #TODO: better use dest IP for share to identify it?
                    SMB_EXTRACTED_SHARES[connection_hash] = dict()
                SMB_EXTRACTED_SHARES[connection_hash][TID] = SMB_SHARE_INFORMATION_TMP[connection_hash][MID]["share_name"]
            else:
                logger.error(f"[-] Error: MID {MID} not found for connection hash {hex(connection_hash)}")
                return    
            


def parse_change_notify_response(data):
    """
    Parse SMB2 Change Notify response data to extract file system change events.
    
    Change Notify responses contain a sequence of structures, each describing
    a file system change (create, delete, modify, rename, etc.).
    
    Args:
        data: Raw bytes from the Change Notify response buffer
        
    Returns:
        List of tuples containing (action, file_name) for each change event
    """
    parsed_data = []
    index = 0
    next_structure = True
    while index < len(data):
        # Read the offset to the next structure (0 means this is the last one)
        next_structure_offset = int.from_bytes(data[index:index+4], byteorder='little')
        # Read the action type 
        action = int.from_bytes(data[index+4:index+8], byteorder='little')
        # Read the length of the file name
        file_name_length = int.from_bytes(data[index+8:index+12], byteorder='little')
        # Extract and decode the file name
        file_name = data[index+12:index+12+file_name_length].decode('utf-8')
        parsed_data.append((action, file_name))
        logger.debug_purple(f"\t{FILE_ACTIONS.get(action, 'unknown action')} {file_name}")
        # Move to next structure
        index += next_structure_offset
        # If offset is 0, this was the last structure
        if next_structure_offset == 0:
            break
    return parsed_data

def get_bidirectional_connection_hash(packet):
    """
    Generate a hash that uniquely identifies a bidirectional TCP connection.
    
    The hash is the same regardless of which direction the packet is traveling,
    allowing us to track both sides of a connection with a single identifier.
    
    Args:
        packet: Scapy packet containing IP and TCP layers
        
    Returns:
        Integer hash representing the bidirectional connection, or None if packet lacks IP/TCP
    """
    if IP in packet and TCP in packet:
        src_ip = packet[IP].src
        src_port = packet[TCP].sport
        dst_ip = packet[IP].dst
        dst_port = packet[TCP].dport
        # Create tuples for both directions
        connection_tuple1 = (src_ip, src_port, dst_ip, dst_port)
        connection_tuple2 = (dst_ip, dst_port, src_ip, src_port)
        # Use a sorted tuple to ensure bidirectional uniqueness
        # This ensures packets in both directions produce the same hash
        bidirectional_tuple = tuple(sorted([connection_tuple1, connection_tuple2]))
        connection_hash = hash(bidirectional_tuple)
        return connection_hash
    return None