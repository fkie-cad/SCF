import logging
logger = logging.getLogger(__name__)
import traceback
from .smb_parser import parse_smb2_packet
from scapy.all import rdpcap
from scapy.layers.smb2 import SMB2_Header

def extract_smb_commands_from_pcap(pcap_file_path):
    """
    Extracts SMB2 commands from a PCAP file by analyzing packets.
    
    Args:
        pcap_file_path: Path to the PCAP file to analyze
        
    Returns:
        List of extracted SMB command objects, or empty list if error occurs
    """
    # Initialize list to store all extracted SMB command objects
    extracted_commands_list = []
    
    # Separate list to track command hashes for debugging output
    # This allows us to print a summary at the end without modifying the main command objects
    all_generated_hashes_for_output = [] 
    
    logger.info(f"Attempting to read PCAP from: {pcap_file_path}")
    
    try:
        # Load all packets from the PCAP file into memory
        packets = rdpcap(pcap_file_path) 
        logger.info(f"Successfully loaded {len(packets)} packets from {pcap_file_path}")
        
        # Validate that the PCAP file contains packets
        if not packets:
            logger.error("WARNING: The PCAP file appears to be empty or contains no packets.")
            return []
        
        # Iterate through each packet in the capture file
        for i, packet in enumerate(packets):
            # Check if this packet contains an SMB2 protocol header
            if packet.haslayer(SMB2_Header):
                # Parse the SMB2 packet and extract command objects
                commands_from_packet = parse_smb2_packet(packet, i)
                
                # Process any commands that were successfully extracted
                if commands_from_packet:
                    # Store hash information for each command for later debugging output
                    for cmd in commands_from_packet:
                        all_generated_hashes_for_output.append(
                            f"Packet #{i}: {type(cmd).__name__}: {cmd.get_hash()}"
                        )
                    
                    # Add all extracted commands to our main collection
                    extracted_commands_list.extend(commands_from_packet)
            
            # Provide progress updates every 1000 packets to track processing of large files
            if i % 1000 == 0 and i > 0:
                logger.debug(f"Processed {i} packets. Current collected SMB commands: {len(extracted_commands_list)}")
    
    # Handle case where the PCAP file doesn't exist at the specified path
    except FileNotFoundError:
        logger.error(f"ERROR: PCAP file not found at {pcap_file_path}.")
        return []
    
    # Catch any other unexpected errors during PCAP processing
    except Exception as e:
        logger.error(f"AN UNEXPECTED ERROR occurred while reading or processing the PCAP: {e}")
        traceback.print_exc()
        return []
    
    # Log summary information about the processing results
    logger.debug(f"\n--- Finished PCAP processing ---")
    logger.debug(f"Total SMB commands collected before returning: {len(extracted_commands_list)}")
    
    # Output a formatted table of all command hashes
    logger.debug("\n" + "="*50)
    logger.debug("ALL GENERATED SMB COMMAND HASHES:")
    logger.debug("="*50)
    for hash_entry in all_generated_hashes_for_output:
        logger.debug(hash_entry)
    logger.debug("="*50 + "\n")
    
    # Return the complete list of extracted SMB command objects
    return extracted_commands_list