import os
import re
import traceback
import logging
from utils.helper import timestamp_to_human_readable
from parsers.signature_parser import *
import csv
import inspect
from parsers import signature_parser
# Loggin Setup
logger = logging.getLogger(__name__)




# Auto-discovery of parser functions using inspection
def _build_parser_dispatcher():
    """Automatically discovers all parser functions from the signature_parser module."""
    """ Print() is used instead of logger.debug(), since logging is not successfully set up while this function is called"""
    
    dispatcher = {}
    
    # Get all functions from the signature_parser module
    for name, obj in inspect.getmembers(signature_parser, inspect.isfunction):
        # Only include functions that start with 'signature_parsing_'
        if name.startswith('signature_parsing_'):
            dispatcher[name] = obj
            #print(f"Registered parser function: {name}")
    
    #print(f"Auto-discovered {len(dispatcher)} parser functions")
    return dispatcher

# Build the dispatcher automatically
PARSER_DISPATCHER = _build_parser_dispatcher()
def load_rules(filepath):
    """
    Loads rules from a TSV file and groups them by their first hash in the signature (trigger_hash).
    This allows for efficient lookup of rules based on command hashes.
    
    Args:
        filepath: Path to the TSV rules file
        
    Returns:
        Dictionary mapping trigger_hash to list of rule objects, or None if error occurs
    """
    rules_dict = {}
    
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            # Skip comment lines that start with #
            lines = [line for line in f if not line.strip().startswith('#')]
            
            # Reset file pointer and read with csv
            f.seek(0)
            # Skip the two header lines
            next(f)  # Skip #fields line
            next(f)  # Skip #types line
            
            reader = csv.DictReader(f, delimiter='\t', fieldnames=[
                'application', 'description', 'signature', 'excluded', 'max_skip',
                'filename_hashes', 'id', 'command', 'parsing'
            ])
            
            rule_count = 0
            for row in reader:
                # Parse signature field (comma-separated list)
                signature_str = row.get('signature', '').strip()
                if not signature_str or signature_str == '-':
                    continue

                signature = [s.strip() for s in signature_str.split(',')]

                # Parse excluded field (comma-separated list or set)
                excluded_str = row.get('excluded', '-').strip()
                if excluded_str == '-' or not excluded_str:
                    excluded = set()
                else:
                    excluded = set(s.strip() for s in excluded_str.split(','))

                # Parse filename_hashes field (comma-separated list or set)
                filename_hashes_str = row.get('filename_hashes', '-').strip()
                if filename_hashes_str == '-' or not filename_hashes_str:
                    filename_hashes = set()
                else:
                    filename_hashes = set(s.strip() for s in filename_hashes_str.split(','))

                # Create rule object (compatible with existing code)
                rule_object = {
                    'id': row.get('id', '').strip(),
                    'application': row.get('application', '').strip(),
                    'description': row.get('description', '').strip(),
                    'command': row.get('command', '').strip(),
                    'signature': signature,
                    'excluded': excluded,
                    'max_skip': int(row.get('max_skip', 0)),
                    'filename_hashes': filename_hashes,
                    'parsing': row.get('parsing', '').strip() if row.get('parsing', '-').strip() != '-' else None,
                    'trigger_hash': signature[0] if signature else None
                }
                
                trigger_hash = rule_object['trigger_hash']
                if not trigger_hash:
                    continue

                # Add rule to dictionary
                if trigger_hash in rules_dict:
                    rules_dict[trigger_hash].append(rule_object)
                else:
                    rules_dict[trigger_hash] = [rule_object]
                
                rule_count += 1
        
        logger.info(f"Successfully loaded and grouped {rule_count} rules into {len(rules_dict)} triggers from TSV.")
        return rules_dict
        
    except FileNotFoundError:
        logger.critical(f"FATAL: Rules file not found at '{filepath}'.")
        return None
    except Exception as e:
        logger.critical(f"FATAL: Error loading or processing rules from '{filepath}': {e}")
        return None


def analyze_smb_commands(smb_commands, smb_rules, output_file=None):
    """
    Analyzes a sequence of SMB commands against the loaded ruleset.

    This function matches SMB command sequences against predefined patterns (rules),
    allowing for skipped commands within limits, and reconstructs high-level operations.

    Args:
        smb_commands: List of SMB command objects extracted from PCAP
        smb_rules: Dictionary of rules grouped by trigger hash
        output_file: Optional file path to write results (if None, only prints to terminal)

    Returns:
        Tuple of (reconstructed_commands, matched_rules) lists
    """

    logger.info("Analyzing SMB Commands")

    # Validate that rules were successfully loaded
    if not smb_rules:
        logger.error("SMB Rules could not be loaded. Aborting analysis.")
        return [], []

    # If output file specified, clear it at start
    if output_file:
        with open(output_file, 'w') as f:
            pass  # Creates/clears the file

    # Log a preview of the raw extracted commands for debugging
    logger.debug("--- Raw SMB Commands Extracted (first 10) ---")
    for i, command in enumerate(smb_commands[:10]):
        logger.debug_red(f"[{i}] {str(command)}")
    logger.debug("---------------------------------------------")
    logger.debug("######################")

    # Initialize lists to store analysis results
    reconstructed_commands = []  # Human-readable reconstructed operations
    matched_rules = []  # Rules that successfully matched command sequences

    # Initialize counters for iterating through commands
    index = 0  # Current position in the command list
    processed_commands_count = 0  # Total number of commands examined
    
    # Main loop: iterate through all SMB commands
    while index < len(smb_commands):
        command = smb_commands[index]
        processed_commands_count += 1

        logger.debug(f"\n--- Analyzing command at index {index} ---")
        logger.debug(f"  Command type: {type(command).__name__}, Hash: {command.get_hash()}")

        # Skip commands that have already been matched to a rule
        if command.is_assigned():
            logger.debug(f"  Command at index {index} is already assigned. Skipping.")
            index += 1
            continue

        # Get the hash of the current command for rule lookup
        command_hash = command.get_hash()
        possible_candidates = []  # Will store rules that successfully match

        # Check if there are any rules triggered by this command's hash
        if command_hash in smb_rules:
            logger.debug(f"  Found {len(smb_rules[command_hash])} rule candidate(s) for hash: {command_hash}")
            candidates = smb_rules[command_hash]

            # Try to match each candidate rule against the command sequence
            for i, candidate_rule in enumerate(candidates):
                logger.debug(f"    Checking candidate rule {i+1}: '{candidate_rule['description']}'")
                # Create a copy to avoid modifying the original rule
                candidate_rule_copy = candidate_rule.copy()

                # Extract rule parameters that control matching behavior
                max_skip = candidate_rule_copy.get('max_skip', 0)  # Max commands that can be skipped
                excluded = candidate_rule_copy.get('excluded', [])  # Hashes that invalidate the match
                dont_skip = candidate_rule_copy.get('dont_skip', [])  # Hashes that cannot be skipped over

                # Initialize matching state variables
                skipped = 0  # Number of commands skipped so far
                signature = candidate_rule_copy["signature"][1:]  # Remaining signature to match (exclude trigger)
                candidate_okay = True  # Flag indicating if rule still matches
                commands_in_sequence = [command]  # Collect all matched commands

                # Track dynamic parts of commands for length encoding
                temp_dynamic_parts = dict()
                if command.get_dynamic_part():
                    dynamic_part = command.get_dynamic_part()
                    # Assign alphabetic labels to unique dynamic parts
                    if dynamic_part not in temp_dynamic_parts:
                        temp_dynamic_parts[dynamic_part] = chr(65 + len(temp_dynamic_parts))
                    enc_conversion_length = f"{command.get_static_length()} + {temp_dynamic_parts[dynamic_part]}"
                else:
                    enc_conversion_length = command.length
                
                # Store metadata about the matched sequence
                candidate_rule_copy["enc_conversion_lengths"] = [enc_conversion_length]
                candidate_rule_copy["enc_time_stamps"] = [command.timestamp]

                # Try to match the rest of the signature against future commands
                for j, signature_hash_expected in enumerate(signature):
                    signature_found = False
                    current_check_offset = j + 1  # Offset from current command

                    # Allow skipping up to max_skip commands while searching for the expected hash
                    while skipped <= max_skip:
                        try:
                            # Calculate the index of the future command to check
                            future_command_index = index + current_check_offset + skipped
                            future_command = smb_commands[future_command_index]
                            logger.debug(f"      Checking future cmd at index {future_command_index} (skipped: {skipped}) for sig part {j+1}")
                        except IndexError:
                            # Ran out of commands before completing the signature
                            logger.debug_red(f"      IndexError for rule '{candidate_rule_copy['description']}'. Not okay.")
                            candidate_okay = False
                            break

                        future_command_hash = future_command.get_hash()
                        logger.debug_red(f"        Future command hash: {future_command_hash}, Expected: {signature_hash_expected}")

                        # Check if the future command is explicitly excluded
                        if future_command_hash in excluded:
                            logger.debug_red(f"        Hash {future_command_hash} is EXCLUDED. Not okay.")
                            candidate_okay = False
                            break

                        # Check if we're trying to skip over a command that shouldn't be skipped
                        if skipped > 0 and future_command_hash in dont_skip:
                            logger.debug_red(f"        Hash {future_command_hash} is in DONT_SKIP. Not okay.")
                            candidate_okay = False
                            break

                        # Check if the future command matches the expected signature part
                        # Signature can be either a single hash or a list of acceptable hashes
                        is_match = (isinstance(signature_hash_expected, list) and future_command_hash in signature_hash_expected) or \
                                  (future_command_hash == signature_hash_expected)

                        if not is_match:
                            # This command doesn't match, try skipping it
                            skipped += 1
                        else:
                            # Found a match! Add to sequence and move to next signature part
                            signature_found = True
                            commands_in_sequence.append(future_command)
                            break

                    # If we couldn't find this signature part, the rule doesn't match
                    if not signature_found:
                        candidate_okay = False
                        logger.debug_red(f"      Signature hash '{signature_hash_expected}' not found. Not okay.")
                        break

                # If the entire signature matched, try to parse the command sequence
                if candidate_okay:
                    logger.debug_green(f"    Rule '{candidate_rule_copy['description']}' signature matched! Parsing...")
                    info = None
                    try:
                        # Look up and execute the appropriate parsing function
                        parser_name = candidate_rule_copy["parsing"]
                        parsing_function = PARSER_DISPATCHER.get(parser_name)

                        if parsing_function:
                            # Parse the matched command sequence to extract high-level info
                            info = parsing_function(commands_in_sequence)
                        else:
                            logger.error(f"    Parser function '{parser_name}' not found in PARSER_DISPATCHER!")

                    except Exception as e:
                        logger.debug_red(f"    ERROR: Parsing function for '{candidate_rule_copy['description']}' failed: {e}")
                        traceback.print_exc()

                    # Only consider this candidate if parsing was successful
                    if info is None:
                        logger.debug_red(f"    Parsing for '{candidate_rule_copy['description']}' returned None. Not okay.")
                    else:
                        # Store the parsed information and add to candidates list
                        candidate_rule_copy["info"] = info
                        candidate_rule_copy["skipped"] = skipped
                        possible_candidates.append(candidate_rule_copy)
                        logger.debug(f"    Rule '{candidate_rule_copy['description']}' added to possible_candidates.")

        # If multiple rules matched, select the best one
        if possible_candidates:
            # Prefer rules with longer signatures (more specific matches)
            max_length = max(len(c['signature']) for c in possible_candidates)
            max_candidates = [c for c in possible_candidates if len(c['signature']) == max_length]
            final_candidate = max_candidates[0] if max_candidates else None
            
            # Simplified ambiguity logic
            # If multiple rules have the same max length, just use the first one
            if len(max_candidates) > 1:
                logger.debug_red("  Multiple candidates with max length found. Defaulting to the first one.")

            # Process the selected rule and create reconstructed command
            if final_candidate:
                # Convert timestamp to human-readable format
                timestamp_human = timestamp_to_human_readable(command.timestamp)
                ip_src = command.ip_src
                info = final_candidate['info']
                
                # Clean ANSI color codes from the info string
                clean_info = re.sub(r'\x1b\[[0-9;]*m', '', info)
                # Replace any existing application tags with the correct one from the rule
                clean_info = re.sub(r'\[.*?\]', f"[{final_candidate['application']}]", clean_info)
                
                # Create the final reconstructed command tuple
                reconstructed_command = (timestamp_human, ip_src, clean_info)
                reconstructed_commands.append(reconstructed_command)
                matched_rules.append(final_candidate)

                logger.debug_green(f"[{ip_src}] {info}")

                # Print to terminal (with colors from info)
                print(f"{timestamp_human} {ip_src} {info}")

                # Write to file only if specified (use clean_info without ANSI codes)
                if output_file:
                    with open(output_file, 'a') as f:
                        f.write(f"{timestamp_human} {ip_src} {clean_info}\n")

                # Advance the index past all commands that were part of this match
                index += len(final_candidate['signature']) + final_candidate['skipped']
            else:
                # No valid candidate found, move to next command
                index += 1
        else:
            # No matching rules found for this command, move to next
            index += 1

    # Log summary statistics of the analysis
    logger.debug_yellow(f"\nReconstructed commands: {len(reconstructed_commands)}")
    logger.debug_yellow(f"Total commands processed by loop: {processed_commands_count}")


    return reconstructed_commands, matched_rules