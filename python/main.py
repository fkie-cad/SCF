import os
import sys
import logging
from config.logging_config import setup_logging
from parsers.pcap_reader import extract_smb_commands_from_pcap
from analysis.analyser import analyze_smb_commands, load_rules

setup_logging()
logger = logging.getLogger(__name__)


def output_hashes_only(smb_commands, output_file=None):
    """
    Output SMB command hashes without pattern matching.
    Similar to Zeek's hash-only mode.
    Prints to terminal by default, writes to file only if output_file is specified.
    """
    if output_file:
        logger.info(f"Hash-only mode: Writing hashes to {output_file}")

    # Print header to terminal
    print("packet_num\tcommand\trequest_type\thash")

    # If file specified, open and write header
    f = None
    if output_file:
        f = open(output_file, 'w')
        f.write("packet_num\tcommand\trequest_type\thash\n")

    for command in smb_commands:
        # Determine command type
        cmd_type = command.get_command()

        # Determine if it's a request or response based on class name
        class_name = command.__class__.__name__
        if "Response" in class_name:
            request_type = "RESPONSE"
        else:
            request_type = "REQUEST"

        # Get hash
        cmd_hash = command.get_hash()

        # Get packet number (use actual packet number from PCAP)
        packet_num = command.packet_num if command.packet_num is not None else "N/A"

        # Build output line
        line = f"{packet_num}\t{cmd_type}\t{request_type}\t{cmd_hash}"

        # Print to terminal
        print(line)

        # Write to file if specified
        if f:
            f.write(line + "\n")

    if f:
        f.close()
        logger.info(f"Wrote {len(smb_commands)} command hashes to {output_file}")


def main():
    # Check for hash-only flag
    hash_only_mode = "--hash-only" in sys.argv

    # Parse -o/--output flag
    output_file = None
    remaining_args = []
    i = 1
    while i < len(sys.argv):
        arg = sys.argv[i]
        if arg == "--hash-only":
            i += 1
            continue
        elif arg in ("-o", "--output"):
            if i + 1 < len(sys.argv):
                output_file = sys.argv[i + 1]
                i += 2
            else:
                print("Error: -o/--output requires a filename argument.")
                sys.exit(1)
            continue
        else:
            remaining_args.append(arg)
        i += 1

    args = remaining_args

    # In hash mode, only PCAP is required
    if hash_only_mode:
        if len(args) < 1:
            print("Error: PCAP file must be specified.")
            print(f"Usage: python {sys.argv[0]} capture.pcap --hash-only")
            print(f"       python {sys.argv[0]} capture.pcap --hash-only -o output.txt")
            sys.exit(1)

        PCAP_FILE_PATH = args[0]

        if not os.path.exists(PCAP_FILE_PATH):
            print(f"Error: The file '{PCAP_FILE_PATH}' does not exist.")
            sys.exit(1)

        # Extract SMB Commands
        smb_commands = extract_smb_commands_from_pcap(PCAP_FILE_PATH)

        # Output hashes only
        output_hashes_only(smb_commands, output_file)

    else:
        # Normal mode - both PCAP and rules required
        if len(args) != 2:
            print("Error: Both PCAP file and rules file must be specified as arguments.")
            print(f"Usage: python {sys.argv[0]} capture.pcap rules.tsv")
            print(f"       python {sys.argv[0]} capture.pcap rules.tsv -o output.txt")
            print(f"Hash-only mode: python {sys.argv[0]} capture.pcap --hash-only")
            sys.exit(1)

        file1 = args[0]
        file2 = args[1]

        # Check if both files exist
        if not os.path.exists(file1):
            print(f"Error: The file '{file1}' does not exist.")
            sys.exit(1)

        if not os.path.exists(file2):
            print(f"Error: The file '{file2}' does not exist.")
            sys.exit(1)

        # Determine which file is which based on extension
        PCAP_FILE_PATH = None
        RULES_FILE_PATH = None

        if file1.lower().endswith(('.pcap', '.pcapng')):
            PCAP_FILE_PATH = file1
        elif file1.lower().endswith('.tsv'):
            RULES_FILE_PATH = file1

        if file2.lower().endswith(('.pcap', '.pcapng')):
            if PCAP_FILE_PATH is not None:
                print("Error: Both files appear to be PCAP files.")
                sys.exit(1)
            PCAP_FILE_PATH = file2
        elif file2.lower().endswith('.tsv'):
            if RULES_FILE_PATH is not None:
                print("Error: Both files appear to be TSV files.")
                sys.exit(1)
            RULES_FILE_PATH = file2

        # Validate we found both file types
        if PCAP_FILE_PATH is None:
            print("Error: No PCAP file (.pcap or .pcapng) found in arguments.")
            sys.exit(1)

        if RULES_FILE_PATH is None:
            print("Error: No TSV rules file (.tsv) found in arguments.")
            sys.exit(1)


        # Load Rules
        smb_rules = load_rules(RULES_FILE_PATH)

        # Extract SMB Commands
        smb_commands = extract_smb_commands_from_pcap(PCAP_FILE_PATH)

        # Analyze SMB Commands
        reconstructed_commands, matched_rules = analyze_smb_commands(smb_commands, smb_rules, output_file)
        logger.info(f"Reconstructed commands: {len(reconstructed_commands)}")


if __name__ == "__main__":
    main()