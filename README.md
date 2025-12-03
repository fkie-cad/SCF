# SMB Command Fingerprinting

SMB Command Fingerprinting (SCF) is a network forensics technique that reconstructs file operations and identifies the specific applications that generated SMB traffic. By analyzing sequences of SMB commands and matching them against predefined signatures, SCF can determine which application performed which actions, directly from packet captures without access to endpoints.


> Based on: [Advancing Event Reconstruction in Network Forensics: Extending and Evaluating SMB Command Fingerprinting (ACM 2025)](https://dl.acm.org/doi/10.1145/3712716.3712723) and [Mount SMB.pcap: Reconstructing file systems and file operations from network traffic (ScienceDirect 2024)](https://www.sciencedirect.com/science/article/pii/S2666281724001318)
--- 




## python/
The Python implementation uses Scapy for SMB packet parsing.


##### Requirements
```
colorama==0.4.6
colorlog==6.10.1
impacket==0.13.0
scapy==2.6.1
```
Install required dependencies:
```
pip install -r requirements.txt
```

##### Usage

```
python main.py /path/to/capture.pcap /path/to/rules.tsv
```

Hash-only mode (outputs command hashes without pattern matching):
```
python main.py /path/to/capture.pcap --hash-only
```



##### Project structure

```
├── main.py                     # Main executable script
├── reconstructed_commands.txt  # Output file with results
├── requirements.txt            # Python package dependencies
├── analysis/                   # Analysis-related modules
├── config/                     # Configuration files
├── logs/                       # Log file storage
├── models/                     # Class definitions for SMB commands
├── parsers/                    # Data processing modules
└── utils/                      # Utility functions
```


##### Output

- **Standard mode**: Results are written to `reconstructed_commands.txt`

    Example entry:

    | Timestamp | Source IP | Application | Description | Filename/Path |
    |---|---|---|---|---|
    | 2025-11-27 21:36:20 | 192.168.206.62 | smbclient | Creation of directory | testdir |

- **Hash-only mode**: Hashes are written to `smb_hashes.txt`

    Example entry:

    | Packet Number | Command | Request Type | Hash |
    |---|---|---|---|
    | 1 | CREATE | REQUEST | a1b2c3d4e5f6... |

---
## zeek/

The Zeek implementation follows the same functional approach as the Python version, with key differences:

- Instead of using external libraries, this script operates directly at the TCP bit level.
- Zeek's architecture enables real-time traffic analysis alongside offline PCAP processing.

##### Usage


```
zeek -C -r /path/to/capture.pcap smbcommandfingerprinting.zeek SMBCommandFingerprinting::RULE_FILE=path/to/rules.tsv
```


Optional debug mode:
```
zeek -C -r /path/to/capture.pcap smbcommandfingerprinting.zeek SMBCommandFingerprinting::RULE_FILE=path/to/rules.tsv SMBCommandFingerprinting::DEBUG_MODE=T
```

Optional hash-only mode (logs hashes without pattern matching):
```
zeek -C -r /path/to/capture.pcap smbcommandfingerprinting.zeek SMBCommandFingerprinting::HASH_ONLY_MODE=T
```

##### Output
- **Standard mode**: Results are written to `reconstructed_commands.log`

    Example entry:

    | Timestamp | Connection ID | Source IP | Source Port | Destination IP | Destination Port | Application | Description | Filename |
    |---|---|---|---|---|---|---|---|---|
    | 1764275817.795940 | CnMgaF1p7EnYZTX6kc | 192.168.206.62 | 54272 | 192.168.2.139 | 445 | smbclient | Creating a directory using mkdir | testdir |

- **Hash-only mode**: Hashes are written to `smb_hashes.log`

    Example entry:

    | Packet Number | Command | Request Type | Hash |
    |---|---|---|---|
    | 123 | CREATE | REQUEST | e26ab3635920a9977c21009a4edf8f01 |


---
## rules/
The `*-rules.tsv` files serve as a unified rule database used by both the Python and Zeek implementations:

- Compatible with both analysis engines.
- Can be manually extended with custom rules.

You need to specify a rule file when starting an analysis. 

---
## examples/
The examples/ folder contains sample PCAP files with corresponding ground truth data for testing purposes.

---

## Limitations & notes
- Works when SMB headers/payloads are visible: fully encrypted sessions (e.g., SMB 3 encryption/QUIC without keys) conceal fields needed for CFs.
- Caching may suppress network I/O for some actions (cd ..), so not all operations yield traffic.

---

## Reference

If you use SCF in research or tooling, please cite:

- Hilgert, J.-N., Mahr, A., Lambertz, M. “Mount SMB.pcap: Reconstructing file systems and file operations from network traffic,” *Forensic Science International: Digital Investigation* 50 (2024) 301807. https://doi.org/10.1016/j.fsidi.2024.301807