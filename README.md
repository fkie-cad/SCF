# SCF — SMB Command Fingerprinting

Reconstruct **file operations** from SMB network traffic by matching command **sequences + parameters** to SCF rulesets.

---

## What is SCF?

**SCF (SMB Command Fingerprinting)** turns raw SMB packets into higher‑level events (e.g., `mkdir`, `rename`, `del`, `copy`) by hashing the **stable, semantically relevant fields** of each SMB command and then matching **sequences of these hashes** against SCF rules.

---

## Limitations & notes

- Works when **SMB headers/payloads are visible**: fully encrypted sessions (e.g., SMB 3 encryption/QUIC without keys) conceal fields needed for CFs. 
- **Caching** may suppress network I/O for some actions (`cd ..`), so not all operations yield traffic.  

---

## Status & getting the code

This repository is currently being **refactored**.  
If you need access now, please email **jan-niclas.hilgert@fkie.fraunhofer.de**.

---

## Reference

If you use SCF in research or tooling, please cite:

- Hilgert, J.-N., Mahr, A., Lambertz, M. “Mount SMB.pcap: Reconstructing file systems and file operations from network traffic,” *Forensic Science International: Digital Investigation* 50 (2024) 301807. https://doi.org/10.1016/j.fsidi.2024.301807

