# Network Security Scanner & Brute-Force Automation

## Overview

This script automates the process of scanning a given IP range for open services, performing brute-force attacks, 
and logging the results in a structured report. It utilizes **Nmap** for network scanning and **Hydra** for brute-force attacks. 
Additionally, successful logins are logged along with host details, permissions, and system architecture.

## Features

- Scans a given IP range for open ports and services.
- Uses Hydra for brute-force attacks on detected services (SSH, FTP).
- Detects system architecture upon successful authentication.
- Uploads and executes payloads if access is granted.
- Logs all findings, including timestamps, credentials, host data, and attack success rates.

## Installation

Ensure the following dependencies are installed:

```bash
sudo apt update && sudo apt install -y nmap hydra sshpass
```

## Usage
Create a user and password list to match the variables in the script.

USER_LIST="users.txt"

PASS_LIST="pass.txt"

create your owne payload for 32/64-bit and change the variables to match:
PAYLOAD="payloads/payload_64_4444.elf"
PAYLOAD="payloads/payload_32_4444.elf" 

Run the script with an IP range:

```bash
./scanner.sh <IP_RANGE>

```

Example:

```bash
./scanner.sh 192.168.1.0/24
```

## Output Files

- **Nmap Scan Results:** `nmap_scan/<epoch_time>_nmap.txt`
- **Hydra Brute-Force Logs:** `hydra_results/<epoch_time>_hydra.txt`
- **Matching Credentials:** `matching_credentials/<epoch_time>_matching_credentials.txt`
- **Full Scan Log:** `scan_log/<epoch_time>_scan.log`

## Disclaimer

This script is intended **for educational and security research purposes only**. 
Unauthorized use of this tool **against networks you do not own or have explicit permission to test** may be illegal and punishable by law.

By using this tool, you agree that the author is **not responsible** for any misuse, damages, or legal consequences resulting from its usage.


## **Use responsibly and ethically!**

