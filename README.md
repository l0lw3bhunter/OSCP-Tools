
# OSCP Enumeration Script

A comprehensive Bash tool for automating enumeration and vulnerability scanning tasks during penetration testing and OSCP labs/exams.

> **Disclaimer:** This tool is for educational purposes and authorized testing only. Use it responsibly and only on systems you are permitted to assess.

## Description

The OSCP Enumeration Script automates various scanning and enumeration tasks such as:
- **Core Scans:** Performs an aggressive full TCP port scan, safe script scan, and a top-20 UDP port scan using Nmap.
- **Service Enumeration:** Detects open ports from scan results and automatically runs service-specific enumeration for FTP, SSH, SMTP, POP3, IMAP, SNMP, LDAP, MySQL, RDP, VNC, WinRM, DNS, and web services.
- **Vulnerability Checks:** Runs additional vulnerability scans using Nmap NSE scripts and credential spraying via Hydra.
- **Report Generation:** Creates a Markdown report (`initial_scan.md`) with banners, timestamps, and detailed output from each scan.

## Features

- **Automated Workflow:** Sequential phases covering core scans, service enumeration, and vulnerability checks.
- **Service-Specific Enumeration:** Custom functions to enumerate common services (FTP, SSH, SMTP, etc.).
- **Output Report:** Saves results in a well-structured Markdown file with timing details.
- **Customizable:** Global configuration variables (target IP, output file, wordlists, credentials) can be adjusted.

## Requirements

- **Operating System:** Linux (Kali Linux is recommended)
- **Shell:** Bash
- **Tools and Dependencies:**
  - **Nmap** (with NSE scripts)
  - **Hydra** (for credential spraying)
  - **FTP client** (for FTP checks)
  - **Gobuster** (for directory and file brute-forcing)
  - **Nikto** and **WhatWeb** (for web vulnerability scanning)
  - **Netcat (`nc`)**
  - **snmpwalk**, **onesixtyone**, **ldapsearch**, **mysqladmin** (for service enumeration)
  - **SecLists** (wordlists are used from `/usr/share/seclists/Discovery/Web-Content`)

## Installation

1. **Clone the repository:**

   ```bash
   git clone https://github.com/l0lw3bhunter/OSCP-Tools.git
   cd OSCP-Tools/scripts
   ```

2. **Install the required tools:**

   For Debian-based systems (e.g., Kali Linux), run:
   
   ```bash
   sudo apt update
   sudo apt install nmap hydra ftp gobuster nikto whatweb netcat snmpwalk ldap-utils mysql-client seclists
   ```

3. **Verify the SecLists directory exists:**

   Ensure that `/usr/share/seclists/Discovery/Web-Content` is present. If not, install or update the `seclists` package.

## Usage

Run the script by providing the target IP. The script requires at least the `-ip` option.

```bash
./deepscan.sh -ip <target_ip> [options]
```

### Options

- `-ip <target_ip>`  
  **Required.** Specifies the target IP address for scanning.

- `-createdir <DIR>`  
  (Optional) Creates the specified output directory and saves the report as `initial_scan.md` inside that directory.

- `-h` or `--help`  
  Displays the help menu with usage instructions.

### Example

```bash
./deepscan.sh -ip 10.10.10.123 -createdir target_data
```

This command sets the target to `10.10.10.123`, creates a directory named `target_data` (if it doesn’t exist), and saves the Markdown report in that directory.

## How It Works

1. **Initialization:**
   - Parses command-line arguments.
   - Displays an ASCII banner and help menu if requested.
   - Initializes the output file with target details and start time.

2. **Core Scans (Phase 1):**
   - **Aggressive TCP Scan:** Uses Nmap with aggressive options.
   - **Safe Scripts Scan:** Runs a safer scan with default scripts.
   - **UDP Scan:** Scans the top 20 UDP ports.

3. **Service Enumeration (Phase 2):**
   - Reads open TCP ports from the initial report.
   - Runs service-specific functions for each recognized port (e.g., FTP, SSH, SMTP, etc.).

4. **Vulnerability Checks (Phase 3):**
   - Executes Nmap vulnerability scripts.
   - Performs credential spraying using Hydra against services like SSH, FTP, and SMB.

5. **Finalization:**
   - Appends a completion timestamp and tidies up the report.

## Customization

- **Global Configuration:**  
  Edit variables at the top of the script to change the target, output file, or wordlist directories.
- **Credential Lists:**  
  Update the paths in the `CREDENTIALS` array if you wish to use different username/password wordlists.
- **Service Functions:**  
  Extend or modify service check functions (e.g., `ftp_checks`, `ssh_checks`, etc.) to fit your testing needs.

## Contributing

Contributions, suggestions, and improvements are welcome. Feel free to open issues or submit pull requests to enhance this tool.

## License

Distributed under the [MIT License](LICENSE).
