Below is the updated README.md file reflecting the current state of the script. It preserves the original structure for downloading, installing, and running the tool while incorporating details about the new features such as modular per‐service reports, formatted durations, and screenshot capture. Note that the script is now described as an automated reconnaissance tool for initial enumeration in CTF/box environments (without mentioning any specific certification).

---

```markdown
# Recon Scan Script

This script is an automated reconnaissance tool designed for initial enumeration on target boxes in CTF and similar environments. It performs a full TCP port scan, service enumeration, and then runs various modules (e.g., Gobuster, Curl, Nikto, WhatWeb, FTP, SMB, SSH with Hydra, RDP, and WPScan) to gather as much information as possible about the target.

In addition, if you use the **-createdir** flag, the script will create a folder structure with modular per‑service Markdown reports (e.g., `Enum/80_http.md`, `Enum/21_ftp.md`) where the output of each module is neatly stored. The overall scan summary is also included (wrapped in triple backticks) and durations are formatted as “Xm, Ys”.

## Prerequisites

- A Debian-based system (e.g., Kali Linux)
- An active internet connection
- `wget` installed (usually pre-installed on Kali Linux)
- Sudo privileges

## Installation

1. **Clone this repository:**
   ```bash
   git clone https://github.com/l0lw3bhunter/kalivm.git
   cd kalivm
   ```

2. **Run the setup script (if needed):**
   ```bash
   sudo ./setup.sh
   ```

## Downloading and Running the scan.sh Script

The `scan.sh` script is an automated reconnaissance tool that performs initial enumeration of a target. It supports multiple modules (such as Nmap, Gobuster, Curl, Nikto, WhatWeb, FTP, SMB, SSH, RDP, and WPScan) and can generate modular reports if desired.

### Download

If the script is hosted in this repository, simply navigate to it. Otherwise, download it directly:
```bash
wget https://raw.githubusercontent.com/l0lw3bhunter/kalivm/main/scan.sh
```

### Make the Script Executable

Ensure the script has execute permissions:
```bash
chmod +x scan.sh
```

### Running the Script

**Basic usage:**
```bash
./scan.sh -target <TARGET_IP>
```
For example, to scan a target with IP `192.168.1.100`:
```bash
./scan.sh -target 192.168.1.100
```

### Additional Flags

- **`-createdir <PATH>`**:  
  Create a folder structure at the specified path. This will create subdirectories:
  - `Enum` (which will include `Initial_scan.md` and per‑service reports like `80_http.md`, `21_ftp.md`, etc.)
  - `Exploit`
  - `Privesc`
  
- **`-o <OUTPUT_FILE>`**:  
  Specify a custom output file (overridden by -createdir).

- **`-w <WORDLIST>`**:  
  Set a custom wordlist for Gobuster (default:  
  `/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt`).

- **`-threads <NUMBER>`**:  
  Set the Gobuster thread count (default: 50).

- **`-ports <PORTS>`**:  
  Run additional Gobuster, Nikto, Curl, and WhatWeb scans on the specified comma-separated ports (e.g., `8080,1234`).

- **`-modular <modules>`**:  
  Run only the specified modules. Valid modules are:  
  `nmap, gobuster, curl, nikto, whatweb, ftp, smb, ssh, rdp, wpscan`.

- **`-hide <modules>`**:  
  Hide output from the specified modules.

- **`-hideReport`**:  
  Do not prepend the auto-generated overall summary report.

- **`-listModules`**:  
  List all valid modules and exit.

- **`-h` or `--help`**:  
  Show this help menu and exit.

### Example with Additional Flags

```bash
./scan.sh -target 192.168.1.100 -ports 8080,8888 -modular nmap,ssh,rdp -hide curl,whatweb -hideReport
```

## Output Details

- **Main Report:**  
  The primary output is saved as either the file specified with `-o` or (if `-createdir` is used) in the `Enum/Initial_scan.md` file within the created folder structure. The overall scan summary is wrapped in triple backticks for neat Markdown formatting.

- **Modular Reports:**  
  If you use the `-createdir` flag, separate Markdown files will be generated for each discovered service (for example, `80_http.md` for HTTP on port 80). These files contain the raw output of the corresponding module (e.g., Gobuster results with discovered subdirectories and, if available, screenshots) as well as additional details such as FTP file listings.

- **Duration Format:**  
  Task durations and the overall scan time are displayed in a “Xm, Ys” format (e.g., “2m, 30s”).

Enjoy using the script for your initial reconnaissance tasks!
```

---

This updated README now reflects the latest version of the script with all the restored flags and features, along with a clear explanation of the output formats and how to use the tool.
