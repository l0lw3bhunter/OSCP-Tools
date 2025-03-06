

---

```markdown
# OSCP Initial Scan Script

This is an automated reconnaissance tool designed for initial enumeration on target boxes in CTF environments. It performs a full TCP port scan with Nmap, runs multiple web enumeration modules (Gobuster, Curl, Nikto, WhatWeb), and conducts additional service-specific tasks (FTP, SMB, SSH with Hydra, RDP, etc.). The script also offers modular report generation, which creates separate Markdown files for each discovered service when used with the **-createdir** flag.

## Features

- **Full TCP Port Scan & Service Detection**  
  Uses Nmap to identify open ports and service details.

- **Web Enumeration**  
  Runs Gobuster scans for HTTP and HTTPS using a specified wordlist, Curl checks, Nikto vulnerability scans, and WhatWeb for CMS detection.  
  *The default Gobuster wordlist is:*
  ```
  /usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
  ```
  *Default Gobuster thread count is set to 50.*

- **Additional Service Tasks**  
  Based on Nmap results, it runs further tasks such as:
  - FTP enumeration (checks for anonymous login and lists files)
  - SMB enumeration via enum4linux
  - SSH auditing (with Hydra for default credential brute-forcing)
  - RDP and netcat banner grabbing

- **Modular Markdown Reports**  
  When the **-createdir** flag is used, the script creates a folder structure with the following directories:
  - **Enum**: Contains the main scan report (`Initial_scan.md`) and separate per-service reports (e.g., `80_http.md`, `21_ftp.md`, etc.).  
  - **Exploit**: Placeholder for exploitation findings.
  - **Privesc**: Placeholder for privilege escalation notes.
  
  The modular reports include raw output from individual modules (Gobuster output, FTP results, etc.) along with informative headers.

- **Enhanced Output Formatting**  
  - Durations are displayed in a formatted “Xm, Ys” style.
  - The overall scan summary is wrapped in triple backticks for a clean Markdown code block presentation.
  - Screenshots of web pages are automatically captured (if either `wkhtmltoimage` or `cutycapt` is available) when Gobuster finds subdirectories.

## Prerequisites

- A Debian-based system (e.g., Kali Linux)
- Required tools installed in your PATH:
  - `nmap`
  - `gobuster`
  - `curl`
  - `nikto`
  - `whatweb`
  - `ftp`
  - `enum4linux`
  - `hydra`
  - `netcat`
  - Optionally, `wkhtmltoimage` or `cutycapt` for screenshot capture
- Sudo privileges (for tasks that require elevated permissions)

## Installation

1. **Clone the repository or download the script directly:**
   ```bash
   git clone https://github.com/l0lw3bhunter/kalivm.git
   cd kalivm
   ```
   Or download the scan script directly:
   ```bash
   wget https://raw.githubusercontent.com/l0lw3bhunter/kalivm/main/scan.sh
   ```

2. **Make the script executable:**
   ```bash
   chmod +x scan.sh
   ```

## Usage

**Basic usage:**
```bash
./scan.sh -target <TARGET_IP>
```
Example:
```bash
./scan.sh -target 192.168.1.100
```

**Using the -createdir flag for Modular Reports:**

When you supply the **-createdir** flag, the script creates a folder structure with the following:
- `Enum/Initial_scan.md`: The overall scan report.
- `Enum/<port>_<service>.md`: Separate reports for each discovered service (e.g., `80_http.md`, `21_ftp.md`).
- `Exploit/Exploit.md` and `Privesc/Privesc.md`: Placeholders for further enumeration.

Example:
```bash
./scan.sh -target 192.168.1.100 -createdir /home/user/MyScanReports
```

**Additional Flags:**

- **`-modular <modules>`**: Run only the specified modules.  
  *Valid modules*: nmap, gobuster, curl, nikto, whatweb, ftp, smb, ssh, rdp, wpscan  
  Example: `-modular nmap,ssh,rdp`

- **`-hide <modules>`**: Hide output from the specified modules (comma-separated).  
  Example: `-hide curl,whatweb`

- **`-hideReport`**: Do not prepend the auto-generated overall summary report.

- **`-o <OUTPUT_FILE>`**: Specify a custom output file (overridden by -createdir).

- **`-w <WORDLIST>`**: Set a custom wordlist for Gobuster.

- **`-threads <NUMBER>`**: Set Gobuster's thread count.

- **`-ports <PORTS>`**: Run additional scans (Gobuster, Nikto, Curl, WhatWeb) on the specified ports.  
  Example: `-ports 8080,8888`

- **`-listModules`**: Lists all available modules and exits.

- **`-h, --help`**: Display help and exit.

**Example with Multiple Flags:**
```bash
./scan.sh -target 192.168.1.100 -createdir /home/user/MyScanReports -ports 8080,8888 -modular nmap,ssh,rdp -hide curl,whatweb -hideReport
```

## Output

The script generates an overall scan report in Markdown format that includes sections for:
- Nmap Scan results (open ports, OS detection, etc.)
- SSH Module results (including Hydra results)
- Gobuster Scan results (with details of discovered directories and screenshots)
- Nikto Scan results
- FTP Module results (with anonymous login status and file listings)
- CMS Detection

The overall summary is wrapped in triple backticks for neat formatting, and modular reports (if enabled) are created for each service.

## Disclaimer

This tool is intended for educational and authorized penetration testing use only. Unauthorized scanning of networks is illegal and unethical.

---

Happy scanning!
```

---

