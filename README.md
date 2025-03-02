Below is a reformatted version of the README file with consistent formatting throughout. This version includes clear headings, code blocks, and step‐by‐step instructions on how to download and run the script.

---


# Kali Linux Setup Script

This script sets up your Kali Linux environment by performing the following tasks:
- **Creates directories** in your `~/Documents` folder: `Apps`, `Boxes`, `Tools`, and `VPNs`.
- **Downloads AppImages** for Obsidian and Caido into the `~/Documents/Apps` directory.
- **Sets execute permissions** on the downloaded AppImages so they can be run as programs.
- **Updates and upgrades** your system packages.

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

2. **Run the setup script:**
   ```bash
   sudo ./setup.sh
   ```

## Downloading and Running the scan.sh Script

The `scan.sh` script is an automated reconnaissance tool designed for initial enumeration on target boxes in CTF/OSCP environments.

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

**Additional Flags:**

- **`-modular <modules>`**: Run only the specified modules.
- **`-hide <modules>`**: Hide output from the specified modules.
- **`-hideReport`**: Do not prepend the auto-generated summary report.
- **`-hide <modules>`**: Hide output of specified modules (inverse of -modular).
- **`-threads <NUMBER>`**: Set Gobuster's thread count.
- **`-w <WORDLIST>`**: Set a custom wordlist for Gobuster.
- **`-listModules`**: Lists all available modules.
- **`-ports`**: Runs additional gobuster, nikto, curl and whatweb scans on the ports specified.

**Example with Additional Flags:**
```bash
./scan.sh -target 192.168.1.100 -ports 8080,8888 -modular nmap,ssh,rdp -hide curl,whatweb -hideReport
```
