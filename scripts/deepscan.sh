#!/bin/bash
# ==========================
#  GLOBAL CONFIGURATIONS
# ==========================
TARGET=""
OUTPUT_FILE="initial_scan.md"
WORDLIST_DIR="/usr/share/seclists/Discovery/Web-Content"
DIR_WORDLIST="$WORDLIST_DIR/directory-list-2.3-medium.txt"
FILE_WORDLIST="$WORDLIST_DIR/common.txt"
CREDENTIALS=(
    "/usr/share/seclists/Usernames/top-usernames-shortlist.txt"
    "/usr/share/seclists/Passwords/Common-Credentials/top-20-common-SSH-passwords.txt"
)

# ==========================
#  ASCII BANNER
# ==========================
print_banner() {
cat << "EOF"
██▓     ▒█████   ██▓        █     █░▓█████  ▄▄▄▄    ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓▓█████  ██▀███  
▓██▒    ▒██▒  ██▒▓██▒       ▓█░ █ ░█░▓█   ▀ ▓█████▄ ▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒██░    ▒██░  ██▒▒██░       ▒█░ █ ░█ ▒███   ▒██▒ ▄██▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
▒██░    ▒██   ██░▒██░       ░█░ █ ░█ ▒▓█  ▄ ▒██░█▀  ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄  
░██████▒░ ████▓▒░░██████▒   ░░██▒██▓ ░▒████▒░▓█  ▀█▓░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▓  ░   ░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░ ▒  ░  ░ ▒ ▒░ ░ ░ ▒  ░     ▒ ░ ░   ░ ░  ░▒░▒   ░  ▒ ░▒░ ░░░▒░ ░ ░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░▒▓░
  ░ ░   ░ ░ ░ ▒    ░ ░        ░   ░     ░    ░    ░  ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░         ░     ░░   ░ 
    ░  ░    ░ ░      ░  ░       ░       ░  ░ ░       ░  ░  ░   ░              ░             ░  ░   ░     
                         v1.3
EOF
}

show_help() {
    cat << EOF
OSCP Enumeration Script v2.3

Usage: $0 -ip <target_ip> [options]

Required:
  -ip <IP>         Target IP address to scan

Options:
  -createdir <DIR> Create output directory and store results
  -h               Show this help menu

Features:
  • Comprehensive port scanning (TCP/UDP)
  • Service-specific enumeration (FTP, SSH, SMTP, POP3, IMAP, SNMP, LDAP, MySQL, RDP, VNC, WinRM)
  • Automated vulnerability checks (via nmap scripts)
  • Auto-generated exploit checklist (if implemented)
  • Timed scan sections with duration tracking

Example:
  $0 -ip 10.10.10.123 -createdir target_data

Report Format:
  • Results saved in markdown format
  • Commands and outputs in code blocks
  • Critical findings highlighted at EOF
EOF
    exit 0
}

parse_arguments() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) show_help ;;
            -ip) TARGET="$2"; shift ;;
            -createdir)
                mkdir -p "$(dirname "$2")"
                OUTPUT_FILE="$2/initial_scan.md"
                touch "$OUTPUT_FILE"
                shift ;;
            *) echo "Unknown option: $1"; show_help ;;
        esac
        shift
    done
    [[ -z "$TARGET" ]] && { echo "Error: -ip required"; show_help; }
}

initialize_output() {
    {
        echo -e "# OSCP Enumeration Report\n"
        print_banner
        echo -e "\n**Target**: $TARGET"
        echo -e "**Started**: $(date)\n"
    } | tee "$OUTPUT_FILE"
    sync
}

finalize_output() {
    echo -e "\n**Completed**: $(date)" | tee -a "$OUTPUT_FILE"
    sed -i '/^$/N;/^\n$/D' "$OUTPUT_FILE"
    echo -e "\n# Report saved to: $OUTPUT_FILE" | tee -a "$OUTPUT_FILE"
}

timed_section() {
    local title="$1"
    local command="$2"
    local start_time=$(date +%s)
    local escaped_title
    escaped_title=$(printf '%s\n' "$title" | sed 's/[\/&]/\\&/g')
    
    {
        echo -e "\n## $title"
        echo -e "\n\`\`\`bash"
        echo "$command"
        echo -e "\`\`\`"
        echo -e "\n\`\`\`"
        eval "$command" 2>&1
        echo -e "\`\`\`"
    } | tee -a "$OUTPUT_FILE"
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    sed -i "s|## ${escaped_title}|## ${title} [${duration}s]|g" "$OUTPUT_FILE"
}

# ==========================
#  CORE SCANS (PHASE 1)
# ==========================
run_core_scans() {
    timed_section "Full TCP Port Scan (Aggressive)" "sudo nmap -Pn -p- -A -T4 $TARGET"
    timed_section "Safe Scripts Scan" "sudo nmap -Pn -sC -sV -p- $TARGET"
    timed_section "Top 20 UDP Port Scan" "sudo nmap -Pn -sU -sV -sC --top-ports=20 $TARGET"
}

# ==========================
#  SERVICE ENUMERATION (PHASE 2)
# ==========================
run_service_scans() {
    # Retrieve open TCP ports from the output file for further enumeration
    local open_ports
    open_ports=$(grep -E '^[0-9]+/tcp.*open' "$OUTPUT_FILE" | cut -d'/' -f1 | sort -un)
    
    for port in $open_ports; do
        case $port in
            21)  timed_section "FTP (Port 21)" "ftp_checks" ;;
            22)  timed_section "SSH (Port 22)" "ssh_checks" ;;
            23)  timed_section "SMTP (Port 25)" "smtp_checks" ;;
            24)  timed_section "DNS (Port 53)" "dns_checks" ;;
            25)  timed_section "HTTP (Port 80)" "web_checks 80" ;;
            26)  timed_section "Kerberos (Port 88)" "kerberos_checks" ;;
            27) timed_section "POP3 (Port 110)" "pop_checks" ;;
            28) timed_section "SMB (Port 139)" "smb_checks" ;;
            29) timed_section "IMAP (Port 143)" "imap_checks" ;;
            30) timed_section "SNMP (Port 161)" "snmp_checks" ;;
            31) timed_section "LDAP (Port 389)" "ldap_checks" ;;
            32) timed_section "HTTPS (Port 443)" "web_checks 443" ;;
            33) timed_section "SMB (Port 445)" "smb_checks" ;;
            34) timed_section "MySQL (Port 3306)" "mysql_checks" ;;
            35) timed_section "RDP (Port 3389)" "rdp_checks" ;;
            36) timed_section "VNC (Port 5900)" "vnc_checks" ;;
            37) timed_section "WinRM (Port 5985)" "winrm_checks" ;;
            *)    timed_section "Port $port" "generic_checks $port" ;;
        esac
    done
}

# ==========================
#  SERVICE CHECK FUNCTIONS
# ==========================

ftp_checks() {
    echo "FTP: Running banner and anonymous login check..."
    echo -e "open $TARGET 21\\nuser anonymous anonymous\\nls\\nquit" | ftp -n
    nmap -Pn -p21 --script="ftp-anon,ftp-syst" $TARGET
}

ssh_checks() {
    echo "SSH: Checking supported algorithms and host keys..."
    nmap -Pn -p22 --script="ssh2-enum-algos,ssh-hostkey,ssh-auth-methods" $TARGET
}

smtp_checks() {
    echo "SMTP: Enumerating commands and NTLM info..."
    nmap -Pn -p25 --script="smtp-commands,smtp-ntlm-info" $TARGET
    echo "SMTP: Attempting user enumeration using VRFY..."
    smtp-user-enum -M VRFY -t $TARGET -U /usr/share/wordlists/unix_users.txt
}

pop_checks() {
    echo "POP3: Running POP3 brute and information scan..."
    nmap -Pn -p110 --script="pop3-brute,pop3-info" $TARGET
    echo "POP3: (Optional) Use telnet for manual testing: telnet $TARGET 110"
}

imap_checks() {
    echo "IMAP: Running IMAP brute and information scan..."
    nmap -Pn -p143 --script="imap-brute,imap-info" $TARGET
    echo "IMAP (IMAPS): Try: openssl s_client -connect $TARGET:993 -crlf"
}

snmp_checks() {
    echo "SNMP: Scanning with nmap..."
    nmap -Pn -sU -p161 --script="snmp-brute,snmp-info" $TARGET
    echo "SNMP: Walking SNMP tree with snmpwalk..."
    snmpwalk -v1 -c public $TARGET
    echo "SNMP: Brute-forcing community strings with onesixtyone..."
    onesixtyone -c /usr/share/wordlists/snmp_default_pass.txt $TARGET
}

ldap_checks() {
    echo "LDAP: Scanning LDAP service..."
    nmap -Pn -p389 --script="ldap-rootdse,ldap-search" $TARGET
    echo "LDAP: Querying with ldapsearch (adjust base DN accordingly)..."
    ldapsearch -x -h $TARGET -b "dc=example,dc=com"
}

mysql_checks() {
    echo "MySQL: Scanning MySQL service..."
    nmap -Pn -p3306 --script="mysql-info,mysql-vuln-cve2012-2122" $TARGET
    echo "MySQL: Checking server status with mysqladmin..."
    mysqladmin -h $TARGET -u root -p status
}

rdp_checks() {
    echo "RDP: Scanning for RDP information..."
    nmap -Pn -p3389 --script="rdp-enum-encryption,rdp-vuln-ms12-020" $TARGET
    echo "RDP: Consider using rdesktop or xfreerdp to test connectivity."
}

vnc_checks() {
    echo "VNC: Scanning VNC service..."
    nmap -Pn -p5900 --script="vnc-info" $TARGET
    echo "VNC: Retrieving info with vncdotool..."
    vncdotool -s $TARGET:5900 info
}

winrm_checks() {
    echo "WinRM: Scanning for WinRM service..."
    nmap -Pn -p5985 --script="winrm-enum" $TARGET
    echo "WinRM: If you have credentials, consider using evil-winrm for further interaction."
}

generic_checks() {
    local port=$1
    echo "Generic: Running version detection on port $port..."
    nmap -Pn -sV -p $port $TARGET
    echo "Generic: Banner grabbing with netcat on port $port..."
    nc -nv $TARGET $port
}

dns_checks() {
    echo "DNS: Running DNS enumeration..."
    nmap -Pn -p53 --script="dns-recursion,dns-nsid" $TARGET
    echo "DNS: Attempting AXFR using dig..."
    dig axfr @$TARGET $TARGET
    echo "DNS: Reverse lookup using nslookup..."
    nslookup -query=ANY $TARGET $TARGET
}

web_checks() {
    local port=$1
    local proto
    proto=$([ $port -eq 443 ] && echo "https" || echo "http")
    echo "Web: Running directory brute force and vulnerability scans on $proto://$TARGET:$port..."
    gobuster dir -q -u $proto://$TARGET:$port -w $DIR_WORDLIST -t 40
    gobuster dir -q -u $proto://$TARGET:$port -w $FILE_WORDLIST -t 30 -x php,txt,html,zip,bak
    nikto -h $proto://$TARGET:$port
    whatweb --color=never $proto://$TARGET:$port
}

# ==========================
#  VULNERABILITY CHECKS (PHASE 3)
# ==========================
run_vulnerability_checks() {
    timed_section "Critical Vulnerability Scan" "nmap -Pn --script vulners,http-vuln-*,ssl-* $TARGET"
    timed_section "Credential Spraying" <<-EOF
	hydra -L ${CREDENTIALS[0]} -P ${CREDENTIALS[1]} ssh://$TARGET -t 4
	hydra -L ${CREDENTIALS[0]} -P ${CREDENTIALS[1]} ftp://$TARGET -t 4
	hydra -L ${CREDENTIALS[0]} -P ${CREDENTIALS[1]} smb://$TARGET -t 4
EOF
    # Optionally, generate an exploit checklist based on the findings.
    # generate_checklist
}

# ==========================
#  MAIN FUNCTION
# ==========================
main() {
    [[ $# -eq 0 ]] && show_help
    parse_arguments "$@"
    initialize_output
    run_core_scans
    run_service_scans
    run_vulnerability_checks
    finalize_output
}

# ==========================
#  EXECUTION
# ==========================
main "$@"
