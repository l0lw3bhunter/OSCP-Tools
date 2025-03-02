#!/usr/bin/env bash

# --------------------------------------------------------------
#   l0l_w3bhunter scanner - Production-Ready Version with Dynamic Summary
#
#   Enhancements:
#    - Additional port scanning via -ports flag.
#    - Auto-generated overall summary report in the specified format,
#      with dynamic parsing of each module’s output.
#    - -modular flag to select modules; -hide flag to hide specified modules.
#    - Improved error handling with timeouts.
#    - Hydra SSH brute forcing uses 32 threads (-t 32).
#    - Gobuster runs in quiet mode (-q).
# --------------------------------------------------------------

# ==========================
#  CONFIG / DEFAULTS
# ==========================
DEFAULT_OUTPUT_FILE="scan_results.md"
OUTPUT_FILE="$DEFAULT_OUTPUT_FILE"

CREATEDIR_NAME=""
TARGET=""

# Gobuster defaults
GOBUSTER_WORDLIST="/usr/share/wordlists/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt"
GOBUSTER_THREADS="10"

# Additional ports flag (-ports), e.g.: "8080,1234"
ADDITIONAL_PORTS=""

# Flags for module selection and output hiding
HIDE_REPORT=false
MODULAR=""       # Comma-separated list of modules to run (if empty, run all)
HIDE_MODULES=""  # Comma-separated list of module keywords whose output will be hidden
LIST_MODULES=false

# Valid modules (for -modular and -listModules)
VALID_MODULES=("nmap" "gobuster" "curl" "nikto" "whatweb" "ftp" "smb" "ssh" "rdp" "wpscan")

# Global timing variables for overall scan
overall_start_fmt=""
overall_start_epoch=0
overall_end_fmt=""
overall_end_epoch=0
overall_duration=0

# Global summary variables (dynamically parsed)
nmap_duration=""
nmap_os_info=""
nmap_ports_info=""

ssh_duration=""
ssh_ports=""
hydra_summary=""

gobuster_http_duration=""
gobuster_https_duration=""
gobuster_http_results=""
gobuster_https_results=""

nikto_http_duration=""
nikto_https_duration=""
nikto_http_summary=""
nikto_https_summary=""

ftp_duration=""
ftp_status=""
ftp_findings=""

cms_duration=""
cms_details=""

# Declare an associative array for service summary (from Nmap)
declare -A SUMMARY

# Declare an associative array for Gobuster HTTP directories (keyed by port)
declare -A HTTP_DIRS

# Arrays for tasks
declare -a TASKS_STAGE1=()  # Nmap + baseline tasks
declare -a TASKS_STAGE2=()  # Tasks queued from Nmap parsing
declare -a TASKS_WPSCAN=()  # WPScan tasks (if any)
declare -a TASKS_ADDP=()    # Additional port scanning tasks from -ports flag

# Track how many tasks fail
FAILED_TASKS=0

# Module task summary (dynamically built)
TASK_SUMMARY=""

# ==========================
#   SHOW HELP (USAGE)
# ==========================
show_help() {
cat <<EOF
Usage: \$0 [OPTIONS]

Options:
  -target <IP>         Specify the target IP address to scan

  -createdir <PATH>    Create a folder structure at <PATH>:
                         <PATH>/Enum/Enum.md
                         <PATH>/Exploit/Exploit.md
                         <PATH>/Privesc/Privesc.md
                       Main scan results go to:
                         <PATH>/Enum/Initial_scan.md

  -o <OUTPUT_FILE>     Specify a custom output file (overridden by -createdir)

  -w <WORDLIST>        Provide a custom wordlist for Gobuster
                       (default: \$GOBUSTER_WORDLIST)

  -threads <NUMBER>    Gobuster thread count (default: \$GOBUSTER_THREADS)

  -ports <PORTS>       Comma-separated list of ports for additional HTTP scans.
                       (e.g., -ports 8080,1234)

  -modular <modules>   Comma-separated list of modules to run.
                       Valid modules: nmap, gobuster, curl, nikto, whatweb, ftp, smb, ssh, rdp, wpscan.
                       (If omitted, all modules run.)

  -hide <modules>      Comma-separated list of module keywords whose output
                       will be hidden. (e.g., -hide curl,whatweb)

  -hideReport          Do not prepend the auto-generated overall summary report.

  -listModules         List all valid modules and exit.

  -h, --help           Show this help menu and exit

Examples:
  \$0 -target 10.10.10.10
  \$0 -target 192.168.1.100 -createdir /home/user/MyScan
  \$0 -target 172.16.0.5 -modular nmap,ssh,rdp
  \$0 -target 10.10.10.10 -w /path/to/custom_wordlist.txt -threads 50 -ports 8080,1234 -hide curl,whatweb
  \$0 -listModules
EOF
}

# ==========================
#  ASCII ART BANNER
# ==========================
print_banner() {
cat << "EOF"
██▓     ▒█████   ██▓        █     █░▓█████  ▄▄▄▄    ██░ ██  █    ██  ███▄    █ ▄▄▄█████▓▓█████  ██▀███
▓██▒    ▒██▒  ██▒▓██▒       ▓█░ █ ░█░▓█   ▀ ▓█████▄ ▓██░ ██▒ ██  ▓██▒ ██ ▀█   █ ▓  ██▒ ▓▒▓█   ▀ ▓██ ▒ ██▒
▒██░    ▒██░  ██▒▒██░       ▒█░ █ ░█ ▒███   ▒██▒ ▄██▒██▀▀██░▓██  ▒██░▓██  ▀█ ██▒▒ ▓██░ ▒░▒███   ▓██ ░▄█ ▒
▒██░    ▒██   ██░▒██░       ░█░ █ ░█ ▒▓█  ▄ ▒██░█▀  ░▓█ ░██ ▓▓█  ░██░▓██▒  ▐▌██▒░ ▓██▓ ░ ▒▓█  ▄ ▒██▀▀█▄
░██████▒░ ████▓▒░░██████▒   ░░██▒██▓ ░▒████▒░▓█  ▀█▓░▓█▒░██▓▒▒█████▓ ▒██░   ▓██░  ▒██▒ ░ ░▒████▒░██▓ ▒██▒
░ ▒░▓  ░░ ▒░▒░▒░ ░ ▒░▓  ░   ░ ▓░▒ ▒  ░░ ▒░ ░░▒▓███▀▒ ▒ ░░▒░▒░▒▓▒ ▒ ▒ ░ ▒░   ▒ ▒   ▒ ░░   ░░ ▒░ ░░ ▒▓ ░▒▓░
░ ░ ▒  ░  ░ ▒ ▒░ ░ ░ ▒  ░     ▒ ░ ░   ░ ░  ░▒░▒   ░  ▒ ░▒░ ░░░▒░ ░ ░ ░ ░░   ░ ▒░    ░     ░ ░  ░  ░▒ ░▒▓░
  ░ ░   ░ ░ ░ ▒    ░ ░        ░   ░     ░    ░    ░  ░  ░░ ░ ░░░ ░ ░    ░   ░ ░   ░         ░     ░░   ░
    ░  ░    ░ ░      ░  ░       ░       ░  ░ ░       ░  ░  ░   ░              ░             ░  ░   ░
v1.0.3 - Oliver Jones
EOF
}

# ==========================
#  HELPER FUNCTIONS
# ==========================
timestamp() {
  date "+%F %T"
}

confirm_overwrite() {
  local path="$1"
  if [[ -e "$path" ]]; then
    echo "WARNING: $path already exists."
    read -rp "Do you want to overwrite? [y/N] " ans
    case "$ans" in
      [yY]) echo "Overwriting $path...";;
      *)    echo "Aborted."; exit 1;;
    esac
  fi
}

# Check if a module's output should be hidden based on the -hide flag
module_hidden() {
  local title_lower
  title_lower=$(echo "$1" | tr '[:upper:]' '[:lower:]')
  if [[ -n "$HIDE_MODULES" ]]; then
    IFS=',' read -ra hide_array <<< "$HIDE_MODULES"
    for h in "${hide_array[@]}"; do
      if echo "$title_lower" | grep -qw "$h"; then
        return 0
      fi
    done
  fi
  return 1
}

# ==========================
#  SUMMARY REPORT FUNCTIONS
# ==========================
declare -A SUMMARY
add_summary() {
  local service="$1"
  local port="$2"
  if [[ -z "${SUMMARY[$service]}" ]]; then
    SUMMARY[$service]="$port"
  else
    SUMMARY[$service]+=", $port"
  fi
}

generate_overall_summary() {
  local overall_summary
  overall_summary="==============================
SCAN SUMMARY
==============================
Start Time: ${overall_start_fmt}
Finish Time: ${overall_end_fmt}
Total Duration: ${overall_duration} sec

[Nmap Scan]
Duration: ${nmap_duration}
OS Detected: ${nmap_os_info}
Open Ports:
${nmap_ports_info}

[SSH Module]
Duration: ${ssh_duration}
- Open SSH Ports: ${ssh_ports}
- Hydra: ${hydra_summary}

[Gobuster Scan]
Duration: ${gobuster_http_duration} (HTTP), ${gobuster_https_duration} (HTTPS)
- HTTP Ports:
${gobuster_http_results}
- HTTPS Ports:
${gobuster_https_results}

[Nikto Scan]
Duration: ${nikto_http_duration} (HTTP), ${nikto_https_duration} (HTTPS)
- HTTP: ${nikto_http_summary}
- HTTPS: ${nikto_https_summary}

[FTP Module]
Duration: ${ftp_duration}
- Anonymous Login: ${ftp_status}
- Files/Directories found: ${ftp_findings}

[CMS Detection]
Duration: ${cms_duration}
- CMS Detected: ${cms_details}
=============================="
  echo -e "$overall_summary"
}

prepend_report() {
  if [ "$HIDE_REPORT" = false ]; then
    local overall_summary
    overall_summary=$(generate_overall_summary)
    local tmp_file
    tmp_file=$(mktemp)
    echo -e "$overall_summary\n\n$(cat "$OUTPUT_FILE")" > "$OUTPUT_FILE"
  fi
}

# ==========================
#  TASK EXECUTION (Sequential)
# ==========================
run_single_task() {
  local title="$1"
  local cmd="$2"

  local start_time_fmt
  start_time_fmt=$(date "+%F %T")
  local start_time_epoch
  start_time_epoch=$(date +%s)

  echo "Running: $title (Start: $start_time_fmt)"
  echo "## $title (Started at $start_time_fmt)" >> "$OUTPUT_FILE"
  echo '```' >> "$OUTPUT_FILE"

  local raw
  raw=$(eval "$cmd" 2>&1)
  local rc=$?

  # If this is a Gobuster HTTP task, capture directory output
  if [[ "$title" =~ ^Gobuster\ \(HTTP\ on\ port ]]; then
    local clean_output
    clean_output=$(echo "$raw" | sed -r 's/\x1B\[[0-9;]*[mK]//g')
    local dirs
    dirs=$(echo "$clean_output" | grep "^/")
    local port_number
    port_number=$(echo "$title" | sed -r 's/.*on port ([0-9]+).*/\1/')
    HTTP_DIRS["$port_number"]="$dirs"
  fi

  if module_hidden "$title"; then
    echo "Output hidden for module: $title" >> "$OUTPUT_FILE"
  else
    echo "$raw" >> "$OUTPUT_FILE"
  fi

  echo '```' >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  local end_time_fmt
  end_time_fmt=$(date "+%F %T")
  local end_time_epoch
  end_time_epoch=$(date +%s)
  local duration=$(( end_time_epoch - start_time_epoch ))

  # --- Dynamic Parsing Based on Task Title ---

  if [[ "$title" == "Nmap Full Port Scan" ]]; then
    nmap_duration="${duration} sec"
    nmap_os_info=$(echo "$raw" | grep -i "OS details:" | head -n1 | cut -d: -f2 | xargs)
    if [ -z "$nmap_os_info" ]; then
      nmap_os_info="Not detected"
    fi
    nmap_ports_info=$(echo "$raw" | grep -E "^[0-9]+/tcp" | awk '{$1=$1};1' | sed 's/^/  - /')
  fi

  if [[ "$title" =~ ^SSH\  && "$title" =~ Hydra ]]; then
    # For Hydra tasks, parse for success/failure messages.
    if echo "$raw" | grep -qi "login:"; then
      hydra_summary="Credentials found: $(echo "$raw" | grep -i "login:" | head -n1 | xargs)"
    else
      hydra_summary="Default credentials not found"
    fi
    ssh_duration="${duration} sec"
    local port_found
    port_found=$(echo "$title" | grep -oE '[0-9]+')
    ssh_ports="${ssh_ports} ${port_found}"
  fi

  if [[ "$title" =~ ^Gobuster\ \(HTTP ]]; then
    gobuster_http_duration="${duration} sec"
    # Append directories for this port to gobuster_http_results:
    local port_number
    port_number=$(echo "$title" | sed -r 's/.*on port ([0-9]+).*/\1/')
    local dirs
    dirs=$(echo "${HTTP_DIRS[$port_number]}" | tr '\n' ', ' | sed 's/, $//')
    if [ -z "$dirs" ]; then
      dirs="No directories found"
    fi
    gobuster_http_results+="- Port ${port_number}: Directories found: ${dirs}\n"
  fi

  if [[ "$title" =~ ^Gobuster\ \(HTTPS ]]; then
    gobuster_https_duration="${duration} sec"
    # For HTTPS Gobuster, similar parsing (assuming output similar to HTTP)
    local port_number
    port_number=$(echo "$title" | sed -r 's/.*on port ([0-9]+).*/\1/')
    local dirs
    dirs=$(echo "$raw" | sed -r 's/\x1B\[[0-9;]*[mK]//g' | grep "^/" | tr '\n' ', ' | sed 's/, $//')
    if [ -z "$dirs" ]; then
      dirs="No directories found"
    fi
    gobuster_https_results+="- Port ${port_number}: Directories found: ${dirs}\n"
  fi

  if [[ "$title" =~ ^Nikto\ \(HTTP ]]; then
    nikto_http_duration="${duration} sec"
    nikto_http_summary=$(echo "$raw" | grep -i "Target IP:" | head -n1 | cut -d: -f2- | xargs)
    if [ -z "$nikto_http_summary" ]; then
      nikto_http_summary="No significant issues"
    fi
  fi
  if [[ "$title" =~ ^Nikto\ \(HTTPS ]]; then
    nikto_https_duration="${duration} sec"
    nikto_https_summary=$(echo "$raw" | grep -i "Target IP:" | head -n1 | cut -d: -f2- | xargs)
    if [ -z "$nikto_https_summary" ]; then
      nikto_https_summary="No significant issues"
    fi
  fi

  if [[ "$title" =~ ^FTP ]]; then
    ftp_duration="${duration} sec"
    if echo "$raw" | grep -qi "230"; then
       ftp_status="Allowed"
    else
       ftp_status="Disallowed"
    fi
    ftp_findings=$(echo "$raw" | grep -v "^ftp>" | tr '\n' ', ' | sed 's/, $//')
  fi

  if [[ "$title" =~ ^WhatWeb ]]; then
    # For WhatWeb, check for CMS keywords.
    if echo "$raw" | grep -qi "wordpress"; then
      cms_duration="${duration} sec"
      cms_details="WordPress detected on port $(echo "$title" | grep -oE '[0-9]+')"
    elif echo "$raw" | grep -qi "joomla"; then
      cms_duration="${duration} sec"
      cms_details="Joomla detected on port $(echo "$title" | grep -oE '[0-9]+')"
    elif echo "$raw" | grep -qi "drupal"; then
      cms_duration="${duration} sec"
      cms_details="Drupal detected on port $(echo "$title" | grep -oE '[0-9]+')"
    else
      cms_duration="${duration} sec"
      cms_details="No CMS detected"
    fi
  fi

  if [[ $rc -ne 0 ]]; then
    if [[ "$title" == *"Nikto"* ]] && echo "$raw" | grep -Eq "0 error\(s\) and [0-9]+ item\(s\) reported on remote host"; then
      echo "(Nikto exit code 1 is normal in this scenario—treating as success.)" >> "$OUTPUT_FILE"
      rc=0
    else
      echo "**Command [$title] failed with exit code $rc.**" >> "$OUTPUT_FILE"
      echo "Error lines (if any):" >> "$OUTPUT_FILE"
      echo "$raw" | grep -i "error" >> "$OUTPUT_FILE"
      echo "" >> "$OUTPUT_FILE"
      ((FAILED_TASKS++))
    fi
  fi

  # Append a line to TASK_SUMMARY for this module
  TASK_SUMMARY+="\n[$title] finished at ${end_time_fmt} (Duration: ${duration} sec, Exit: $rc)"
  echo "Finished: $title (Duration: ${duration} sec, Exit: $rc)"
}

run_all_tasks() {
  local -n arr_ref="$1"
  for item in "${arr_ref[@]}"; do
    IFS='|' read -r title cmd <<< "$item"
    run_single_task "$title" "$cmd"
  done
}

# ==========================
#  STAGE 2: Nmap Parsing
# ==========================
parse_nmap_and_queue_stage2() {
  if [[ ! -f /tmp/nmap_temp ]]; then
    echo "Error: /tmp/nmap_temp not found. Did Nmap run?"
    exit 1
  fi

  local NMAP_RESULT
  NMAP_RESULT="$(cat /tmp/nmap_temp)"
  rm -f /tmp/nmap_temp

  echo "## Parsed Nmap Results" >> "$OUTPUT_FILE"
  echo '```' >> "$OUTPUT_FILE"
  echo "$NMAP_RESULT" >> "$OUTPUT_FILE"
  echo '```' >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  local open_ports
  open_ports=$(echo "$NMAP_RESULT" | grep -E "^[0-9]+/tcp\s+open")

  while IFS= read -r line; do
    local port service
    port="$(echo "$line" | cut -d'/' -f1)"
    service="$(echo "$line" | awk '{print $3}' | tr '[:upper:]' '[:lower:]')"
    add_summary "$service" "$port"

    # Ports 80 and 443 are handled in Stage 1
    if [[ "$port" == "80" || "$port" == "443" ]]; then
      continue
    fi

    case "$service" in
      ftp)
        TASKS_STAGE2+=(
          "FTP Anonymous on port $port|echo 'open $TARGET $port
user anonymous anonymous
ls
quit' | ftp -n"
        )
        ;;
      microsoft-ds|netbios-ssn|smb)
        TASKS_STAGE2+=(
          "SMB Enum on port $port|timeout 120 enum4linux -a $TARGET"
        )
        ;;
      ssh)
        TASKS_STAGE2+=(
          "SSH Audit on port $port|timeout 120 ssh-audit $TARGET:$port"
          "SSH Hydra on port $port (default creds)|timeout 120 hydra -L /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt -P /usr/share/wordlists/seclists/Passwords/Default-Credentials/ssh-betterdefaultpasslist.txt ssh://$TARGET -s $port -t 32"
        )
        ;;
      ms-wbt-server|rdp)
        TASKS_STAGE2+=(
          "RDP Enum on port $port|nmap -p $port --script rdp-enum-encryption $TARGET"
        )
        ;;
      http*)
        echo "Detected additional HTTP port: $port - scanning now..."
        TASKS_STAGE2+=(
          "Curl (HTTP on port $port)|timeout 60 curl -sSf http://$TARGET:$port -m 30 || echo 'Curl (HTTP) failed on port $port'"
          "WhatWeb (HTTP on port $port)|timeout 60 whatweb http://$TARGET:$port"
          "Nikto (HTTP on port $port)|timeout 300 nikto -h http://$TARGET:$port"
          "Gobuster (HTTP on port $port)|timeout 300 gobuster dir -q -u http://$TARGET:$port -w $GOBUSTER_WORDLIST -t $GOBUSTER_THREADS"
        )
        ;;
      https*|ssl*|tls*)
        TASKS_STAGE2+=(
          "Curl (HTTPS on port $port)|timeout 60 curl -sSf -k https://$TARGET:$port -m 30 || echo 'Curl (HTTPS) failed on port $port'"
          "WhatWeb (HTTPS on port $port)|timeout 60 whatweb https://$TARGET:$port"
          "Nikto (HTTPS on port $port)|timeout 300 PERL_LWP_SSL_VERIFY_HOSTNAME=0 nikto -h https://$TARGET:$port"
          "Gobuster (HTTPS on port $port)|timeout 300 gobuster dir -q -u https://$TARGET:$port -w $GOBUSTER_WORDLIST -k -t $GOBUSTER_THREADS"
        )
        ;;
      *)
        TASKS_STAGE2+=(
          "Netcat Banner Grab on port $port ($service)|echo | nc -nv $TARGET $port -w 3"
        )
        ;;
    esac

  done <<< "$open_ports"
}

# ==========================
#  ADDITIONAL PORT SCANNING TASKS
# ==========================
build_additional_port_tasks() {
  if [[ -n "$ADDITIONAL_PORTS" ]]; then
    IFS=',' read -ra port_array <<< "$ADDITIONAL_PORTS"
    for p in "${port_array[@]}"; do
      TASKS_ADDP+=(
        "Curl (HTTP on port $p)|timeout 60 curl -sSf http://$TARGET:$p -m 30 || echo 'Curl (HTTP) failed on port $p'"
        "WhatWeb (HTTP on port $p)|timeout 60 whatweb http://$TARGET:$p"
        "Nikto (HTTP on port $p)|timeout 300 nikto -h http://$TARGET:$p"
        "Gobuster (HTTP on port $p)|timeout 300 gobuster dir -q -u http://$TARGET:$p -w $GOBUSTER_WORDLIST -t $GOBUSTER_THREADS"
      )
    done
    run_all_tasks TASKS_ADDP
  fi
}

# ==========================
#  OVERALL SUMMARY GENERATION
# ==========================
generate_overall_summary() {
  local overall_summary
  overall_summary="==============================
SCAN SUMMARY
==============================
Start Time: ${overall_start_fmt}
Finish Time: ${overall_end_fmt}
Total Duration: ${overall_duration} sec

[Nmap Scan]
Duration: ${nmap_duration}
OS Detected: ${nmap_os_info}
Open Ports:
${nmap_ports_info}

[SSH Module]
Duration: ${ssh_duration}
- Open SSH Ports: ${ssh_ports}
- Hydra: ${hydra_summary}

[Gobuster Scan]
Duration: HTTP: ${gobuster_http_duration}, HTTPS: ${gobuster_https_duration}
- HTTP Ports:
${gobuster_http_results}
- HTTPS Ports:
${gobuster_https_results}

[Nikto Scan]
Duration: HTTP: ${nikto_http_duration}, HTTPS: ${nikto_https_duration}
- HTTP: ${nikto_http_summary}
- HTTPS: ${nikto_https_summary}

[FTP Module]
Duration: ${ftp_duration}
- Anonymous Login: ${ftp_status}
- Files/Directories found: ${ftp_findings}

[CMS Detection]
Duration: ${cms_duration}
- CMS Detected: ${cms_details}
=============================="
  echo -e "$overall_summary"
}

prepend_report() {
  if [ "$HIDE_REPORT" = false ]; then
    local overall_summary
    overall_summary=$(generate_overall_summary)
    local tmp_file
    tmp_file=$(mktemp)
    echo -e "$overall_summary\n\n$(cat "$OUTPUT_FILE")" > "$OUTPUT_FILE"
  fi
}

# ==========================
#           MAIN
# ==========================
main() {
  print_banner

  overall_start_fmt=$(date "+%F %T")
  overall_start_epoch=$(date +%s)

  if [[ $# -eq 0 ]]; then
    show_help
    exit 1
  fi

  while [[ "$#" -gt 0 ]]; do
    case "$1" in
      -h|--help)
        show_help
        exit 0
        ;;
      -listModules)
        echo "Valid modules:"
        for mod in "${VALID_MODULES[@]}"; do
          echo " - $mod"
        done
        exit 0
        ;;
      -target)
        TARGET="$2"
        shift
        ;;
      -createdir)
        CREATEDIR_NAME="$2"
        shift
        ;;
      -o)
        OUTPUT_FILE="$2"
        shift
        ;;
      -w)
        GOBUSTER_WORDLIST="$2"
        shift
        ;;
      -threads)
        GOBUSTER_THREADS="$2"
        shift
        ;;
      -ports)
        ADDITIONAL_PORTS="$2"
        shift
        ;;
      -modular)
        MODULAR="$2"
        shift
        ;;
      -hideReport)
        HIDE_REPORT=true
        ;;
      -hide)
        HIDE_MODULES="$2"
        shift
        ;;
      *)
        echo "Unknown parameter passed: $1"
        exit 1
        ;;
    esac
    shift
  done

  if [[ -z "$TARGET" ]]; then
    echo "Error: Target IP not provided. Use -target <IP>"
    exit 1
  fi

  if [[ -n "$CREATEDIR_NAME" ]]; then
    if [[ -d "$CREATEDIR_NAME" ]]; then
      confirm_overwrite "$CREATEDIR_NAME"
    fi
    mkdir -p "$CREATEDIR_NAME"/{Enum,Exploit,Privesc}
    touch "$CREATEDIR_NAME"/Enum/Enum.md
    touch "$CREATEDIR_NAME"/Exploit/Exploit.md
    touch "$CREATEDIR_NAME"/Privesc/Privesc.md
    OUTPUT_FILE="$CREATEDIR_NAME/Enum/Initial_scan.md"
  else
    confirm_overwrite "$OUTPUT_FILE"
  fi

  echo "# Initial Scan Results for $TARGET" > "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"
  echo "Script started at: $(timestamp)" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  # STAGE 1: Build tasks based on modules
  TASKS_STAGE1+=("Nmap Full Port Scan|timeout 300 nmap -p- -sV -vv $TARGET | tee /tmp/nmap_temp")

  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)gobuster(,|$) ]]; then
    TASKS_STAGE1+=("Gobuster (HTTP)|timeout 300 gobuster dir -q -u http://$TARGET -w $GOBUSTER_WORDLIST -t $GOBUSTER_THREADS")
  fi
  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)curl(,|$) ]]; then
    TASKS_STAGE1+=("Curl (HTTP)|timeout 60 curl -sSf http://$TARGET -m 30 || echo 'Curl (HTTP) failed to connect'")
  fi
  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)nikto(,|$) ]]; then
    TASKS_STAGE1+=("Nikto (HTTP)|timeout 300 nikto -h http://$TARGET")
  fi
  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)whatweb(,|$) ]]; then
    TASKS_STAGE1+=("WhatWeb (HTTP)|timeout 60 whatweb http://$TARGET")
  fi

  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)gobuster(,|$) ]]; then
    TASKS_STAGE1+=("Gobuster (HTTPS)|timeout 300 gobuster dir -q -u https://$TARGET -w $GOBUSTER_WORDLIST -k -t $GOBUSTER_THREADS")
  fi
  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)curl(,|$) ]]; then
    TASKS_STAGE1+=("Curl (HTTPS)|timeout 60 curl -sSf -k https://$TARGET -m 30 || echo 'Curl (HTTPS) failed to connect'")
  fi
  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)nikto(,|$) ]]; then
    TASKS_STAGE1+=("Nikto (HTTPS)|timeout 300 PERL_LWP_SSL_VERIFY_HOSTNAME=0 nikto -h https://$TARGET")
  fi
  if [[ -z "$MODULAR" || "$MODULAR" =~ (^|,)whatweb(,|$) ]]; then
    TASKS_STAGE1+=("WhatWeb (HTTPS)|timeout 60 whatweb https://$TARGET")
  fi

  run_all_tasks TASKS_STAGE1

  # STAGE 2: Parse Nmap and queue tasks for discovered ports
  parse_nmap_and_queue_stage2

  if [[ ${#TASKS_STAGE2[@]} -gt 0 ]]; then
    echo "Additional open ports discovered. Running new tasks..."
    run_all_tasks TASKS_STAGE2
  fi

  # STAGE 3: Additional port scanning via -ports flag
  build_additional_port_tasks

  if [[ ${#TASKS_WPSCAN[@]} -gt 0 ]]; then
    echo "WordPress detected. Running WPScan tasks..."
    run_all_tasks TASKS_WPSCAN
  fi

  overall_end_fmt=$(date "+%F %T")
  overall_end_epoch=$(date +%s)
  overall_duration=$(( overall_end_epoch - overall_start_epoch ))

  prepend_report

  echo "Script finished at: $(timestamp)" >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  echo "## Task Summary" >> "$OUTPUT_FILE"
  echo '```' >> "$OUTPUT_FILE"
  echo -e "$TASK_SUMMARY" >> "$OUTPUT_FILE"
  echo '```' >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  local total_tasks=$(( ${#TASKS_STAGE1[@]} + ${#TASKS_STAGE2[@]} + ${#TASKS_WPSCAN[@]} ))
  echo "Scan completed. Results saved in $OUTPUT_FILE."
  echo "Total tasks run: $total_tasks"
  echo "Failed tasks: $FAILED_TASKS"

  echo ""
  echo "OVERALL SCAN SUMMARY:"
  echo "---------------------"
  generate_overall_summary
}

main "$@"
