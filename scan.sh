#!/usr/bin/env bash

# --------------------------------------------------------------
#   l0l_w3bhunter scanner - Enhanced for OSCP/CTF with Module Listing
#
#   Key Enhancements:
#    - Additional service-specific enumeration (SMB, FTP, CMS detection)
#    - Auto-generated summary report categorizing discovered ports/services,
#      which is prepended to the Markdown output (unless hidden via -hideReport).
#    - A -modular flag to run only selected modules, and a new -hide flag
#      to hide output of specified modules.
#    - A new -listModules flag that prints out the list of all available modules.
#    - Improved error handling and timeouts using the 'timeout' command.
#    - Hydra SSH brute forcing uses 32 threads (-t 32)
#    - Gobuster runs in quiet mode (-q) so only positive results are shown.
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

# Ports to skip (comma-separated), e.g., "80,443"
SKIP_PORTS=""

# Flags for output and module selection
HIDE_REPORT=false
MODULAR=""       # Comma-separated list of modules to run (if empty, run all)
HIDE_MODULES=""  # Comma-separated list of module keywords to hide output
LIST_MODULES=false

# Valid modules (for -modular and -listModules)
VALID_MODULES=("nmap" "gobuster" "curl" "nikto" "whatweb" "ftp" "smb" "ssh" "rdp" "wpscan")

# Declare an associative array for summary report
declare -A SUMMARY

# Arrays for tasks
declare -a TASKS_STAGE1=()  # Nmap + baseline tasks
declare -a TASKS_STAGE2=()  # Newly discovered ports
declare -a TASKS_WPSCAN=()  # WPScan tasks

# Track how many tasks fail
FAILED_TASKS=0

# Summaries (for tasks)
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

  -skip <PORTS>        Comma-separated list of ports to skip (e.g., 80,443)

  -modular <modules>   Comma-separated list of modules to run.
                       Valid modules: nmap, gobuster, curl, nikto, whatweb, ftp, smb, ssh, rdp, wpscan.
                       (If omitted, all modules run.)

  -hide <modules>      Comma-separated list of module keywords whose output
                       will be hidden. For example: -hide curl,whatweb

  -hideReport          Do not prepend the auto-generated summary report to the output.

  -listModules         List all valid modules and exit.

  -h, --help           Show this help menu and exit

Examples:
  \$0 -target 10.10.10.10
  \$0 -target 192.168.1.100 -createdir /home/user/MyScan
  \$0 -target 172.16.0.5 -modular nmap,ssh,rdp
  \$0 -target 10.10.10.10 -w /path/to/custom_wordlist.txt -threads 50 -skip 80,443 -hide curl,whatweb
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
EOF
}

# ==========================
#  HELPER FUNCTIONS
# ==========================
timestamp() {
  date "+%F %T"
}

should_skip_port() {
  if echo "$SKIP_PORTS" | grep -qw "$1"; then
    return 0
  else
    return 1
  fi
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

# Check if module output should be hidden based on -hide flag
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

generate_summary_report() {
  local report="## Auto-generated Summary Report\n\n"
  for service in "${!SUMMARY[@]}"; do
    report+="- Open ${service^^} ports: ${SUMMARY[$service]}\n"
  done
  echo -e "$report"
}

prepend_report() {
  if [ "$HIDE_REPORT" = false ]; then
    local report
    report=$(generate_summary_report)
    local tmp_file
    tmp_file=$(mktemp)
    echo -e "$report\n$(cat "$OUTPUT_FILE")" > "$OUTPUT_FILE"
  fi
}

# ==========================
#  TASK EXECUTION (Sequential)
# ==========================
run_single_task() {
  local title="$1"
  local cmd="$2"

  local start_time
  start_time=$(timestamp)

  echo "Running: $title (Start: $start_time)"
  echo "## $title (Started at $start_time)" >> "$OUTPUT_FILE"
  echo '```' >> "$OUTPUT_FILE"

  local raw
  raw=$(eval "$cmd" 2>&1)
  local rc=$?

  if module_hidden "$title"; then
    echo "Output hidden for module: $title" >> "$OUTPUT_FILE"
  else
    echo "$raw" >> "$OUTPUT_FILE"
  fi

  echo '```' >> "$OUTPUT_FILE"
  echo "" >> "$OUTPUT_FILE"

  local end_time
  end_time=$(timestamp)

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

  TASK_SUMMARY+="\n- [$title] finished at $end_time (Exit: $rc)"
}

run_all_tasks() {
  local -n arr_ref="$1"
  for item in "${arr_ref[@]}"; do
    IFS='|' read -r title cmd <<< "$item"
    run_single_task "$title" "$cmd"
  done
}

# ==========================
#  STAGE 2 PARSING (Nmap)
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

    if should_skip_port "$port"; then
      echo "Skipping discovered port $port as requested..."
      continue
    fi

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
#  GENERATE SUMMARY REPORT
# ==========================
generate_summary_report() {
  local report="## Auto-generated Summary Report\n\n"
  for service in "${!SUMMARY[@]}"; do
    report+="- Open ${service^^} ports: ${SUMMARY[$service]}\n"
  done
  echo -e "$report"
}

prepend_report() {
  if [ "$HIDE_REPORT" = false ]; then
    local report
    report=$(generate_summary_report)
    local tmp_file
    tmp_file=$(mktemp)
    echo -e "$report\n$(cat "$OUTPUT_FILE")" > "$OUTPUT_FILE"
  fi
}

# ==========================
#           MAIN
# ==========================
main() {
  print_banner

  if [[ $# -eq 0 ]]; then
    show_help
    exit 1
  fi

  # Process command-line arguments
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
      -skip)
        SKIP_PORTS="$2"
        shift
        ;;
      -hideReport)
        HIDE_REPORT=true
        ;;
      -modular)
        MODULAR="$2"
        shift
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

  # STAGE 1: Build tasks based on modules (if -modular is provided, only run those)
  TASKS_STAGE1+=("Nmap Full Port Scan|timeout 300 nmap -p- -sV -vv $TARGET | tee /tmp/nmap_temp")

  if ! should_skip_port "80"; then
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
  fi

  if ! should_skip_port "443"; then
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
  fi

  run_all_tasks TASKS_STAGE1

  # STAGE 2: Parse Nmap and queue tasks for discovered ports
  parse_nmap_and_queue_stage2

  if [[ ${#TASKS_STAGE2[@]} -gt 0 ]]; then
    echo "Additional open ports discovered. Running new tasks..."
    run_all_tasks TASKS_STAGE2
  fi

  if [[ ${#TASKS_WPSCAN[@]} -gt 0 ]]; then
    echo "WordPress detected. Running WPScan tasks..."
    run_all_tasks TASKS_WPSCAN
  fi

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
}

main "$@"
