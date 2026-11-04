#!/usr/bin/env bash
# ==============================================================================
# server_webshell_rootkit_audit.sh
# Production-Grade Linux/VPS/cPanel Webshell, RCE & Rootkit Auditor
# ==============================================================================
# Audits 8 critical security vectors across PHP/MySQL web server environments:
#   1. PHP Webshell, RCE & Obfuscation Signature Scanner
#   2. Rogue Executable Scripts in Static/Upload Directories
#   3. Recently Modified Code & Config Files (Past 7 Days)
#   4. .htaccess Hijacking & auto_prepend_file Injections
#   5. PHP Runtime Hardening & PHP2Shell (session.upload_progress) Audit
#   6. Persistence Check (Crontabs, SSH Keys & Rogue Running Processes)
#   7. Active Network Sockets & Userland Rootkit (LD_PRELOAD) Checks
#   8. File Permission Audit (World-Writable Executable & Env Files)
# ==============================================================================

set -u

# Target Webroot Path (defaults to $HOME if not supplied)
WEBROOT="${1:-$HOME}"

# Timestamp & Log Files
TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
LOGFILE="./server_security_audit_${TIMESTAMP}.log"
CONSOLE_LOG="./console_execution_${TIMESTAMP}.log"
JSON_REPORT="./server_security_audit_${TIMESTAMP}.json"
PORTAL_URL="${PORTAL_URL:-http://127.0.0.1:8888}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || echo ".")"

# Auto-Start Local Remediation Portal if Not Running
if command -v python3 >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/portal_server.py" ]; then
    if ! curl -s --connect-timeout 1 "$PORTAL_URL/api/health" >/dev/null 2>&1; then
        python3 "$SCRIPT_DIR/portal_server.py" >/dev/null 2>&1 &
        sleep 2
    fi
elif command -v python >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/portal_server.py" ]; then
    if ! curl -s --connect-timeout 1 "$PORTAL_URL/api/health" >/dev/null 2>&1; then
        python "$SCRIPT_DIR/portal_server.py" >/dev/null 2>&1 &
        sleep 2
    fi
fi

# Counters
ALERT_COUNT=0
WARN_COUNT=0
INFO_COUNT=0

# Colors for terminal output
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m' # No Color

# Helper Logging Function
log_entry() {
    local level="$1"
    local message="$2"
    local timestamp
    timestamp="$(date +'%Y-%m-%d %H:%M:%S')"
    local plain_line="[$timestamp] [$level] $message"

    case "$level" in
        "HEADER")
            echo -e "\n${CYAN}================================================================================${NC}"
            echo -e "${CYAN} $message${NC}"
            echo -e "${CYAN}================================================================================${NC}"
            echo -e "\n================================================================================\n $message\n================================================================================" >> "$LOGFILE"
            echo -e "\n================================================================================\n $message\n================================================================================" >> "$CONSOLE_LOG"
            ;;
        "SECTION")
            echo -e "\n${CYAN}--- [MODULE: $message] ---${NC}"
            echo -e "\n--- [MODULE: $message] ---" >> "$LOGFILE"
            echo -e "\n--- [MODULE: $message] ---" >> "$CONSOLE_LOG"
            ;;
        "ALERT")
            echo -e "${RED}[-] ${plain_line}${NC}"
            echo "[-] ${plain_line}" >> "$LOGFILE"
            echo "[-] ${plain_line}" >> "$CONSOLE_LOG"
            ALERT_COUNT=$((ALERT_COUNT + 1))
            ;;
        "WARN")
            echo -e "${YELLOW}[!] ${plain_line}${NC}"
            echo "[!] ${plain_line}" >> "$LOGFILE"
            echo "[!] ${plain_line}" >> "$CONSOLE_LOG"
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        "OK")
            echo -e "${GREEN}[+] ${plain_line}${NC}"
            echo "[+] ${plain_line}" >> "$LOGFILE"
            echo "[+] ${plain_line}" >> "$CONSOLE_LOG"
            INFO_COUNT=$((INFO_COUNT + 1))
            ;;
        "INFO")
            echo -e "${GRAY}[*] ${plain_line}${NC}"
            echo "[*] ${plain_line}" >> "$LOGFILE"
            echo "[*] ${plain_line}" >> "$CONSOLE_LOG"
            INFO_COUNT=$((INFO_COUNT + 1))
            ;;
    esac
}

# Start Banner
log_entry "HEADER" "LINUX VPS & cPanel PHP WEBSHELL, RCE & ROOTKIT AUDIT TOOLKIT"
log_entry "INFO" "Target Webroot Directory: $WEBROOT"
log_entry "INFO" "Auditing Hostname       : $(hostname -f 2>/dev/null || hostname)"
log_entry "INFO" "Execution User          : $(whoami) (UID: $(id -u))"
log_entry "INFO" "Audit Log File Path     : $LOGFILE"
log_entry "INFO" "Audit Start Timestamp   : $(date -u +'%Y-%m-%d %H:%M:%S UTC')"

if [ ! -d "$WEBROOT" ]; then
    log_entry "ALERT" "Specified target path does not exist: $WEBROOT"
    exit 1
fi

# ==============================================================================
# MODULE 1: PHP Webshell, RCE & Obfuscation Signature Scanner
# ==============================================================================
log_entry "SECTION" "1. PHP Webshell, RCE & Obfuscation Signature Scanner"

# High-Risk Signatures Array
patterns=(
    'eval\s*\(\s*(base64_decode|gzinflate|str_rot13|gzuncompress|hex2bin)'
    'shell_exec\s*\('
    'passthru\s*\('
    'system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)'
    'proc_open\s*\('
    'popen\s*\('
    'assert\s*\(\s*\$_(GET|POST|REQUEST)'
    'preg_replace\s*\(.*\/e'
    'create_function\s*\('
    'move_uploaded_file.*\$_(GET|POST).*\.php'
)

matched_signatures=0
temp_scan_output=$(mktemp)

for pat in "${patterns[@]}"; do
    # Run ripgrep or standard grep across PHP-related file extensions
    grep -rnE --include="*.php" --include="*.phtml" --include="*.php5" --include="*.php7" --include="*.inc" --include="*.phar" "$pat" "$WEBROOT" 2>/dev/null >> "$temp_scan_output" || true
done

if [ -s "$temp_scan_output" ]; then
    matched_signatures=$(wc -l < "$temp_scan_output")
    log_entry "ALERT" "Potential PHP Webshell / RCE primitives detected! Found $matched_signatures signature match(es):"
    while IFS= read -r line; do
        log_entry "ALERT" "  -> $line"
    done < "$temp_scan_output"
else
    log_entry "OK" "No dangerous high-risk PHP evaluation or unconstrained execution primitives found."
fi
rm -f "$temp_scan_output"

# ==============================================================================
# MODULE 2: Rogue Executable Scripts in Static/Upload Directories
# ==============================================================================
log_entry "SECTION" "2. Rogue Executable Scripts in Static/Upload Directories"

temp_upload_matches=$(mktemp)

# Find directories matching upload/media/cache/assets/tmp patterns
find "$WEBROOT" -type d \( \
    -iname "*upload*" -o \
    -iname "*images*" -o \
    -iname "*media*" -o \
    -iname "*assets*" -o \
    -iname "*cache*" -o \
    -iname "*tmp*" \
\) 2>/dev/null | while IFS= read -r upload_dir; do
    # Search for executable script extensions inside this static folder
    find "$upload_dir" -type f \( \
        -name "*.php*" -o \
        -name "*.phtml" -o \
        -name "*.phar" -o \
        -name "*.py" -o \
        -name "*.sh" -o \
        -name "*.pl" -o \
        -name "*.cgi" \
    \) 2>/dev/null >> "$temp_upload_matches" || true
done

if [ -s "$temp_upload_matches" ]; then
    rogue_count=$(wc -l < "$temp_upload_matches")
    log_entry "ALERT" "HIGH RISK: Found $rogue_count executable script(s) in static/upload directories (Common Webshell Staging Vector):"
    while IFS= read -r file_path; do
        file_meta=$(ls -lh "$file_path" 2>/dev/null || echo "$file_path")
        log_entry "ALERT" "  -> $file_meta"
    done < "$temp_upload_matches"
else
    log_entry "OK" "No executable scripts (.php, .phtml, .sh, .py, etc.) found in static or upload directories."
fi
rm -f "$temp_upload_matches"

# ==============================================================================
# MODULE 3: Recently Modified Code & Config Files (Past 7 Days)
# ==============================================================================
log_entry "SECTION" "3. Recently Modified Code & Config Files (Past 7 Days)"

temp_modified=$(mktemp)
find "$WEBROOT" -type f \( \
    -name "*.php*" -o \
    -name ".htaccess" -o \
    -name "*.js" -o \
    -name "*.env*" -o \
    -name "*config*" \
\) -mtime -7 2>/dev/null > "$temp_modified" || true

if [ -s "$temp_modified" ]; then
    mod_count=$(wc -l < "$temp_modified")
    log_entry "WARN" "Found $mod_count recently modified script/config file(s) within the last 7 days:"
    while IFS= read -r f; do
        if ls --time-style=long-iso -lh "$f" >/dev/null 2>&1; then
            meta=$(ls --time-style=long-iso -lh "$f")
        else
            meta=$(ls -lh "$f")
        fi
        log_entry "WARN" "  -> $meta"
    done < "$temp_modified"
else
    log_entry "OK" "No code or configuration files were modified in the past 7 days."
fi
rm -f "$temp_modified"

# ==============================================================================
# MODULE 4: .htaccess Hijacking & auto_prepend_file Injections
# ==============================================================================
log_entry "SECTION" "4. .htaccess Hijacking & auto_prepend_file Injections"

htaccess_matches=$(mktemp)
find "$WEBROOT" -type f -name ".htaccess" 2>/dev/null | while IFS= read -r ht; do
    grep -HnEi '(auto_prepend_file|auto_append_file|AddType.*php|SetHandler.*php|RewriteCond.*HTTP_REFERER.*(google|bing|yahoo|yandex))' "$ht" 2>/dev/null >> "$htaccess_matches" || true
done

if [ -s "$htaccess_matches" ]; then
    log_entry "ALERT" "CRITICAL: Suspicious .htaccess directives detected (Execution trapping or SEO redirect cloaking):"
    while IFS= read -r line; do
        log_entry "ALERT" "  -> $line"
    done < "$htaccess_matches"
else
    log_entry "OK" "All .htaccess configurations inspected; no auto_prepend, mime-type overrides, or SEO cloaking rules found."
fi
rm -f "$htaccess_matches"

# ==============================================================================
# MODULE 5: PHP Runtime Hardening & PHP2Shell (session.upload_progress) Audit
# ==============================================================================
log_entry "SECTION" "5. PHP Runtime Hardening & PHP2Shell Audit"

if command -v php >/dev/null 2>&1; then
    php_version=$(php -v | head -n 1)
    log_entry "INFO" "Active PHP CLI: $php_version"

    # Check session.upload_progress.enabled (PHP2Shell LFI-to-RCE vector)
    upload_prog=$(php -r 'echo ini_get("session.upload_progress.enabled");' 2>/dev/null || echo "1")
    if [ "$upload_prog" = "1" ] || [ "$upload_prog" = "On" ] || [ "$upload_prog" = "on" ]; then
        log_entry "ALERT" "PHP session.upload_progress.enabled is ON! (Exploitable via PHP2Shell LFI-to-RCE race condition)."
        log_entry "WARN"  "  Remediation: Set 'session.upload_progress.enabled = 0' in php.ini."
    else
        log_entry "OK" "PHP session.upload_progress.enabled is Disabled (0)."
    fi

    # Check allow_url_include
    url_inc=$(php -r 'echo ini_get("allow_url_include");' 2>/dev/null || echo "0")
    if [ "$url_inc" = "1" ] || [ "$url_inc" = "On" ] || [ "$url_inc" = "on" ]; then
        log_entry "ALERT" "CRITICAL: allow_url_include is ON! Remote File Inclusion (RFI) attacks are permitted."
        log_entry "WARN"  "  Remediation: Set 'allow_url_include = Off' in php.ini."
    else
        log_entry "OK" "allow_url_include is securely disabled."
    fi

    # Check disable_functions
    disabled_fn=$(php -r 'echo ini_get("disable_functions");' 2>/dev/null || echo "")
    log_entry "INFO" "Configured disable_functions: ${disabled_fn:-[NONE]}"

    # Verify critical execution primitives are disabled
    crit_primitives=("exec" "passthru" "shell_exec" "system" "proc_open" "popen")
    missing_disabled=()
    for prim in "${crit_primitives[@]}"; do
        if ! echo "$disabled_fn" | grep -qw "$prim"; then
            missing_disabled+=("$prim")
        fi
    done

    if [ ${#missing_disabled[@]} -gt 0 ]; then
        log_entry "WARN" "The following dangerous execution functions are NOT disabled in php.ini: ${missing_disabled[*]}"
    else
        log_entry "OK" "All standard dangerous execution functions are blocked in disable_functions."
    fi

    # Check expose_php
    expose_php=$(php -r 'echo ini_get("expose_php");' 2>/dev/null || echo "1")
    if [ "$expose_php" = "1" ] || [ "$expose_php" = "On" ]; then
        log_entry "WARN" "expose_php is ON (Leaks PHP version headers). Recommended: expose_php = Off"
    fi
else
    log_entry "WARN" "PHP CLI binary ('php') is not found in PATH; skipping runtime php.ini inspection."
fi

# ==============================================================================
# MODULE 6: Persistence Check (Crontabs, SSH Keys & Rogue Processes)
# ==============================================================================
log_entry "SECTION" "6. Persistence Check (Crontabs, SSH Keys & Rogue Processes)"

# Check user crontab
log_entry "INFO" "Checking crontab entries for $(whoami):"
user_cron=$(crontab -l 2>/dev/null || true)
if [ -n "$user_cron" ]; then
    echo "$user_cron" | while IFS= read -r cron_line; do
        if echo "$cron_line" | grep -qiE '(curl|wget|python|perl|bash|sh|socat|nc|/tmp/|/dev/shm)'; then
            log_entry "ALERT" "Suspicious crontab entry detected: $cron_line"
        else
            log_entry "INFO" "  Cron entry: $cron_line"
        fi
    done
else
    log_entry "OK" "No user crontab entries configured."
fi

# Check system crontabs if readable
if [ -r /etc/crontab ]; then
    log_entry "INFO" "Auditing /etc/crontab for anomalous tasks..."
    grep -v '^#' /etc/crontab | grep -v '^[[:space:]]*$' | while IFS= read -r line; do
        if echo "$line" | grep -qiE '(curl|wget|python|perl|bash|sh|socat|nc|/tmp/|/dev/shm)'; then
            log_entry "ALERT" "Suspicious system crontab line: $line"
        fi
    done
fi

# Check SSH Authorized Keys
auth_keys_path="$HOME/.ssh/authorized_keys"
if [ -f "$auth_keys_path" ]; then
    key_count=$(wc -l < "$auth_keys_path")
    log_entry "INFO" "Found $key_count authorized SSH key(s) in $auth_keys_path:"
    while IFS= read -r key_line; do
        [ -z "$key_line" ] && continue
        # Print key type and comment/trailing identity
        key_type=$(echo "$key_line" | awk '{print $1}')
        key_comment=$(echo "$key_line" | awk '{$1=""; $2=""; print $0}' | sed 's/^[ \t]*//')
        log_entry "INFO" "  -> Key: $key_type | Identity: ${key_comment:-[No Comment]}"
    done < "$auth_keys_path"
else
    log_entry "OK" "No $auth_keys_path found for current user."
fi

# Check Running Processes for reverse shells and rogue temp executions
log_entry "INFO" "Auditing running processes for rogue execution paths and reverse shells..."
ps_threat_found=0
ps_output=$(ps aux 2>/dev/null || ps -ef 2>/dev/null || true)

if [ -n "$ps_output" ]; then
    echo "$ps_output" | while IFS= read -r ps_line; do
        # Check if process is running from /tmp, /var/tmp, or /dev/shm
        if echo "$ps_line" | grep -qE '(/tmp/|/var/tmp/|/dev/shm/)'; then
            log_entry "ALERT" "Process executing from temp staging filesystem: $ps_line"
            ps_threat_found=1
        fi
        # Check for reverse shell command patterns
        if echo "$ps_line" | grep -qE '(nc\s+-e|bash\s+-i|socat\s+exec|python.*-c.*socket|perl.*-e.*socket|curl.*\|.*(bash|sh)|wget.*\|.*(bash|sh))'; then
            log_entry "ALERT" "Reverse shell invocation detected in process tree: $ps_line"
            ps_threat_found=1
        fi
    done
fi

# ==============================================================================
# MODULE 7: Active Network Sockets & Userland Rootkit (LD_PRELOAD) Checks
# ==============================================================================
log_entry "SECTION" "7. Active Network Sockets & Userland Rootkit (LD_PRELOAD) Checks"

# Check /etc/ld.so.preload
if [ -f /etc/ld.so.preload ]; then
    if [ -s /etc/ld.so.preload ]; then
        log_entry "ALERT" "CRITICAL ROOTKIT INDICATOR: /etc/ld.so.preload exists and is NON-EMPTY!"
        while IFS= read -r preload_entry; do
            log_entry "ALERT" "  -> Injected Library: $preload_entry"
        done < /etc/ld.so.preload
    else
        log_entry "OK" "/etc/ld.so.preload exists but is 0 bytes."
    fi
else
    log_entry "OK" "/etc/ld.so.preload does not exist (Normal)."
fi

# Check environment LD_PRELOAD
if [ -n "${LD_PRELOAD:-}" ]; then
    log_entry "ALERT" "CRITICAL: Active LD_PRELOAD environment variable detected: $LD_PRELOAD"
else
    log_entry "OK" "Environment LD_PRELOAD is empty."
fi

# Audit Listening & Established Sockets
log_entry "INFO" "Active listening and established sockets:"
if command -v ss >/dev/null 2>&1; then
    ss -tulnp 2>/dev/null | head -n 25 | while IFS= read -r sock_line; do
        log_entry "INFO" "  $sock_line"
    done
elif command -v netstat >/dev/null 2>&1; then
    netstat -tulnp 2>/dev/null | head -n 25 | while IFS= read -r sock_line; do
        log_entry "INFO" "  $sock_line"
    done
else
    log_entry "WARN" "Neither 'ss' nor 'netstat' available to query network sockets."
fi

# ==============================================================================
# MODULE 8: File Permission Audit (World-Writable Files)
# ==============================================================================
log_entry "SECTION" "8. File Permission Audit (World-Writable Code & Config)"

world_writable_matches=$(mktemp)
find "$WEBROOT" -type f \( \
    -name "*.php*" -o \
    -name "*.sh" -o \
    -name "*.env*" -o \
    -name ".htaccess" \
\) -perm -0002 2>/dev/null > "$world_writable_matches" || true

if [ -s "$world_writable_matches" ]; then
    ww_count=$(wc -l < "$world_writable_matches")
    log_entry "ALERT" "Found $ww_count world-writable executable/config file(s) (Arbitrary Overwrite / Injection Vector):"
    while IFS= read -r ww_file; do
        perm_meta=$(ls -lh "$ww_file")
        log_entry "ALERT" "  -> $perm_meta"
    done < "$world_writable_matches"
    log_entry "WARN" "Remediation: chmod 644 on files and chmod 755 on directories (find $WEBROOT -type f -exec chmod 644 {} +)."
else
    log_entry "OK" "No world-writable code, script, or environment files detected in $WEBROOT."
fi
rm -f "$world_writable_matches"

# ==============================================================================
# EXECUTIVE SUMMARY & REMEDIATION NEXT STEPS
# ==============================================================================
log_entry "HEADER" "SERVER COMPROMISE AUDIT SUMMARY"
log_entry "INFO" "Total Critical Alerts [ALERT] : $ALERT_COUNT"
log_entry "INFO" "Total Warnings         [WARN]  : $WARN_COUNT"
log_entry "INFO" "Total Informational    [INFO]  : $INFO_COUNT"

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "\n${RED}${BOLD}[!] HIGH RISK COMPROMISE DETECTED!${NC}"
    echo -e "${YELLOW}Immediate Server Remediation Actions:${NC}"
    echo -e "  1. Block suspicious IP connections at the firewall (iptables / ufw / cloud security groups)."
    echo -e "  2. Quarantine rogue webshell files immediately (move outside webroot or chmod 000)."
    echo -e "  3. Lock down static upload directories in .htaccess with '<FilesMatch \"\\.(php.*|phar|sh|py|cgi)$\">Require all denied</FilesMatch>'."
    echo -e "  4. Set 'session.upload_progress.enabled = 0' and 'allow_url_include = Off' in php.ini."
    echo -e "  5. Refer to cyber_defense_playbook.pdf for comprehensive VPS containment workflow."
else
    echo -e "\n${GREEN}${BOLD}[+] SERVER HEALTH CLEAN:${NC} No critical webshells, rogue upload scripts, or rootkits detected."
    echo -e "    Ensure periodic scanning and enforce PHP runtime hardening in production."
fi

log_entry "INFO" "Audit report saved to: $LOGFILE"
log_entry "INFO" "Raw console execution log saved to: $CONSOLE_LOG"

# ==============================================================================
# REPORT EXPORT & AUTOMATED PORTAL UPLOAD
# ==============================================================================
if command -v python3 >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/portal_server.py" ]; then
    python3 -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); import portal_server, json; rep = portal_server.parse_raw_text_report(open('$LOGFILE', encoding='utf-8', errors='ignore').read()); rep['console_log'] = open('$CONSOLE_LOG', encoding='utf-8', errors='ignore').read(); print(json.dumps(rep, indent=2))" > "$JSON_REPORT" 2>/dev/null || true
elif command -v python >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/portal_server.py" ]; then
    python -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); import portal_server, json; rep = portal_server.parse_raw_text_report(open('$LOGFILE', encoding='utf-8', errors='ignore').read()); rep['console_log'] = open('$CONSOLE_LOG', encoding='utf-8', errors='ignore').read(); print(json.dumps(rep, indent=2))" > "$JSON_REPORT" 2>/dev/null || true
fi

if [ -s "$JSON_REPORT" ]; then
    log_entry "OK" "Structured JSON scan report generated at: $JSON_REPORT"
    if curl -s --connect-timeout 2 "$PORTAL_URL/api/health" >/dev/null 2>&1; then
        upload_resp=$(curl -s -X POST -H "Content-Type: application/json" -d @"$JSON_REPORT" "$PORTAL_URL/api/upload_report" 2>/dev/null || true)
        echo -e "\n${GREEN}================================================================================${NC}"
        echo -e "${GREEN} [+] AUDIT REPORT TRANSMITTED TO REMEDIATION PORTAL${NC}"
        echo -e "${GREEN}================================================================================${NC}"
        echo -e " Open the Cyber Defense Portal to view interactive threat analysis & fix guides:"
        echo -e " Portal URL: ${CYAN}${PORTAL_URL}${NC}"
        echo -e " Log files available:"
        echo -e "   - Structured Report : ${JSON_REPORT}"
        echo -e "   - Human Report      : ${LOGFILE}"
        echo -e "   - Console Log       : ${CONSOLE_LOG}"
        echo -e "${GREEN}================================================================================${NC}\n"
    else
        log_entry "INFO" "Local remediation portal not online. Start manually with: python portal_server.py"
        log_entry "INFO" "Then drag & drop $JSON_REPORT or $CONSOLE_LOG into the dashboard."
    fi
else
    # Fallback to posting raw log text if python was unavailable
    if curl -s --connect-timeout 2 "$PORTAL_URL/api/health" >/dev/null 2>&1; then
        curl -s -X POST -H "Content-Type: application/json" --data-binary "{\"raw_log\": $(python3 -c 'import json, sys; print(json.dumps(open(sys.argv[1]).read()))' "$CONSOLE_LOG" 2>/dev/null || python3 -c 'import json, sys; print(json.dumps(open(sys.argv[1]).read()))' "$LOGFILE" 2>/dev/null || echo '""')}" "$PORTAL_URL/api/upload_report" >/dev/null 2>&1 || true
    fi
fi

exit 0

