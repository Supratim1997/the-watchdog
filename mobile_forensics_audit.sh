#!/usr/bin/env bash
# ==============================================================================
# mobile_forensics_audit.sh
# Mobile Endpoint Forensics & Spyware (MVT / Pegasus / Predator) Orchestrator
# ==============================================================================
# Automates comprehensive forensic acquisition and threat hunting for:
#   - Android devices via ADB & Mobile Verification Toolkit (mvt-android)
#   - Apple iOS devices via libimobiledevice & MVT (mvt-ios)
#
# Audits:
#   1. Android Verified Boot State (AVB) & SELinux Enforcement
#   2. Root detection (su binaries & permissions)
#   3. Abusive Accessibility Services (Keyloggers & Stalkerware)
#   4. Active Device Admin applications (Anti-Uninstall persistence)
#   5. Sideloaded 3rd-party packages (Non-Google Play origin)
#   6. Rogue User-Installed Root CA Certificates (TLS MITM Interception)
#   7. Active network listening sockets
#   8. Automated MVT STIX2 IOC matching (Pegasus, Predator, Cytrox)
#   9. Full iOS forensic backup extraction & MVT database artifact audit
# ==============================================================================

set -u

TIMESTAMP="$(date +'%Y%m%d_%H%M%S')"
OUT_DIR="./mobile_forensics_${TIMESTAMP}"
mkdir -p "$OUT_DIR"
SUMMARY_LOG="${OUT_DIR}/mobile_audit_summary.txt"
CONSOLE_LOG="${OUT_DIR}/console_execution_${TIMESTAMP}.log"
JSON_REPORT="${OUT_DIR}/mobile_forensics_report.json"
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

# Color formatting
RED='\033[0;31m'
YELLOW='\033[1;33m'
GREEN='\033[0;32m'
CYAN='\033[0;36m'
GRAY='\033[0;37m'
BOLD='\033[1m'
NC='\033[0m'

log_msg() {
    local level="$1"
    local message="$2"
    local time_str
    time_str="$(date +'%Y-%m-%d %H:%M:%S')"
    local plain="[$time_str] [$level] $message"

    case "$level" in
        "HEADER")
            echo -e "\n${CYAN}================================================================================${NC}"
            echo -e "${CYAN} $message${NC}"
            echo -e "${CYAN}================================================================================${NC}"
            echo -e "\n================================================================================\n $message\n================================================================================" >> "$SUMMARY_LOG"
            echo -e "\n================================================================================\n $message\n================================================================================" >> "$CONSOLE_LOG"
            ;;
        "SECTION")
            echo -e "\n${CYAN}--- [$message] ---${NC}"
            echo -e "\n--- [$message] ---" >> "$SUMMARY_LOG"
            echo -e "\n--- [$message] ---" >> "$CONSOLE_LOG"
            ;;
        "ALERT")
            echo -e "${RED}[-] ${plain}${NC}"
            echo "[-] ${plain}" >> "$SUMMARY_LOG"
            echo "[-] ${plain}" >> "$CONSOLE_LOG"
            ALERT_COUNT=$((ALERT_COUNT + 1))
            ;;
        "WARN")
            echo -e "${YELLOW}[!] ${plain}${NC}"
            echo "[!] ${plain}" >> "$SUMMARY_LOG"
            echo "[!] ${plain}" >> "$CONSOLE_LOG"
            WARN_COUNT=$((WARN_COUNT + 1))
            ;;
        "OK")
            echo -e "${GREEN}[+] ${plain}${NC}"
            echo "[+] ${plain}" >> "$SUMMARY_LOG"
            echo "[+] ${plain}" >> "$CONSOLE_LOG"
            INFO_COUNT=$((INFO_COUNT + 1))
            ;;
        "INFO")
            echo -e "${GRAY}[*] ${plain}${NC}"
            echo "[*] ${plain}" >> "$SUMMARY_LOG"
            echo "[*] ${plain}" >> "$CONSOLE_LOG"
            INFO_COUNT=$((INFO_COUNT + 1))
            ;;
    esac
}

show_usage() {
    echo -e "${BOLD}Usage:${NC}"
    echo -e "  $0 android                 Audit connected Android device over USB (requires ADB)"
    echo -e "  $0 ios [/path/to/backup]   Audit iOS device or analyze existing forensic backup"
    echo -e "  $0 --help                  Display this tactical usage guide"
    echo -e ""
    echo -e "${BOLD}Prerequisites:${NC}"
    echo -e "  Android : 'adb' utility (sudo apt install adb / brew install android-platform-tools)"
    echo -e "  iOS     : 'libimobiledevice' (sudo apt install libimobiledevice-utils / brew install libimobiledevice)"
    echo -e "  MVT     : Python 3 with 'mvt' package installed (pip install mvt)"
    exit 1
}

# ==============================================================================
# Dependency & Threat Intelligence Checker (MVT & STIX2 IOCs)
# ==============================================================================
check_mvt() {
    log_msg "SECTION" "Mobile Verification Toolkit (MVT) & Threat IOC Verification"

    local mvt_missing=0
    if ! command -v mvt-android >/dev/null 2>&1; then
        mvt_missing=1
    fi
    if ! command -v mvt-ios >/dev/null 2>&1; then
        mvt_missing=1
    fi

    if [ "$mvt_missing" -eq 1 ]; then
        log_msg "WARN" "MVT binaries not found in PATH. Attempting automatic installation via pip3 / uv..."
        if command -v uv >/dev/null 2>&1; then
            uv tool install mvt || true
        elif command -v pip3 >/dev/null 2>&1; then
            pip3 install --user --upgrade mvt || true
        elif command -v pip >/dev/null 2>&1; then
            pip install --user --upgrade mvt || true
        fi

        # Check again
        export PATH="$HOME/.local/bin:$PATH"
        if command -v mvt-android >/dev/null 2>&1 && command -v mvt-ios >/dev/null 2>&1; then
            log_msg "OK" "MVT installed successfully."
        else
            log_msg "ALERT" "Could not install MVT automatically. Install manually with: pip3 install --user mvt"
        fi
    else
        log_msg "OK" "MVT binaries (mvt-android, mvt-ios) detected in PATH."
    fi

    # Update IOC feeds
    log_msg "INFO" "Updating latest Amnesty International STIX2 spyware IOC definitions (Pegasus, Predator, Cytrox)..."
    if command -v mvt-ios >/dev/null 2>&1; then
        mvt-ios download-iocs >/dev/null 2>&1 || log_msg "WARN" "Failed to update mvt-ios IOC feed (Network offline?)."
    fi
    if command -v mvt-android >/dev/null 2>&1; then
        mvt-android download-iocs >/dev/null 2>&1 || log_msg "WARN" "Failed to update mvt-android IOC feed (Network offline?)."
    fi
}

# ==============================================================================
# AUDIT ANDROID
# ==============================================================================
audit_android() {
    log_msg "HEADER" "ANDROID FORENSIC & SPYWARE AUDIT"

    if ! command -v adb >/dev/null 2>&1; then
        log_msg "ALERT" "ADB binary ('adb') is not installed. Install with: sudo apt install adb or brew install android-platform-tools"
        exit 1
    fi

    log_msg "INFO" "Starting ADB server and checking device connection..."
    adb start-server >/dev/null 2>&1 || true

    local device_state
    device_state=$(adb get-state 2>/dev/null || echo "disconnected")
    if [ "$device_state" != "device" ]; then
        log_msg "ALERT" "Android device not in authorized 'device' state (Current: '$device_state')."
        log_msg "WARN"  "Troubleshooting:"
        log_msg "WARN"  "  1. Ensure USB Debugging is enabled in Android Developer Options."
        log_msg "WARN"  "  2. Unlock phone and tap 'Allow USB Debugging' on prompt."
        log_msg "WARN"  "  3. Re-seat USB cable or run: adb kill-server && adb devices"
        exit 1
    fi

    # 1. Device Metadata
    local brand model os_ver patch_level serial
    brand=$(adb shell getprop ro.product.manufacturer 2>/dev/null | tr -d '\r')
    model=$(adb shell getprop ro.product.model 2>/dev/null | tr -d '\r')
    os_ver=$(adb shell getprop ro.build.version.release 2>/dev/null | tr -d '\r')
    patch_level=$(adb shell getprop ro.build.version.security_patch 2>/dev/null | tr -d '\r')
    serial=$(adb get-serialno 2>/dev/null | tr -d '\r')

    log_msg "INFO" "Connected Device : $brand $model (Serial: $serial)"
    log_msg "INFO" "Android Version  : $os_ver (SPL: $patch_level)"

    # 2. Verified Boot State
    log_msg "SECTION" "1. Android Verified Boot (AVB) Integrity"
    local boot_state
    boot_state=$(adb shell getprop ro.boot.verifiedbootstate 2>/dev/null | tr -d '\r')
    if [ -z "$boot_state" ]; then
        boot_state=$(adb shell getprop ro.boot.flash.locked 2>/dev/null | tr -d '\r')
    fi

    if [ "$boot_state" = "green" ] || [ "$boot_state" = "1" ]; then
        log_msg "OK" "Verified Boot State is GREEN (Locked OEM bootloader, OEM key enforced)."
    elif [ "$boot_state" = "orange" ] || [ "$boot_state" = "yellow" ] || [ "$boot_state" = "red" ] || [ "$boot_state" = "0" ]; then
        log_msg "ALERT" "CRITICAL: Verified Boot State is TAMPERED/UNLOCKED ($boot_state)! Kernel or partition integrity compromised."
    else
        log_msg "WARN" "Verified Boot State returned unrecognized value: '$boot_state'."
    fi

    # 3. SELinux Enforcement
    log_msg "SECTION" "2. SELinux Policy Enforcement"
    local selinux_state
    selinux_state=$(adb shell getenforce 2>/dev/null | tr -d '\r')
    if [ "$selinux_state" = "Enforcing" ]; then
        log_msg "OK" "SELinux is in ENFORCING mode."
    else
        log_msg "ALERT" "CRITICAL: SELinux is NOT Enforcing (Status: '$selinux_state')! Exploit / rootkit condition."
    fi

    # 4. Root / Su Binary Detection
    log_msg "SECTION" "3. Root & Binary Elevation Checks"
    local su_locations=(
        "/system/bin/su"
        "/system/xbin/su"
        "/sbin/su"
        "/vendor/bin/su"
        "/system/sd/xbin/su"
        "/su/bin/su"
        "/data/local/su"
    )
    local root_found=0
    for su_path in "${su_locations[@]}"; do
        local check_res
        check_res=$(adb shell "ls -d $su_path 2>/dev/null" | tr -d '\r')
        if [ -n "$check_res" ]; then
            log_msg "ALERT" "Root elevation binary detected: $su_path"
            root_found=1
        fi
    done
    if [ "$root_found" -eq 0 ]; then
        log_msg "OK" "No unauthorized su elevation binaries detected in system paths."
    fi

    # 5. Accessibility Services Check (Stalkerware hook)
    log_msg "SECTION" "4. Abusive Accessibility Services (Keylogger & Stalkerware Vector)"
    local access_services
    access_services=$(adb shell settings get secure enabled_accessibility_services 2>/dev/null | tr -d '\r')
    if [ -n "$access_services" ] && [ "$access_services" != "null" ]; then
        log_msg "ALERT" "Active Accessibility Services enabled: $access_services"
        log_msg "WARN"  "  Note: Malicious stalkerware & banking trojans abuse Accessibility Services to capture keystrokes, SMS, and screen contents."
    else
        log_msg "OK" "No suspicious third-party Accessibility Services currently active."
    fi

    # 6. Device Admin Applications
    log_msg "SECTION" "5. Enabled Device Administrators (Anti-Uninstall Persistence)"
    local dev_admins
    dev_admins=$(adb shell dumpsys device_policy 2>/dev/null | grep -A 6 "Enabled Device Admins" | tr -d '\r')
    if echo "$dev_admins" | grep -qi "ComponentInfo"; then
        log_msg "ALERT" "Active Device Administrator packages detected:"
        echo "$dev_admins" | while IFS= read -r da_line; do
            log_msg "ALERT" "  $da_line"
        done
        log_msg "WARN" "Verify that all Device Admins are legitimate MDM or Google Find My Device."
    else
        log_msg "OK" "No anomalous Device Administrator packages found."
    fi

    # 7. Sideloaded 3rd-Party Applications
    log_msg "SECTION" "6. 3rd-Party & Sideloaded Package Audit"
    local packages_file="${OUT_DIR}/third_party_packages.txt"
    adb shell pm list packages -3 -i -f 2>/dev/null | tr -d '\r' > "$packages_file" || true

    local sideloaded_count=0
    if [ -s "$packages_file" ]; then
        local total_3p
        total_3p=$(wc -l < "$packages_file")
        log_msg "INFO" "Auditing $total_3p installed 3rd-party package(s)..."

        while IFS= read -r pkg_line; do
            [ -z "$pkg_line" ] && continue
            # Format: package:/data/app/.../base.apk=com.example installer=com.android.vending
            local installer
            installer=$(echo "$pkg_line" | grep -o 'installer=[^ ]*' | cut -d'=' -f2)
            local pkg_name
            pkg_name=$(echo "$pkg_line" | awk -F'=' '{print $2}' | awk '{print $1}')

            if [ "$installer" != "com.android.vending" ] && [ "$installer" != "com.google.android.feedback" ]; then
                log_msg "WARN" "Sideloaded / Non-Play-Store Package: $pkg_name (Installer: ${installer:-NONE/Direct-APK})"
                sideloaded_count=$((sideloaded_count + 1))
            fi
        done < "$packages_file"

        if [ "$sideloaded_count" -eq 0 ]; then
            log_msg "OK" "All 3rd-party applications originated from the official Google Play Store."
        else
            log_msg "WARN" "Found $sideloaded_count sideloaded or alternative-store application(s). Review $packages_file."
        fi
    fi

    # 8. User Root CA Certificates (TLS Decryption / MITM Proxy)
    log_msg "SECTION" "7. User-Installed Root CA Certificates (TLS Interception Check)"
    local user_certs
    user_certs=$(adb shell "ls -la /data/misc/user/0/cacerts-added/ 2>/dev/null" | tr -d '\r')
    if [ -n "$user_certs" ] && echo "$user_certs" | grep -qiE '\.0'; then
        log_msg "ALERT" "CRITICAL: User-installed Root CA certificate found in /data/misc/user/0/cacerts-added/!"
        echo "$user_certs" | while IFS= read -r cert_line; do
            log_msg "ALERT" "  -> $cert_line"
        done
        log_msg "WARN" "A rogue Root CA permits silent HTTPS/TLS traffic interception (Burp, Charles, or Spyware MITM)."
    else
        log_msg "OK" "No rogue user-installed Root CA certificates detected."
    fi

    # 9. Active Network Sockets
    log_msg "SECTION" "8. Android Network Socket Enumeration"
    local sockets_file="${OUT_DIR}/android_network_sockets.txt"
    adb shell "ss -tulnp 2>/dev/null || netstat -tulnp 2>/dev/null" | tr -d '\r' > "$sockets_file" || true
    if [ -s "$sockets_file" ]; then
        log_msg "INFO" "Dumped active Android network sockets to $sockets_file."
    fi

    # 10. MVT Android Deep IOC Scan
    if command -v mvt-android >/dev/null 2>&1; then
        log_msg "SECTION" "9. MVT Android Deep STIX2 IOC & Artifact Scan"
        local mvt_out="${OUT_DIR}/mvt_android"
        mkdir -p "$mvt_out"
        log_msg "INFO" "Executing: mvt-android check-adb --output $mvt_out"
        mvt-android check-adb --output "$mvt_out" 2>&1 | tee -a "$SUMMARY_LOG" || true

        # Check for detections in MVT output
        if grep -rqi "detected" "$mvt_out" 2>/dev/null || grep -rqi "ioc match" "$mvt_out" 2>/dev/null; then
            log_msg "ALERT" "CRITICAL: MVT DETECTED KNOWN SPYWARE IOC MATCHES (Pegasus / Predator / Cytrox)!"
        else
            log_msg "OK" "MVT completed scan; no known STIX2 spyware IOC matches detected."
        fi
    else
        log_msg "WARN" "mvt-android is not available; skipping automated deep STIX2 IOC scan."
    fi
}

# ==============================================================================
# AUDIT IOS
# ==============================================================================
audit_ios() {
    local target_backup="${1:-}"
    log_msg "HEADER" "APPLE iOS FORENSIC & SPYWARE AUDIT"

    check_mvt

    local backup_path=""

    if [ -n "$target_backup" ]; then
        if [ -d "$target_backup" ]; then
            log_msg "INFO" "Using provided existing iOS backup directory: $target_backup"
            backup_path="$target_backup"
        else
            log_msg "ALERT" "Provided backup path does not exist: $target_backup"
            exit 1
        fi
    else
        # Acquire backup over USB
        log_msg "SECTION" "1. iOS Device Connection & Backup Acquisition"
        if ! command -v idevicebackup2 >/dev/null 2>&1; then
            log_msg "ALERT" "libimobiledevice 'idevicebackup2' is not installed."
            log_msg "WARN"  "Install with: sudo apt install libimobiledevice-utils or brew install libimobiledevice"
            log_msg "WARN"  "Or provide an existing iTunes/Finder backup path: $0 ios /path/to/backup"
            exit 1
        fi

        log_msg "INFO" "Checking for connected iOS device via USB..."
        local udid
        udid=$(idevice_id -l 2>/dev/null | head -n 1 || true)
        if [ -z "$udid" ]; then
            log_msg "ALERT" "No iOS device detected over USB."
            log_msg "WARN"  "Troubleshooting:"
            log_msg "WARN"  "  1. Connect iPhone via USB cable."
            log_msg "WARN"  "  2. Unlock iPhone screen and tap 'Trust This Computer'."
            log_msg "WARN"  "  3. Re-run: $0 ios"
            exit 1
        fi

        log_msg "INFO" "Detected iOS device UDID: $udid"
        backup_path="${OUT_DIR}/ios_backup"
        mkdir -p "$backup_path"

        log_msg "INFO" "Initiating full forensic unencrypted backup to $backup_path (This may take several minutes)..."
        idevicebackup2 backup --full "$backup_path" 2>&1 | tee -a "$SUMMARY_LOG" || true
    fi

    # Run MVT iOS Analysis
    if command -v mvt-ios >/dev/null 2>&1; then
        log_msg "SECTION" "2. MVT iOS Deep Forensic & Spyware Artifact Audit"
        local mvt_ios_out="${OUT_DIR}/mvt_ios_results"
        mkdir -p "$mvt_ios_out"

        log_msg "INFO" "Executing: mvt-ios check-backup --output $mvt_ios_out $backup_path"
        mvt-ios check-backup --output "$mvt_ios_out" "$backup_path" 2>&1 | tee -a "$SUMMARY_LOG" || true

        log_msg "SECTION" "3. Inspecting Forensic Findings & STIX2 Matches"
        if grep -rqi "detected" "$mvt_ios_out" 2>/dev/null || grep -rqi "ioc match" "$mvt_ios_out" 2>/dev/null; then
            log_msg "ALERT" "CRITICAL: MVT DETECTED PEGASUS / PREDATOR / CYTROX INDICATORS IN IOS BACKUP!"
            log_msg "ALERT" "Inspect detailed IOC match records in: $mvt_ios_out"
        else
            log_msg "OK" "MVT iOS scan completed; zero known commercial spyware IOC indicators detected."
        fi
    else
        log_msg "ALERT" "mvt-ios is not installed. Unable to run deep STIX2 threat extraction."
    fi
}

# ==============================================================================
# CLI DISPATCHER
# ==============================================================================
if [ $# -lt 1 ]; then
    show_usage
fi

case "$1" in
    "android")
        check_mvt
        audit_android
        ;;
    "ios")
        shift
        audit_ios "${1:-}"
        ;;
    "-h"|"--help"|"help")
        show_usage
        ;;
    *)
        echo -e "${RED}Unknown subcommand: $1${NC}"
        show_usage
        ;;
esac

# Summary
log_msg "HEADER" "MOBILE FORENSIC AUDIT SUMMARY"
log_msg "INFO" "Total Critical Alerts [ALERT] : $ALERT_COUNT"
log_msg "INFO" "Total Warnings         [WARN]  : $WARN_COUNT"
log_msg "INFO" "Total Informational    [INFO]  : $INFO_COUNT"
log_msg "INFO" "Full forensic logs and raw outputs saved to: $OUT_DIR"

if [ "$ALERT_COUNT" -gt 0 ]; then
    echo -e "\n${RED}${BOLD}[!] HIGH SEVERITY MOBILE THREAT IDENTIFIED!${NC}"
    echo -e "${YELLOW}Immediate Mobile Containment Checklist:${NC}"
    echo -e "  1. Enable iOS Lockdown Mode immediately (Settings -> Privacy & Security -> Lockdown Mode)."
    echo -e "  2. For Android: Revoke rogue Accessibility Services and Device Admin rights."
    echo -e "  3. Remove any unknown User Root CA certificates from security settings."
    echo -e "  4. Implement a strict daily reboot cadence to purge memory-only exploits."
    echo -e "  5. Refer to cyber_defense_playbook.pdf for advanced forensic triage."
fi

# ==============================================================================
# REPORT EXPORT & AUTOMATED PORTAL UPLOAD
# ==============================================================================
log_msg "INFO" "Raw console execution log saved to: $CONSOLE_LOG"

if command -v python3 >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/portal_server.py" ]; then
    python3 -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); import portal_server, json; rep = portal_server.parse_raw_text_report(open('$SUMMARY_LOG', encoding='utf-8', errors='ignore').read()); rep['console_log'] = open('$CONSOLE_LOG', encoding='utf-8', errors='ignore').read(); print(json.dumps(rep, indent=2))" > "$JSON_REPORT" 2>/dev/null || true
elif command -v python >/dev/null 2>&1 && [ -f "$SCRIPT_DIR/portal_server.py" ]; then
    python -c "import sys; sys.path.insert(0, '$SCRIPT_DIR'); import portal_server, json; rep = portal_server.parse_raw_text_report(open('$SUMMARY_LOG', encoding='utf-8', errors='ignore').read()); rep['console_log'] = open('$CONSOLE_LOG', encoding='utf-8', errors='ignore').read(); print(json.dumps(rep, indent=2))" > "$JSON_REPORT" 2>/dev/null || true
fi

if [ -s "$JSON_REPORT" ]; then
    log_msg "OK" "Structured JSON scan report generated at: $JSON_REPORT"
    if curl -s --connect-timeout 2 "$PORTAL_URL/api/health" >/dev/null 2>&1; then
        upload_resp=$(curl -s -X POST -H "Content-Type: application/json" -d @"$JSON_REPORT" "$PORTAL_URL/api/upload_report" 2>/dev/null || true)
        echo -e "\n${GREEN}================================================================================${NC}"
        echo -e "${GREEN} [+] AUDIT REPORT TRANSMITTED TO REMEDIATION PORTAL${NC}"
        echo -e "${GREEN}================================================================================${NC}"
        echo -e " Open the Cyber Defense Portal to view interactive threat analysis & fix guides:"
        echo -e " Portal URL: ${CYAN}${PORTAL_URL}${NC}"
        echo -e " Log files available:"
        echo -e "   - Structured Report : ${JSON_REPORT}"
        echo -e "   - Human Summary     : ${SUMMARY_LOG}"
        echo -e "   - Console Log       : ${CONSOLE_LOG}"
        echo -e "${GREEN}================================================================================${NC}\n"
    else
        log_msg "INFO" "Local remediation portal not online. Start manually with: python portal_server.py"
        log_msg "INFO" "Then drag & drop $JSON_REPORT or $CONSOLE_LOG into the dashboard."
    fi
else
    # Fallback to posting raw log text if python was unavailable
    if curl -s --connect-timeout 2 "$PORTAL_URL/api/health" >/dev/null 2>&1; then
        curl -s -X POST -H "Content-Type: application/json" --data-binary "{\"raw_log\": $(python3 -c 'import json, sys; print(json.dumps(open(sys.argv[1]).read()))' "$CONSOLE_LOG" 2>/dev/null || python3 -c 'import json, sys; print(json.dumps(open(sys.argv[1]).read()))' "$SUMMARY_LOG" 2>/dev/null || echo '""')}" "$PORTAL_URL/api/upload_report" >/dev/null 2>&1 || true
    fi
fi

exit 0

