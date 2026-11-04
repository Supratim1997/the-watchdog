#!/usr/bin/env python3
"""
portal_server.py
================================================================================
Local Incident Response & Compromise Remediation Portal
================================================================================
Zero-dependency, multi-threaded local web portal serving:
  - Automated report aggregation from Windows, Linux, and Mobile scan scripts
  - Deep threat intelligence & heuristic risk analysis
  - Actionable, step-by-step containment and fix guides with copyable commands
  - Real-time remediation tracking scorecard & host risk meter
  - Direct file upload for offline or remote VPS audit logs
================================================================================
Author: Principal Red/Blue Team Security Engineer & Systems Architect
"""

import sys
import os
import json
import time
import re
import urllib.parse
from http.server import ThreadingHTTPServer, BaseHTTPRequestHandler
from datetime import datetime

PORT = 8888
HOST = "127.0.0.1"
REPORTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "portal_reports")
os.makedirs(REPORTS_DIR, exist_ok=True)

# ------------------------------------------------------------------------------
# Threat Intelligence & Remediation Knowledge Base
# ------------------------------------------------------------------------------
REMEDIATION_KB = {
    "windows_non_standard_service": {
        "title": "Non-Standard Service Inspection & Remediation",
        "severity": "WARNING",
        "description": "Third-party services executing outside Windows System32 can be leveraged for defense evasion or unauthorized persistence. Inspect the binary path, vendor digital signature, and startup arguments.",
        "steps": [
            {
                "phase": "1. Inspect Service Details",
                "action": "Query the service configuration and verify vendor signature.",
                "command": "Get-Service -Name \"{service_name}\" | Format-List *"
            },
            {
                "phase": "2. Stop and Disable if Unauthorized",
                "action": "Halt the service and prevent automatic startup.",
                "command": "Stop-Service -Name \"{service_name}\" -Force; Set-Service -Name \"{service_name}\" -StartupType Disabled"
            },
            {
                "phase": "3. Eradicate Service Registration",
                "action": "Delete the service entry if confirmed malicious.",
                "command": "sc.exe delete \"{service_name}\""
            }
        ]
    },
    "windows_scheduled_task": {
        "title": "Suspicious Scheduled Task Remediation",
        "severity": "ALERT",
        "description": "Scheduled tasks executing living-off-the-land interpreters (powershell, cmd, mshta) or launching from user profiles can execute payloads periodically or at system boot.",
        "steps": [
            {
                "phase": "1. Unregister Scheduled Task",
                "action": "Remove the scheduled task registration.",
                "command": "Unregister-ScheduledTask -TaskName \"{task_name}\" -Confirm:$false"
            },
            {
                "phase": "2. Quarantine Task Executable",
                "action": "Quarantine the target binary associated with the task.",
                "command": "Remove-Item -Path \"{exec_path}\" -Force"
            },
            {
                "phase": "3. Verification",
                "action": "Verify task is no longer registered.",
                "command": "Get-ScheduledTask -TaskName \"{task_name}\" -ErrorAction SilentlyContinue"
            }
        ]
    },
    "windows_network_socket": {
        "title": "External Network Socket / Suspicious Listener Mitigation",
        "severity": "ALERT",
        "description": "An unsigned binary or process running from a user directory is maintaining an active TCP connection or external listening socket.",
        "steps": [
            {
                "phase": "1. Isolate Process & Sever Connection",
                "action": "Terminate the process holding the connection.",
                "command": "Stop-Process -Id {pid} -Force"
            },
            {
                "phase": "2. Block Remote Endpoint at Firewall",
                "action": "Block outbound traffic to the destination IP.",
                "command": "New-NetFirewallRule -DisplayName \"IR_Block_{remote_ip}\" -Direction Outbound -RemoteAddress \"{remote_ip}\" -Action Block"
            },
            {
                "phase": "3. Quarantine Binary",
                "action": "Remove the executable holding the socket.",
                "command": "Remove-Item -Path \"{path}\" -Force"
            }
        ]
    },
    "windows_unsigned_process": {
        "title": "Unsigned Executable in User-Writable Staging Directory",
        "severity": "CRITICAL",
        "description": "Malicious implants, infostealers, and secondary stage loaders frequently execute from AppData, Temp, or ProgramData to bypass standard directory ACLs without requiring administrative write privileges.",
        "steps": [
            {
                "phase": "1. Immediate Host & Process Containment",
                "action": "Terminate the rogue process immediately using its Process ID (PID).",
                "command": "Stop-Process -Id {pid} -Force"
            },
            {
                "phase": "2. Forensic Staging & Carving",
                "action": "Copy the suspicious binary to an isolated quarantined location for hashing and reverse engineering before deletion.",
                "command": "Copy-Item -Path \"{path}\" -Destination \"$env:TEMP\\quarantine_{pid}.bin\" -Force"
            },
            {
                "phase": "3. Eradication & File Removal",
                "action": "Permanently remove the unverified binary from the user profile.",
                "command": "Remove-Item -Path \"{path}\" -Force"
            },
            {
                "phase": "4. Verification",
                "action": "Confirm no residual child processes or reinfection routines are executing.",
                "command": "Get-Process -Name \"{name}\" -ErrorAction SilentlyContinue"
            }
        ]
    },
    "windows_registry_lolbin": {
        "title": "Suspicious Registry Run Key Invoking LOLBin / Encoded Command",
        "severity": "CRITICAL",
        "description": "Adversaries maintain userland persistence across reboots by creating registry values in HKLM/HKCU Run keys that trigger living-off-the-land binaries (LOLBins) like powershell.exe, cmd.exe, or mshta.exe with hidden or encoded commands.",
        "steps": [
            {
                "phase": "1. Eradicate Persistence Hook",
                "action": "Remove the malicious autorun registry property.",
                "command": "Remove-ItemProperty -Path \"{key}\" -Name \"{value_name}\" -Force"
            },
            {
                "phase": "2. Inspect Child Processes",
                "action": "Search for any active processes spawned by the autorun script.",
                "command": "Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like \"*{value_name}*\" } | Select-Object ProcessId, CommandLine"
            },
            {
                "phase": "3. Verification",
                "action": "Ensure the registry value has been completely eradicated.",
                "command": "Get-ItemProperty -Path \"{key}\" -Name \"{value_name}\" -ErrorAction SilentlyContinue"
            }
        ]
    },
    "windows_ifeo_debugger": {
        "title": "Image File Execution Options (IFEO) Debugger Backdoor",
        "severity": "CRITICAL",
        "description": "The classic Sticky Keys / Accessibility backdoor. When an IFEO 'Debugger' property is attached to an executable (e.g., sethc.exe, utilman.exe), pressing Shift 5 times or clicking Accessibility spawns an elevated command prompt without logging in.",
        "steps": [
            {
                "phase": "1. Remove Malicious Debugger Property",
                "action": "Delete the Debugger override property under the targeted IFEO subkey.",
                "command": "Remove-ItemProperty -Path \"{key}\" -Name \"Debugger\" -Force"
            },
            {
                "phase": "2. Restore Default Permissions",
                "action": "Verify system binary integrity using the Windows System File Checker.",
                "command": "sfc /scanfile=C:\\Windows\\System32\\sethc.exe"
            },
            {
                "phase": "3. Verification",
                "action": "Confirm that no Debugger property remains under the key.",
                "command": "Get-ItemProperty -Path \"{key}\" -ErrorAction SilentlyContinue"
            }
        ]
    },
    "windows_unsigned_driver": {
        "title": "Unsigned Running Kernel Driver (Rootkit / BYOVD Indicator)",
        "severity": "CRITICAL",
        "description": "Kernel drivers execute in Ring 0 with unrestricted hardware access. An unsigned running driver indicates Driver Signature Enforcement (DSE) tampering, a kernel-mode rootkit, or a Bring-Your-Own-Vulnerable-Driver (BYOVD) attack.",
        "steps": [
            {
                "phase": "1. Forensic Memory Dump (Prior to Reboot)",
                "action": "Acquire volatile physical memory immediately; rebooting will purge in-memory rootkit hooks.",
                "command": "winpmem.exe -o \"$env:USERPROFILE\\Desktop\\memory_dump.raw\""
            },
            {
                "phase": "2. Halt Driver Execution",
                "action": "Attempt to stop and disable the driver service.",
                "command": "Stop-Service -Name \"{driver_name}\" -Force; Set-Service -Name \"{driver_name}\" -StartupType Disabled"
            },
            {
                "phase": "3. Trigger Pre-Boot Offline Rootkit Scan",
                "action": "Reboot into the dedicated Windows Defender Offline pre-boot environment to cleanse Ring 0 hooks out-of-band.",
                "command": "Start-MpWDOScan"
            }
        ]
    },
    "windows_wmi_persistence": {
        "title": "WMI Event Subscription (Fileless Backdoor)",
        "severity": "CRITICAL",
        "description": "WMI event filters bound to command line or script consumers execute malicious payloads invisibly when specific triggers (like user logon or time intervals) fire, completely independent of the filesystem.",
        "steps": [
            {
                "phase": "1. Eradicate WMI Event Consumer",
                "action": "Remove the rogue consumer from root\\subscription.",
                "command": "Get-CimInstance -Namespace root\\subscription -ClassName __EventConsumer | Where-Object { $_.Name -eq '{consumer_name}' } | Remove-CimInstance"
            },
            {
                "phase": "2. Eradicate WMI Event Filter",
                "action": "Remove the trigger filter.",
                "command": "Get-CimInstance -Namespace root\\subscription -ClassName __EventFilter | Where-Object { $_.Name -eq '{filter_name}' } | Remove-CimInstance"
            },
            {
                "phase": "3. Verification",
                "action": "Confirm zero custom subscriptions exist in root\\subscription.",
                "command": "Get-CimInstance -Namespace root\\subscription -ClassName __FilterToConsumerBinding"
            }
        ]
    },
    "windows_defender_tampering": {
        "title": "Windows Defender Real-time Protection Disabled or Exclusion Configured",
        "severity": "HIGH",
        "description": "Exclusion paths and disabled real-time monitoring create permanent blindspots that permit malware to execute without antivirus interception.",
        "steps": [
            {
                "phase": "1. Purge Unauthorized Exclusions",
                "action": "Remove the configured path or process exclusions.",
                "command": "Remove-MpPreference -ExclusionPath \"{exclusion_path}\" -ErrorAction SilentlyContinue"
            },
            {
                "phase": "2. Re-enable Real-Time & Cloud Defenses",
                "action": "Force all Defender behavior and signature protections to active mode.",
                "command": "Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false"
            },
            {
                "phase": "3. Immediate Signature Update & Fast Scan",
                "action": "Update threat definitions and execute an immediate threat check.",
                "command": "Update-MpSignature; Start-MpScan -ScanType QuickScan"
            }
        ]
    },
    "windows_event_new_service": {
        "title": "Recently Installed Service Verification (Event ID 7045)",
        "severity": "WARNING",
        "description": "System Event ID 7045 indicates a new service was installed within the last 7 days. Verify vendor legitimacy, binary hash, and service path to detect unauthorized persistence.",
        "steps": [
            {
                "phase": "1. Inspect Service & Vendor Signature",
                "action": "Check service registration and verify digital certificate on disk.",
                "command": "Get-Service -Name \"{service_name}\" -ErrorAction SilentlyContinue | Format-List *; Get-AuthenticodeSignature (Get-CimInstance Win32_Service -Filter \"Name='{service_name}'\" -ErrorAction SilentlyContinue).PathName"
            },
            {
                "phase": "2. Verify Service Binary Hash",
                "action": "Calculate SHA-256 hash to confirm legitimacy against known vendor hashes.",
                "command": "Get-FileHash -Path \"{path}\" -Algorithm SHA256 -ErrorAction SilentlyContinue"
            },
            {
                "phase": "3. Quarantine & Disable if Unauthorized",
                "action": "Halt and disable the service if it was installed without authorization.",
                "command": "Stop-Service -Name \"{service_name}\" -Force; Set-Service -Name \"{service_name}\" -StartupType Disabled"
            }
        ]
    },

    # Linux / VPS Server Rules
    "linux_webshell_eval": {
        "title": "Obfuscated PHP Webshell / Arbitrary Code Execution Primitive",
        "severity": "CRITICAL",
        "description": "Chained primitives like eval(base64_decode(...)) or unvalidated system($_GET['cmd']) allow remote unauthenticated attackers to execute arbitrary shell commands with web server (www-data) privileges.",
        "steps": [
            {
                "phase": "1. Quarantine Malicious File Immediately",
                "action": "Strip execution permissions and move the webshell outside the public web document root.",
                "command": "chmod 000 \"{file_path}\" && mv \"{file_path}\" /root/quarantine_$(date +%s).php"
            },
            {
                "phase": "2. Inspect Web Server Access Logs for Attacker IP",
                "action": "Identify the external IP addresses that made HTTP requests to this webshell.",
                "command": "grep -rn \"{file_name}\" /var/log/nginx/ /var/log/apache2/ /usr/local/apache/domlogs/ 2>/dev/null | tail -n 20"
            },
            {
                "phase": "3. Block Attacker IP at Firewall",
                "action": "Drop incoming packets from the identified threat actor IP.",
                "command": "iptables -I INPUT -s <ATTACKER_IP> -j DROP"
            }
        ]
    },
    "linux_upload_script": {
        "title": "Rogue Executable Script Located in Static Upload/Media Directory",
        "severity": "CRITICAL",
        "description": "Static directories (/uploads, /images, /cache) should only serve images and documents. An executable script in an upload folder is high-confidence evidence of an unvalidated file-upload exploit.",
        "steps": [
            {
                "phase": "1. Remove Malicious Uploaded Script",
                "action": "Delete the rogue script file.",
                "command": "rm -f \"{file_path}\""
            },
            {
                "phase": "2. Enforce .htaccess Execution Lock",
                "action": "Place an execution lock in the upload directory to forbid script handlers.",
                "command": "cat << 'EOF' > $(dirname \"{file_path}\")/.htaccess\n<FilesMatch \"\\.(php|phtml|phar|pl|py|jsp|asp|sh|cgi)$\">\n    Require all denied\n</FilesMatch>\nOptions -ExecCGI -Indexes\nEOF"
            },
            {
                "phase": "3. Audit Remaining Files in Upload Directory",
                "action": "Scan for any additional scripts in the upload folder tree.",
                "command": "find $(dirname \"{file_path}\") -type f \\( -name \"*.php*\" -o -name \"*.sh\" -o -name \"*.py\" \\)"
            }
        ]
    },
    "linux_htaccess_hijack": {
        "title": ".htaccess Hijack (auto_prepend_file or SEO Cloaking Redirect)",
        "severity": "CRITICAL",
        "description": "Threat actors inject auto_prepend_file into .htaccess to automatically execute a backdoor before every legitimate web page loads, or inject RewriteCond rules to divert search engine traffic.",
        "steps": [
            {
                "phase": "1. Clean Malicious Directives from .htaccess",
                "action": "Remove the injected auto_prepend_file or RewriteCond rules.",
                "command": "sed -i '/auto_prepend_file/d; /auto_append_file/d' \"{file_path}\""
            },
            {
                "phase": "2. Lock .htaccess Immutability",
                "action": "Set strict read-only permissions and optionally immutable flag.",
                "command": "chmod 444 \"{file_path}\" && chattr +i \"{file_path}\" 2>/dev/null || true"
            },
            {
                "phase": "3. Verification",
                "action": "Inspect the cleaned .htaccess configuration.",
                "command": "cat \"{file_path}\""
            }
        ]
    },
    "linux_php_runtime_hardening": {
        "title": "Insecure PHP Configuration: session.upload_progress.enabled or allow_url_include",
        "severity": "HIGH",
        "description": "When session.upload_progress.enabled is On, attackers can exploit local file inclusion (LFI) via PHP2Shell race conditions. allow_url_include allows direct Remote File Inclusion (RFI).",
        "steps": [
            {
                "phase": "1. Edit Active php.ini",
                "action": "Locate php.ini and enforce secure directives.",
                "command": "sudo sed -i 's/^session.upload_progress.enabled = .*/session.upload_progress.enabled = 0/' /etc/php/*/fpm/php.ini /etc/php/*/apache2/php.ini /etc/php.ini 2>/dev/null"
            },
            {
                "phase": "2. Enforce Dangerous Function Restrictions",
                "action": "Disable command execution functions in php.ini.",
                "command": "sudo sed -i 's/^disable_functions =.*/disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source/' /etc/php/*/fpm/php.ini 2>/dev/null"
            },
            {
                "phase": "3. Restart PHP Service",
                "action": "Reload PHP-FPM or Apache to apply the new runtime settings.",
                "command": "sudo systemctl restart php*-fpm 2>/dev/null || sudo systemctl restart apache2 || sudo systemctl restart httpd"
            }
        ]
    },
    "linux_ld_preload_rootkit": {
        "title": "Userland Rootkit Hook (/etc/ld.so.preload or LD_PRELOAD)",
        "severity": "CRITICAL",
        "description": "The dynamic linker hook /etc/ld.so.preload intercepts standard C library calls (open, readdir, stat) to hide webshells, rogue processes, and network listeners from administrators.",
        "steps": [
            {
                "phase": "1. Neutralize Injected Library Hook",
                "action": "Empty the /etc/ld.so.preload configuration immediately.",
                "command": "echo '' > /etc/ld.so.preload && chattr -i /etc/ld.so.preload 2>/dev/null"
            },
            {
                "phase": "2. Quarantine Injected Shared Object (.so)",
                "action": "Relocate the malicious shared library identified in the report.",
                "command": "mv {injected_so} /root/quarantine_rootkit.so"
            },
            {
                "phase": "3. Restart System Daemons",
                "action": "Reboot the server or restart SSH and web services to unload the hooked library from memory.",
                "command": "sudo systemctl restart sshd nginx apache2"
            }
        ]
    },

    # Mobile Rules
    "mobile_sideloaded_app": {
        "title": "Sideloaded / Non-Google Play 3rd-Party Application",
        "severity": "WARNING",
        "description": "Applications installed outside official app stores bypass automated security vetting and frequently contain repackaged spyware or banking trojans.",
        "steps": [
            {
                "phase": "1. Uninstall Sideloaded Package",
                "action": "Remove the unverified package via ADB.",
                "command": "adb uninstall {package_name}"
            },
            {
                "phase": "2. Disable Unknown Sources",
                "action": "Ensure 'Install Unknown Apps' is globally revoked in Android Settings -> Apps -> Special App Access."
            }
        ]
    },
    "mobile_user_root_ca": {
        "title": "User-Installed Root CA Certificate (TLS Interception / MITM Proxy)",
        "severity": "CRITICAL",
        "description": "A rogue certificate installed in user credentials allows attackers or spyware to decrypt and intercept all HTTPS traffic, credentials, and encrypted communications in real-time.",
        "steps": [
            {
                "phase": "1. Delete User Certificate in Android Settings",
                "action": "Navigate to Settings -> Security -> Encryption & Credentials -> User Credentials, select the certificate, and tap 'Remove'."
            },
            {
                "phase": "2. Verify Filesystem Cleanliness via ADB",
                "action": "Check that the user cert directory is empty.",
                "command": "adb shell ls -la /data/misc/user/0/cacerts-added/"
            }
        ]
    },
    "mobile_mvt_ioc_match": {
        "title": "Amnesty International STIX2 Spyware Detection (Pegasus / Predator / Cytrox)",
        "severity": "CRITICAL",
        "description": "High-confidence signature match on commercial state-grade spyware indicators (NSO Pegasus, Predator, Cytrox) discovered in device backup or telemetry.",
        "steps": [
            {
                "phase": "1. Immediate Device Isolation",
                "action": "Place device in Airplane Mode immediately and remove physical SIM card."
            },
            {
                "phase": "2. Activate iOS Lockdown Mode (iOS)",
                "action": "Navigate to Settings -> Privacy & Security -> Lockdown Mode and tap 'Turn On Lockdown Mode'."
            },
            {
                "phase": "3. Scheduled Reboot Cadence",
                "action": "Reboot the smartphone daily. Memory-only zero-click implants (Pegasus) are flushed from RAM upon power cycle."
            },
            {
                "phase": "4. Enterprise Credential Rotation",
                "action": "Assume all cloud accounts, emails, and 2FA tokens configured on this phone are compromised. Rotate all enterprise passwords from a known-clean computer."
            }
        ]
    }
}


def enhance_finding_with_remediation(finding):
    """Augments a finding with structured threat intelligence and step-by-step fix commands."""
    mod = finding.get("module", "").lower()
    msg = finding.get("message", "").lower()
    raw_msg = finding.get("message", "")
    details = dict(finding.get("details", {}) or {})

    # Heuristic Regex Extraction for missing details (supporting legacy and raw text logs)
    if "Summary" in details:
        m_name = re.search(r"Service Name:\s*([^\r\n|]+)", str(details.get("Summary", "")), re.I)
        if m_name:
            details["ServiceName"] = m_name.group(1).strip()
        m_file = re.search(r"Service File Name:\s*([^\r\n|]+)", str(details.get("Summary", "")), re.I)
        if m_file:
            details["ExecutablePath"] = m_file.group(1).strip().strip('"')

    if not details.get("ExclusionPath"):
        m = re.search(r"Defender Path Exclusion Configured.*?:\s*([^\r\n]+)", raw_msg, re.I)
        if m:
            details["ExclusionPath"] = m.group(1).strip()
    if not details.get("ExclusionProcess"):
        m = re.search(r"Defender Process Exclusion Configured.*?:\s*([^\r\n]+)", raw_msg, re.I)
        if m:
            details["ExclusionProcess"] = m.group(1).strip()

    if not details.get("ServiceName"):
        m = re.search(r"(?:High-Risk Non-Standard Service detected|Service detected):\s*([^\r\n|]+)", raw_msg, re.I)
        if m:
            details["ServiceName"] = m.group(1).strip()

    if not details.get("TaskName"):
        m = re.search(r"Scheduled Task detected:\s*([^\r\n|]+)", raw_msg, re.I)
        if m:
            details["TaskName"] = m.group(1).strip()

    if not details.get("ConsumerName"):
        m = re.search(r"Consumer=\[[^(]+\(Name\s*=\s*\"([^\"]+)\"\)\]", raw_msg, re.I)
        if m:
            details["ConsumerName"] = m.group(1).strip()
    if not details.get("FilterName"):
        m = re.search(r"Filter=\[[^(]+\(Name\s*=\s*\"([^\"]+)\"\)\]", raw_msg, re.I) or re.search(r"WMI Event Filter detected:\s*([^\r\n|]+)", raw_msg, re.I)
        if m:
            details["FilterName"] = m.group(1).strip()

    remote_ep = details.get("RemoteEndpoint", "")
    if remote_ep and ":" in remote_ep:
        details["RemoteIP"] = remote_ep.split(":")[0].strip()
    elif not details.get("RemoteIP"):
        m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", raw_msg)
        if m:
            details["RemoteIP"] = m.group(1)

    if not details.get("ProcessID"):
        m = re.search(r"PID:\s*(\d+)", str(details.get("Process", "")) + " " + raw_msg, re.I)
        if m:
            details["ProcessID"] = m.group(1)
    if not details.get("ProcessName"):
        m = re.search(r"([a-zA-Z0-9_\-\.]+)\s*\(PID:", str(details.get("Process", "")))
        if m:
            details["ProcessName"] = m.group(1)
        elif ":" in raw_msg:
            m = re.search(r"binary:\s*([^\r\n\s]+)", raw_msg, re.I)
            if m:
                details["ProcessName"] = m.group(1)

    rule = None

    # Module & Threat Pattern Matching
    # 1. External Network Connections & Listeners
    if "connection" in msg or "listener" in msg or "network connection" in mod or "socket" in msg:
        rule = REMEDIATION_KB.get("windows_network_socket")

    # 2. Unsigned Processes & User-Directory Executables
    elif "unsigned process" in msg or ("process" in mod and ("unsigned" in msg or "user-directory" in msg)):
        rule = REMEDIATION_KB.get("windows_unsigned_process")

    # 3. WMI Event Subscription Persistence
    elif "wmi" in mod or "event consumer" in msg or "eventfilter" in msg or "filtertoconsumerbinding" in msg:
        rule = REMEDIATION_KB.get("windows_wmi_persistence")

    # 4. Registry Persistence vs IFEO Backdoors
    elif "debugger" in msg or "accessibility backdoor" in msg or ("ifeo" in msg and "debugger" in msg):
        rule = REMEDIATION_KB.get("windows_ifeo_debugger")
    elif "registry" in mod or "run key" in msg or "registry persistence" in msg:
        rule = REMEDIATION_KB.get("windows_registry_lolbin")

    # 5. Non-Standard Services vs Running Kernel Drivers vs Event ID 7045
    elif "7045" in msg or "new service installed" in msg or "newly installed services" in msg or "7045" in str(details.get("EventID", "")):
        rule = REMEDIATION_KB.get("windows_event_new_service")
    elif "driver" in msg or "kernel driver" in msg or "rootkit indicator" in msg or "unsigned running kernel driver" in msg:
        rule = REMEDIATION_KB.get("windows_unsigned_driver")
    elif "service" in msg or "non-standard service" in msg:
        rule = REMEDIATION_KB.get("windows_non_standard_service")

    # 6. Anomalous Scheduled Tasks
    elif "task" in mod or "scheduled task" in msg or "stagers" in mod:
        rule = REMEDIATION_KB.get("windows_scheduled_task")

    # 7. Defender Exclusions & Tampering
    elif "defender" in mod or "exclusion" in msg or "realtime" in msg:
        rule = REMEDIATION_KB.get("windows_defender_tampering")

    # 8. Linux Webshells & RCE Primitives
    elif "webshell" in msg or "rce primitives" in msg or "eval" in msg or "passthru" in msg or "shell_exec" in msg:
        rule = REMEDIATION_KB.get("linux_webshell_eval")
    elif "upload" in mod or "upload directories" in msg:
        rule = REMEDIATION_KB.get("linux_upload_script")
    elif "htaccess" in mod or "htaccess" in msg or "auto_prepend" in msg:
        rule = REMEDIATION_KB.get("linux_htaccess_hijack")
    elif "php2shell" in mod or "session.upload_progress" in msg or "disable_functions" in msg:
        rule = REMEDIATION_KB.get("linux_php_runtime_hardening")
    elif "preload" in mod or "ld_preload" in msg or "ld.so.preload" in msg:
        rule = REMEDIATION_KB.get("linux_ld_preload_rootkit")

    # 9. Mobile Stalkerware & Forensics
    elif "sideloaded" in msg or "non-play-store" in msg or "third_party" in msg:
        rule = REMEDIATION_KB.get("mobile_sideloaded_app")
    elif "root ca" in msg or "cacerts-added" in msg or "user certificate" in msg:
        rule = REMEDIATION_KB.get("mobile_user_root_ca")
    elif "mvt detected" in msg or "pegasus" in msg or "predator" in msg or "stix2" in msg:
        rule = REMEDIATION_KB.get("mobile_mvt_ioc_match")

    finding["details"] = details

    if rule:
        finding["remediation_title"] = rule["title"]
        finding["threat_analysis"] = rule["description"]
        raw_steps = rule["steps"]

        interpolated_steps = []
        for s in raw_steps:
            new_s = dict(s)
            cmd = new_s.get("command", "")
            if cmd:
                pid_val = details.get("ProcessID") or details.get("OwningProcess") or "<PID>"
                proc_name = details.get("ProcessName") or details.get("Name") or "<NAME>"
                exec_path = details.get("ExecutablePath") or details.get("BinaryPath") or details.get("ResolvedPath") or details.get("PathName") or details.get("Execute") or "<PATH>"
                reg_key = details.get("RegistryKey") or details.get("SubKey") or "<REG_KEY>"
                val_name = details.get("ValueName") or details.get("TargetBinary") or "<VALUE>"
                driver_name = details.get("DriverName") or details.get("ServiceName") or "<DRIVER>"
                service_name = details.get("ServiceName") or "<SERVICE>"
                task_name = details.get("TaskName") or "<TASK>"
                consumer_name = details.get("ConsumerName") or "<CONSUMER>"
                filter_name = details.get("FilterName") or "<FILTER>"
                ex_path = details.get("ExclusionPath") or details.get("ExclusionProcess") or "<EXCLUSION_PATH>"
                file_path = details.get("FilePath") or details.get("file_path") or details.get("Path") or "<FILE_PATH>"
                file_name = os.path.basename(file_path) if file_path != "<FILE_PATH>" else "backdoor.php"
                inj_so = details.get("InjectedLibrary") or "/lib/librootkit.so"
                pkg_name = details.get("PackageName") or "<PACKAGE>"
                rem_ip = details.get("RemoteIP") or (details.get("RemoteEndpoint", "").split(":")[0] if ":" in details.get("RemoteEndpoint", "") else "") or "0.0.0.0"

                cmd = cmd.replace("{pid}", str(pid_val))
                cmd = cmd.replace("{name}", str(proc_name))
                cmd = cmd.replace("{path}", str(exec_path))
                cmd = cmd.replace("{exec_path}", str(exec_path))
                cmd = cmd.replace("{key}", str(reg_key))
                cmd = cmd.replace("{value_name}", str(val_name))
                cmd = cmd.replace("{driver_name}", str(driver_name))
                cmd = cmd.replace("{service_name}", str(service_name))
                cmd = cmd.replace("{task_name}", str(task_name))
                cmd = cmd.replace("{consumer_name}", str(consumer_name))
                cmd = cmd.replace("{filter_name}", str(filter_name))
                cmd = cmd.replace("{exclusion_path}", str(ex_path))
                cmd = cmd.replace("{file_path}", str(file_path))
                cmd = cmd.replace("{file_name}", str(file_name))
                cmd = cmd.replace("{injected_so}", str(inj_so))
                cmd = cmd.replace("{package_name}", str(pkg_name))
                cmd = cmd.replace("{remote_ip}", str(rem_ip))

                # Safeguard: Never issue termination commands for OS Kernel (PID 4) or System Idle (PID 0)
                if str(pid_val) in ("0", "4") or str(proc_name).lower() in ("system", "idle"):
                    cmd = cmd.replace(f"Stop-Process -Id {pid_val} -Force", "# System process (PID 4) is the Windows OS Kernel; verify NetBIOS/SMB sharing configurations rather than terminating.")
                    cmd = cmd.replace('Remove-Item -Path "<PATH>" -Force', "# System process executes in kernel-space; no userland binary exists on disk.")

                new_s["command"] = cmd
            interpolated_steps.append(new_s)
        finding["remediation_steps"] = interpolated_steps
    else:
        finding["remediation_title"] = f"Generic Mitigation: {finding.get('module', 'System Finding')}"
        finding["threat_analysis"] = "Review the detected artifact against your organization's authorized software baseline. Isolate the offending binary or network connection."
        finding["remediation_steps"] = [
            {
                "phase": "1. Triage & Verify",
                "action": "Inspect the captured technical details and compare hashes against trusted threat databases (VirusTotal, MalwareBazaar)."
            },
            {
                "phase": "2. Host Quarantine",
                "action": "If unverified, terminate the active process or delete unauthorized persistence entries."
            }
        ]
    return finding


def generate_audit_executive_summary(report, raw_text=""):
    """
    Analyzes an audit report and raw console log to produce a structured
    executive summary of:
      1. What Went Well (Defensive Strengths & Clean Security Baselines)
      2. What Went Wrong (Active Threats, Misconfigurations & Execution Errors)
    """
    host_type = str(report.get("host_type", "windows")).lower()
    findings = report.get("findings", [])
    raw_combined = (raw_text or "") + "\n" + (report.get("console_log", "") or "")

    what_went_well = []
    what_went_wrong = []

    alert_findings = [f for f in findings if f.get("severity") == "ALERT"]
    warn_findings = [f for f in findings if f.get("severity") == "WARN"]

    # 1. EVALUATE WHAT WENT WRONG
    for f in alert_findings:
        msg = f.get("message", "")
        mod = f.get("module", "Threat Detection")
        what_went_wrong.append({
            "type": "ALERT",
            "category": "Active Threat Indicator",
            "title": f.get("remediation_title", mod),
            "detail": msg,
            "module": mod
        })

    for f in warn_findings:
        msg = f.get("message", "")
        mod = f.get("module", "Configuration Warning")
        if "error" in msg.lower() or "exception" in msg.lower() or "failed" in msg.lower() or "cannot overwrite" in msg.lower():
            what_went_wrong.append({
                "type": "SCRIPT_ERROR",
                "category": "Audit Execution Exception",
                "title": "Script Runtime Warning / Error Encountered",
                "detail": msg,
                "module": mod
            })
        else:
            what_went_wrong.append({
                "type": "WARN",
                "category": "Security Blindspot / Exposure",
                "title": f.get("remediation_title", mod),
                "detail": msg,
                "module": mod
            })

    # Search raw console log for unhandled script errors or permission barriers
    if raw_combined:
        error_patterns = [
            (r"Cannot overwrite variable PID", "PowerShell PID Collision", "Module 2 encountered variable collision on automatic $PID variable."),
            (r"Access is denied", "Permission Boundary", "Administrative access denied on a specific system node or socket."),
            (r"CommandNotFoundException|is not recognized as the name of a cmdlet", "Missing Command / Tool", "PowerShell cmdlet or system binary was missing in host environment."),
            (r"mvt-ios is not installed", "Missing Mobile Toolkit", "Amnesty International MVT iOS toolkit not installed."),
            (r"idevicebackup2 is not installed", "Missing USB Utility", "libimobiledevice utility missing for iOS acquisition.")
        ]
        for pattern, title, detail in error_patterns:
            if re.search(pattern, raw_combined, re.I):
                if not any(title in item["title"] for item in what_went_wrong):
                    what_went_wrong.append({
                        "type": "EXEC_NOTICE",
                        "category": "Audit Execution Notice",
                        "title": title,
                        "detail": detail,
                        "module": "Script Runtime Diagnostics"
                    })

    # 2. EVALUATE WHAT WENT WELL
    if "windows" in host_type:
        defender_tampered = any("realtime" in f.get("message", "").lower() or "disable" in f.get("message", "").lower() for f in alert_findings)
        if not defender_tampered:
            what_went_well.append({
                "category": "Antivirus Posture",
                "title": "Windows Defender Real-Time Protection Active",
                "detail": "Core antivirus real-time behavioral monitoring and IOAV inspection remain operational."
            })

        wmi_alerts = any("wmi" in f.get("module", "").lower() or "filter" in f.get("message", "").lower() for f in alert_findings)
        if not wmi_alerts:
            what_went_well.append({
                "category": "Persistence Integrity",
                "title": "WMI Repository Clean (Zero Fileless Backdoors)",
                "detail": "No unauthorized __EventFilter or __EventConsumer bindings detected in root\\subscription."
            })

        driver_alerts = any("kernel driver" in f.get("message", "").lower() or "rootkit indicator" in f.get("message", "").lower() for f in alert_findings)
        if not driver_alerts:
            what_went_well.append({
                "category": "Kernel Space Integrity",
                "title": "Kernel Drivers Verified & Clean",
                "detail": "Zero unsigned running kernel drivers discovered. Driver Signature Enforcement (DSE) is uncompromised."
            })

        ifeo_alerts = any("debugger" in f.get("message", "").lower() or "accessibility backdoor" in f.get("message", "").lower() for f in alert_findings)
        if not ifeo_alerts:
            what_went_well.append({
                "category": "Authentication Gate",
                "title": "Accessibility Subsystems Intact (Zero IFEO Backdoors)",
                "detail": "No Debugger overrides configured under Image File Execution Options for sethc.exe or utilman.exe."
            })

        log_cleared = any("1102" in f.get("message", "") or "cleared" in f.get("message", "").lower() for f in alert_findings)
        if not log_cleared:
            what_went_well.append({
                "category": "Audit Trail Integrity",
                "title": "Security Event Log Intact",
                "detail": "No Event ID 1102 (Audit Log Cleared) events found over past 7 days, confirming audit trail integrity."
            })

        unsigned_proc_alerts = any("unsigned process" in f.get("message", "").lower() for f in alert_findings)
        if not unsigned_proc_alerts:
            what_went_well.append({
                "category": "Process Execution",
                "title": "Clean User Staging Directories",
                "detail": "No unverified unsigned binaries were discovered running from AppData, Temp, or Public user directories."
            })

    elif "linux" in host_type or "server" in host_type:
        webshell_alerts = any("webshell" in f.get("message", "").lower() or "eval" in f.get("message", "").lower() for f in alert_findings)
        if not webshell_alerts:
            what_went_well.append({
                "category": "Application Layer",
                "title": "Zero Obfuscated PHP Webshells",
                "detail": "No high-risk code execution primitives (eval(base64_decode), system($_GET)) detected in web application code."
            })

        upload_alerts = any("upload" in f.get("module", "").lower() or "upload" in f.get("message", "").lower() for f in alert_findings)
        if not upload_alerts:
            what_went_well.append({
                "category": "Media & Upload Storage",
                "title": "Static Upload Folders Secure",
                "detail": "Static asset and media directories are free of rogue executable script files (.php, .phtml, .sh, .py)."
            })

        preload_alerts = any("preload" in f.get("message", "").lower() for f in alert_findings)
        if not preload_alerts:
            what_went_well.append({
                "category": "Userland Integrity",
                "title": "Dynamic Linker (/etc/ld.so.preload) Clean",
                "detail": "No shared library hooks or userland LD_PRELOAD rootkit implants detected."
            })

        perms_alerts = any("world-writable" in f.get("message", "").lower() for f in alert_findings)
        if not perms_alerts:
            what_went_well.append({
                "category": "Filesystem Hardening",
                "title": "Secure File Permissions",
                "detail": "Zero world-writable executable, script, or sensitive environment files found in webroot."
            })

    elif "mobile" in host_type:
        root_alerts = any("root" in f.get("message", "").lower() or "su binary" in f.get("message", "").lower() for f in alert_findings)
        if not root_alerts:
            what_went_well.append({
                "category": "OS Security Boundary",
                "title": "Operating System Integrity Uncompromised",
                "detail": "Android Verified Boot (AVB) and SELinux enforcement verified; no unauthorized root/su binaries detected."
            })

        access_alerts = any("accessibility" in f.get("message", "").lower() for f in alert_findings)
        if not access_alerts:
            what_went_well.append({
                "category": "Privacy Defenses",
                "title": "No Abusive Accessibility Keyloggers",
                "detail": "Zero stalkerware or keylogger services hooking screen or keystroke events via Accessibility APIs."
            })

        cert_alerts = any("root ca" in f.get("message", "").lower() or "cacerts-added" in f.get("message", "").lower() for f in alert_findings)
        if not cert_alerts:
            what_went_well.append({
                "category": "Network Traffic Encryption",
                "title": "Zero Rogue User Root CA Certificates",
                "detail": "Credential store free of user-added trust anchors; outbound TLS communications cannot be MITM-intercepted."
            })

        mvt_alerts = any("mvt detected" in f.get("message", "").lower() or "pegasus" in f.get("message", "").lower() for f in alert_findings)
        if not mvt_alerts:
            what_went_well.append({
                "category": "Advanced Threat Intelligence",
                "title": "Clean STIX2 Spyware Indicators",
                "detail": "Zero matches against Amnesty International STIX2 indicators for Pegasus, Predator, or Cytrox spyware."
            })

    what_went_well.append({
        "category": "Audit Execution",
        "title": "Assessment Lifecycle Completed",
        "detail": f"Successfully evaluated {len(findings)} technical artifacts and indicators with timestamped logging."
    })

    return {
        "what_went_well": what_went_well,
        "what_went_wrong": what_went_wrong,
        "strengths_count": len(what_went_well),
        "issues_count": len(what_went_wrong)
    }


def enhance_report(report):
    """Ensures all findings have remediation and an executive summary."""
    if "findings" in report:
        enhanced = []
        for f in report["findings"]:
            enhanced.append(enhance_finding_with_remediation(f))
        report["findings"] = enhanced
    report["audit_summary"] = generate_audit_executive_summary(report, report.get("console_log", ""))
    return report


def parse_raw_text_report(raw_text):
    """Parses raw terminal text logs into a structured report JSON object."""
    report = {
        "scan_id": f"scan_{int(time.time())}",
        "timestamp": datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"),
        "target_host": "Unknown Host",
        "host_type": "unknown",
        "stats": {"alerts": 0, "warnings": 0, "info": 0},
        "findings": []
    }

    if "WINDOWS COMPROMISE ASSESSMENT" in raw_text:
        report["host_type"] = "windows"
    elif "LINUX VPS" in raw_text or "cPanel" in raw_text or "WEBSHELL" in raw_text:
        report["host_type"] = "linux_server"
    elif "ANDROID" in raw_text or "iOS" in raw_text or "MOBILE" in raw_text:
        report["host_type"] = "mobile"

    host_match = re.search(r"Target Host:\s*([^\r\n|]+)", raw_text) or re.search(r"Auditing Hostname\s*:\s*([^\r\n]+)", raw_text)
    if host_match:
        report["target_host"] = host_match.group(1).strip()

    current_module = "General Audit"
    lines = raw_text.splitlines()

    for line in lines:
        mod_m = re.search(r"---\s*\[(?:MODULE:\s*)?([^\]]+)\]\s*---", line)
        if mod_m:
            current_module = mod_m.group(1).strip()
            continue

        if "[-] [" in line and "] [ALERT]" in line:
            msg = line.split("] [ALERT]", 1)[1].strip()
            finding = {
                "severity": "ALERT",
                "module": current_module,
                "message": msg,
                "details": {}
            }
            report["findings"].append(enhance_finding_with_remediation(finding))
            report["stats"]["alerts"] += 1
        elif "[!] [" in line and "] [WARN]" in line:
            msg = line.split("] [WARN]", 1)[1].strip()
            finding = {
                "severity": "WARN",
                "module": current_module,
                "message": msg,
                "details": {}
            }
            report["findings"].append(enhance_finding_with_remediation(finding))
            report["stats"]["warnings"] += 1
        elif "[+] [" in line and "] [OK]" in line:
            report["stats"]["info"] += 1

    report["console_log"] = raw_text
    report = enhance_report(report)
    return report


# ------------------------------------------------------------------------------
# Embedded Single-Page Application (HTML5 / Modern Dark CSS / Reactive Vanilla JS)
# ------------------------------------------------------------------------------
PORTAL_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Cyber Defense Portal // Compromise Assessment & Remediation</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=JetBrains+Mono:wght@400;600;700&family=Inter:wght@400;500;600;700;800&display=swap">
  <style>
    :root {
      --bg-dark: #0B0F19;
      --bg-card: #111827;
      --bg-card-hover: #1F2937;
      --border: #1F2937;
      --border-light: #374151;
      --text-main: #F9FAFB;
      --text-muted: #9CA3AF;
      --text-dim: #6B7280;
      --accent-blue: #3B82F6;
      --accent-cyan: #06B6D4;
      --alert-red: #EF4444;
      --alert-red-bg: rgba(239, 68, 68, 0.12);
      --warn-amber: #F59E0B;
      --warn-amber-bg: rgba(245, 158, 11, 0.12);
      --ok-green: #10B981;
      --ok-green-bg: rgba(16, 185, 129, 0.12);
    }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      background-color: var(--bg-dark);
      color: var(--text-main);
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      min-height: 100vh;
      display: flex;
      flex-direction: column;
    }
    code, pre { font-family: 'JetBrains Mono', monospace; }

    /* Top Navigation */
    header {
      background: rgba(17, 24, 39, 0.85);
      backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border);
      padding: 0.85rem 2rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      position: sticky;
      top: 0;
      z-index: 50;
    }
    .brand {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }
    .brand-logo {
      width: 32px;
      height: 32px;
      border-radius: 8px;
      background: linear-gradient(135deg, #EF4444, #3B82F6);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1rem;
      color: white;
    }
    .brand-title {
      font-weight: 700;
      font-size: 1.05rem;
      letter-spacing: -0.02em;
    }
    .brand-subtitle {
      font-size: 0.72rem;
      color: var(--accent-cyan);
      text-transform: uppercase;
      font-weight: 600;
      letter-spacing: 0.05em;
    }
    .header-status {
      display: flex;
      align-items: center;
      gap: 1.25rem;
    }
    .status-badge {
      display: flex;
      align-items: center;
      gap: 0.4rem;
      font-size: 0.75rem;
      font-weight: 600;
      padding: 0.3rem 0.75rem;
      border-radius: 9999px;
      background: var(--ok-green-bg);
      color: var(--ok-green);
      border: 1px solid rgba(16, 185, 129, 0.25);
    }
    .status-dot {
      width: 7px;
      height: 7px;
      border-radius: 50%;
      background: var(--ok-green);
      box-shadow: 0 0 8px var(--ok-green);
    }
    .btn {
      background: #1E293B;
      color: white;
      border: 1px solid var(--border-light);
      padding: 0.45rem 0.9rem;
      border-radius: 6px;
      font-size: 0.8rem;
      font-weight: 600;
      cursor: pointer;
      display: inline-flex;
      align-items: center;
      gap: 0.4rem;
      transition: all 0.15s ease;
    }
    .btn:hover { background: #334155; }
    .btn-primary {
      background: var(--accent-blue);
      border-color: var(--accent-blue);
    }
    .btn-primary:hover { background: #2563EB; }

    /* Layout */
    .app-container {
      display: flex;
      flex: 1;
      height: calc(100vh - 61px);
      overflow: hidden;
    }

    /* Sidebar */
    .sidebar {
      width: 330px;
      background: #0D1322;
      border-right: 1px solid var(--border);
      display: flex;
      flex-direction: column;
    }
    .sidebar-header {
      padding: 1rem;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .sidebar-title {
      font-size: 0.8rem;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }
    .reports-list {
      flex: 1;
      overflow-y: auto;
      padding: 0.5rem;
    }
    .report-item {
      padding: 0.85rem;
      margin-bottom: 0.4rem;
      border-radius: 8px;
      border: 1px solid transparent;
      background: var(--bg-card);
      cursor: pointer;
      transition: all 0.15s ease;
    }
    .report-item:hover {
      background: var(--bg-card-hover);
      border-color: var(--border-light);
    }
    .report-item.active {
      background: #1E293B;
      border-color: var(--accent-blue);
    }
    .report-item-title {
      font-weight: 600;
      font-size: 0.85rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.25rem;
    }
    .report-item-sub {
      font-size: 0.72rem;
      color: var(--text-muted);
      margin-bottom: 0.5rem;
    }
    .tag-badges {
      display: flex;
      gap: 0.35rem;
    }
    .badge-pill {
      font-size: 0.68rem;
      font-weight: 700;
      padding: 0.15rem 0.45rem;
      border-radius: 4px;
    }
    .badge-alert { background: var(--alert-red-bg); color: var(--alert-red); border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-warn  { background: var(--warn-amber-bg); color: var(--warn-amber); border: 1px solid rgba(245, 158, 11, 0.3); }
    .badge-clean { background: var(--ok-green-bg); color: var(--ok-green); border: 1px solid rgba(16, 185, 129, 0.3); }

    /* Main Content */
    .main-content {
      flex: 1;
      overflow-y: auto;
      padding: 1.5rem 2rem;
      background: var(--bg-dark);
    }

    /* Hero Metrics */
    .metrics-grid {
      display: grid;
      grid-template-columns: repeat(4, 1fr);
      gap: 1rem;
      margin-bottom: 1.5rem;
    }
    .metric-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.1rem;
    }
    .metric-label {
      font-size: 0.72rem;
      font-weight: 600;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 0.05em;
      margin-bottom: 0.4rem;
    }
    .metric-value {
      font-size: 1.85rem;
      font-weight: 800;
      line-height: 1.1;
    }

    /* Host Risk Score Bar */
    .risk-banner {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      padding: 1.25rem;
      margin-bottom: 1.5rem;
      display: flex;
      align-items: center;
      gap: 1.5rem;
    }
    .risk-score-circle {
      width: 72px;
      height: 72px;
      border-radius: 50%;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      font-weight: 800;
      font-size: 1.35rem;
      border: 4px solid var(--alert-red);
      background: rgba(239, 68, 68, 0.08);
      color: var(--alert-red);
    }
    .risk-info { flex: 1; }
    .risk-title { font-size: 1rem; font-weight: 700; margin-bottom: 0.25rem; }
    .risk-desc { font-size: 0.8rem; color: var(--text-muted); line-height: 1.35; }

    /* Executive Summary Grid (What Went Well vs What Went Wrong) */
    .executive-summary-grid {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1.25rem;
      margin-bottom: 1.5rem;
    }
    .summary-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      overflow: hidden;
      display: flex;
      flex-direction: column;
    }
    .summary-card-header {
      padding: 0.85rem 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      border-bottom: 1px solid var(--border);
      font-weight: 700;
      font-size: 0.85rem;
    }
    .header-well {
      background: rgba(16, 185, 129, 0.08);
      color: #34D399;
      border-bottom-color: rgba(16, 185, 129, 0.25);
    }
    .header-wrong {
      background: rgba(239, 68, 68, 0.08);
      color: #F87171;
      border-bottom-color: rgba(239, 68, 68, 0.25);
    }
    .summary-list {
      padding: 0.85rem 1rem;
      display: flex;
      flex-direction: column;
      gap: 0.65rem;
      max-height: 380px;
      overflow-y: auto;
    }
    .summary-item {
      padding: 0.65rem 0.85rem;
      border-radius: 6px;
      border: 1px solid var(--border);
      background: rgba(255, 255, 255, 0.015);
      font-size: 0.76rem;
      transition: all 0.15s ease;
    }
    .summary-item:hover {
      background: rgba(255, 255, 255, 0.035);
      border-color: var(--border-light);
    }
    .summary-item-top {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 0.25rem;
    }
    .summary-item-badge {
      font-size: 0.62rem;
      font-weight: 700;
      padding: 0.12rem 0.38rem;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .badge-well { background: rgba(16, 185, 129, 0.15); color: #34D399; border: 1px solid rgba(16, 185, 129, 0.4); }
    .badge-wrong-alert { background: rgba(239, 68, 68, 0.15); color: #F87171; border: 1px solid rgba(239, 68, 68, 0.4); }
    .badge-wrong-warn  { background: rgba(245, 158, 11, 0.15); color: #FBBF24; border: 1px solid rgba(245, 158, 11, 0.4); }
    .badge-wrong-error { background: rgba(168, 85, 247, 0.15); color: #C084FC; border: 1px solid rgba(168, 85, 247, 0.4); }

    .summary-item-title {
      font-weight: 700;
      color: var(--text-main);
      font-size: 0.8rem;
    }
    .summary-item-detail {
      color: var(--text-muted);
      line-height: 1.35;
      font-size: 0.74rem;
    }
    .summary-action-btn {
      font-size: 0.68rem;
      padding: 0.18rem 0.45rem;
      border-radius: 4px;
      background: #1E293B;
      color: var(--accent-cyan);
      border: 1px solid rgba(6, 182, 212, 0.3);
      cursor: pointer;
      margin-top: 0.35rem;
      display: inline-block;
    }
    .summary-action-btn:hover {
      background: rgba(6, 182, 212, 0.15);
      color: white;
    }

    /* Console Execution Log Viewer */
    .console-viewer-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }
    .console-viewer-header {
      padding: 0.75rem 1.25rem;
      background: #090E17;
      border-bottom: 1px solid var(--border);
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
    }
    .console-viewer-body {
      padding: 1rem;
      background: #06090F;
      max-height: 350px;
      overflow-y: auto;
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.72rem;
      color: #94A3B8;
      line-height: 1.45;
      white-space: pre-wrap;
      word-break: break-all;
      display: none;
    }
    .console-viewer-body.open { display: block; }

    /* Controls Bar */
    .controls-bar {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 1.25rem;
      gap: 1rem;
    }
    .search-input {
      background: var(--bg-card);
      border: 1px solid var(--border);
      color: white;
      padding: 0.55rem 1rem;
      border-radius: 6px;
      font-size: 0.82rem;
      width: 280px;
    }
    .search-input:focus { outline: none; border-color: var(--accent-blue); }
    .filter-tabs {
      display: flex;
      gap: 0.4rem;
    }
    .tab-btn {
      background: var(--bg-card);
      color: var(--text-muted);
      border: 1px solid var(--border);
      padding: 0.4rem 0.8rem;
      border-radius: 6px;
      font-size: 0.78rem;
      font-weight: 600;
      cursor: pointer;
    }
    .tab-btn.active {
      background: var(--accent-blue);
      color: white;
      border-color: var(--accent-blue);
    }

    /* Finding Card */
    .finding-card {
      background: var(--bg-card);
      border: 1px solid var(--border);
      border-radius: 10px;
      margin-bottom: 1rem;
      overflow: hidden;
      transition: border-color 0.15s ease;
    }
    .finding-card.resolved {
      opacity: 0.55;
      border-color: rgba(16, 185, 129, 0.3);
    }
    .finding-header {
      padding: 1rem 1.25rem;
      display: flex;
      align-items: center;
      justify-content: space-between;
      cursor: pointer;
      user-select: none;
      background: rgba(255, 255, 255, 0.015);
    }
    .finding-header:hover { background: rgba(255, 255, 255, 0.03); }
    .finding-title-group {
      display: flex;
      align-items: center;
      gap: 0.75rem;
      flex: 1;
    }
    .severity-tag {
      font-size: 0.72rem;
      font-weight: 800;
      padding: 0.25rem 0.55rem;
      border-radius: 4px;
      text-transform: uppercase;
      letter-spacing: 0.03em;
    }
    .sev-alert { background: var(--alert-red-bg); color: var(--alert-red); border: 1px solid rgba(239, 68, 68, 0.4); }
    .sev-warn  { background: var(--warn-amber-bg); color: var(--warn-amber); border: 1px solid rgba(245, 158, 11, 0.4); }
    .sev-info  { background: rgba(59, 130, 246, 0.12); color: var(--accent-blue); border: 1px solid rgba(59, 130, 246, 0.4); }

    .finding-headline {
      font-size: 0.88rem;
      font-weight: 600;
      color: var(--text-main);
    }
    .finding-module {
      font-size: 0.75rem;
      color: var(--text-dim);
    }
    .finding-body {
      padding: 1.25rem;
      border-top: 1px solid var(--border);
      display: none;
    }
    .finding-body.open { display: block; }

    /* Technical Details Table */
    .details-table {
      width: 100%;
      border-collapse: collapse;
      font-size: 0.78rem;
      margin-bottom: 1.25rem;
    }
    .details-table td {
      padding: 0.45rem 0.75rem;
      border-bottom: 1px solid var(--border);
    }
    .details-table tr:last-child td { border-bottom: none; }
    .td-key {
      font-weight: 600;
      color: var(--text-muted);
      width: 180px;
    }
    .td-val {
      color: #E2E8F0;
      word-break: break-all;
    }

    /* Remediation Guide Box */
    .remediation-box {
      background: #090E17;
      border: 1px solid rgba(59, 130, 246, 0.25);
      border-left: 4px solid var(--accent-blue);
      border-radius: 8px;
      padding: 1.1rem;
    }
    .remediation-title {
      font-size: 0.85rem;
      font-weight: 700;
      color: var(--accent-cyan);
      display: flex;
      align-items: center;
      gap: 0.5rem;
      margin-bottom: 0.5rem;
    }
    .remediation-threat {
      font-size: 0.78rem;
      color: var(--text-muted);
      line-height: 1.4;
      margin-bottom: 1rem;
    }
    .step-item {
      margin-bottom: 0.85rem;
    }
    .step-header {
      font-size: 0.78rem;
      font-weight: 700;
      color: #E2E8F0;
      margin-bottom: 0.25rem;
    }
    .step-action {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-bottom: 0.35rem;
    }
    .code-cmd-wrap {
      position: relative;
      background: #0F172A;
      border: 1px solid #1E293B;
      border-radius: 6px;
      padding: 0.5rem 0.75rem;
      font-size: 0.75rem;
      color: #38BDF8;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }
    .code-cmd-wrap code {
      word-break: break-all;
      padding-right: 2rem;
    }
    .copy-btn {
      background: #1E293B;
      color: var(--text-muted);
      border: 1px solid var(--border-light);
      padding: 0.2rem 0.5rem;
      border-radius: 4px;
      font-size: 0.68rem;
      cursor: pointer;
      flex-shrink: 0;
    }
    .copy-btn:hover { color: white; background: #334155; }

    /* Empty State */
    .empty-state {
      text-align: center;
      padding: 4rem 2rem;
      color: var(--text-muted);
    }
    .empty-icon {
      font-size: 2.5rem;
      margin-bottom: 1rem;
      color: var(--accent-blue);
    }
    .dropzone {
      border: 2px dashed var(--border-light);
      border-radius: 12px;
      padding: 2.5rem;
      text-align: center;
      margin-top: 1.5rem;
      cursor: pointer;
      transition: all 0.2s ease;
    }
    .dropzone:hover {
      border-color: var(--accent-blue);
      background: rgba(59, 130, 246, 0.04);
    }
  </style>
</head>
<body>

  <header>
    <div class="brand">
      <div class="brand-logo">WD</div>
      <div>
        <div class="brand-title">WATCHDOGS // CYBER DEFENSE PORTAL</div>
        <div class="brand-subtitle">Incident Response, Triage & Remediation Platform</div>
      </div>
    </div>
    <div class="header-status">
      <div class="status-badge">
        <div class="status-dot"></div>
        PORTAL LISTENING :8888
      </div>
      <button class="btn btn-primary" onclick="triggerManualUpload()">Upload Report / Log File</button>
      <input type="file" id="manualFileInput" accept=".log,.txt,.json" style="display:none;" onchange="handleFileSelected(event)">
    </div>
  </header>

  <div class="app-container">
    <!-- Sidebar / Scans -->
    <aside class="sidebar">
      <div class="sidebar-header">
        <span class="sidebar-title">Audit Reports (<span id="reportCount">0</span>)</span>
        <button class="btn" style="padding: 0.25rem 0.5rem; font-size: 0.72rem;" onclick="loadReportsList()">Refresh</button>
      </div>
      <div class="reports-list" id="reportsListContainer">
        <!-- Rendered via JS -->
      </div>
    </aside>

    <!-- Main Content -->
    <main class="main-content" id="mainContainer">
      <div class="empty-state" id="emptyPlaceholder">
        <div class="empty-icon">🛡️</div>
        <h2>No Audit Report Selected</h2>
        <p style="font-size: 0.85rem; margin-top: 0.5rem;">Run any of the 3 audit scripts (Windows, Linux, or Mobile) to automatically stream findings here,<br>or drag & drop a saved report log below.</p>
        <div class="dropzone" onclick="triggerManualUpload()" ondragover="event.preventDefault()" ondrop="handleDrop(event)">
          <div style="font-size: 1.5rem; margin-bottom: 0.5rem;">📂</div>
          <p style="font-weight: 600; font-size: 0.85rem;">Click to browse or drop console_execution.log, audit report (.txt), or .json</p>
          <p style="font-size: 0.72rem; color: var(--text-dim); margin-top: 0.25rem;">Automatic parsing: Executive "What Went Well vs What Went Wrong" breakdown and tactical remediation plan generated instantly</p>
        </div>
      </div>

      <div id="reportDetailArea" style="display: none;">
        <!-- Metrics -->
        <div class="metrics-grid">
          <div class="metric-card">
            <div class="metric-label">Critical Alerts</div>
            <div class="metric-value" style="color: var(--alert-red);" id="mAlerts">0</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Warnings</div>
            <div class="metric-value" style="color: var(--warn-amber);" id="mWarnings">0</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Clean Checks</div>
            <div class="metric-value" style="color: var(--ok-green);" id="mClean">0</div>
          </div>
          <div class="metric-card">
            <div class="metric-label">Target Architecture</div>
            <div class="metric-value" style="font-size: 1.15rem; color: var(--accent-cyan); text-transform: uppercase;" id="mHostType">-</div>
          </div>
        </div>

        <!-- Risk Score Banner -->
        <div class="risk-banner">
          <div class="risk-score-circle" id="riskCircle">0%</div>
          <div class="risk-info">
            <div class="risk-title" id="riskTitle">Calculating Host Risk...</div>
            <div class="risk-desc" id="riskDesc">Evaluating active persistence, rootkit indicators, and configuration integrity.</div>
          </div>
          <div>
            <button class="btn" onclick="exportReportJson()">Export JSON</button>
            <button class="btn" onclick="window.print()">Print / PDF</button>
          </div>
        </div>

        <!-- Executive Audit Breakdown: What Went Well & What Went Wrong -->
        <div class="executive-summary-grid">
          <!-- What Went Well -->
          <div class="summary-card">
            <div class="summary-card-header header-well">
              <span>🟢 WHAT WENT WELL (<span id="wellCount">0</span> Verified Baselines)</span>
              <span style="font-size: 0.72rem; color: var(--text-dim);">Defense Posture Intact</span>
            </div>
            <div class="summary-list" id="wellListContainer">
              <!-- Rendered via JS -->
            </div>
          </div>

          <!-- What Went Wrong -->
          <div class="summary-card">
            <div class="summary-card-header header-wrong">
              <span>🔴 WHAT WENT WRONG (<span id="wrongCount">0</span> Identified Issues)</span>
              <span style="font-size: 0.72rem; color: var(--text-dim);">Threats, Blindspots & Script Exceptions</span>
            </div>
            <div class="summary-list" id="wrongListContainer">
              <!-- Rendered via JS -->
            </div>
          </div>
        </div>

        <!-- Raw Console Execution Log Viewer Accordion -->
        <div class="console-viewer-card" id="consoleViewerCard" style="display: none;">
          <div class="console-viewer-header" onclick="toggleConsoleLog()">
            <div style="display: flex; align-items: center; gap: 0.5rem; font-size: 0.8rem; font-weight: 700; color: #94A3B8;">
              <span>📄</span> RAW CONSOLE EXECUTION LOG STREAM
            </div>
            <span style="font-size: 0.75rem; color: var(--accent-cyan);" id="consoleToggleLabel">Show Log Output ▼</span>
          </div>
          <div class="console-viewer-body" id="consoleLogContent"></div>
        </div>

        <!-- Controls -->
        <div class="controls-bar">
          <div class="filter-tabs">
            <button class="tab-btn active" onclick="setFilter('ALL', this)">All Findings</button>
            <button class="tab-btn" onclick="setFilter('ALERT', this)">Critical Alerts</button>
            <button class="tab-btn" onclick="setFilter('WARN', this)">Warnings</button>
            <button class="tab-btn" onclick="setFilter('REMAINING', this)">Unresolved Only</button>
          </div>
          <input type="text" class="search-input" id="searchBox" placeholder="Filter findings, modules, commands..." oninput="renderFindings()">
        </div>

        <!-- Findings List -->
        <div id="findingsContainer">
          <!-- Rendered via JS -->
        </div>
      </div>
    </main>
  </div>

  <script>
    let currentReports = [];
    let activeReport = null;
    let currentFilter = 'ALL';
    let resolvedFindings = new Set();

    async function loadReportsList() {
      try {
        const res = await fetch('/api/reports');
        currentReports = await res.json();
        document.getElementById('reportCount').innerText = currentReports.length;
        renderReportsSidebar();
        if (currentReports.length > 0 && !activeReport) {
          loadReport(currentReports[0].id);
        }
      } catch (err) {
        console.error("Failed to load reports:", err);
      }
    }

    function renderReportsSidebar() {
      const container = document.getElementById('reportsListContainer');
      container.innerHTML = '';
      if (currentReports.length === 0) {
        container.innerHTML = '<div style="padding: 1.5rem; text-align: center; color: var(--text-dim); font-size: 0.78rem;">No reports uploaded yet.</div>';
        return;
      }
      currentReports.forEach(r => {
        const item = document.createElement('div');
        item.className = 'report-item' + (activeReport && activeReport.scan_id === r.id ? ' active' : '');
        item.onclick = () => loadReport(r.id);

        const alertBadge = r.alert_count > 0 ? `<span class="badge-pill badge-alert">${r.alert_count} ALERTS</span>` : '';
        const warnBadge = r.warn_count > 0 ? `<span class="badge-pill badge-warn">${r.warn_count} WARNS</span>` : '';
        const cleanBadge = (r.alert_count === 0 && r.warn_count === 0) ? `<span class="badge-pill badge-clean">CLEAN</span>` : '';

        item.innerHTML = `
          <div class="report-item-title">
            <span>${escapeHtml(r.target_host || 'Target Host')}</span>
            <span style="font-size: 0.7rem; color: var(--accent-cyan); text-transform: uppercase;">${escapeHtml(r.scan_type || 'Audit')}</span>
          </div>
          <div class="report-item-sub">${r.timestamp}</div>
          <div class="tag-badges">${alertBadge} ${warnBadge} ${cleanBadge}</div>
        `;
        container.appendChild(item);
      });
    }

    async function loadReport(id) {
      try {
        const res = await fetch('/api/report?id=' + encodeURIComponent(id));
        activeReport = await res.json();
        resolvedFindings.clear();
        document.getElementById('emptyPlaceholder').style.display = 'none';
        document.getElementById('reportDetailArea').style.display = 'block';

        // Update stats
        const alerts = activeReport.stats ? activeReport.stats.alerts : 0;
        const warns = activeReport.stats ? activeReport.stats.warnings : 0;
        const info = activeReport.stats ? activeReport.stats.info : 0;

        document.getElementById('mAlerts').innerText = alerts;
        document.getElementById('mWarnings').innerText = warns;
        document.getElementById('mClean').innerText = info;
        document.getElementById('mHostType').innerText = activeReport.host_type || 'Unknown';

        calculateRiskScore();
        renderAuditSummary(activeReport.audit_summary);
        renderConsoleLogViewer();
        renderReportsSidebar();
        renderFindings();
      } catch (err) {
        console.error("Failed to load report:", err);
      }
    }

    function renderAuditSummary(summary) {
      const wellContainer = document.getElementById('wellListContainer');
      const wrongContainer = document.getElementById('wrongListContainer');
      wellContainer.innerHTML = '';
      wrongContainer.innerHTML = '';

      if (!summary) {
        wellContainer.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); font-size: 0.75rem;">No summary telemetry available.</div>';
        wrongContainer.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); font-size: 0.75rem;">No issues recorded.</div>';
        document.getElementById('wellCount').innerText = '0';
        document.getElementById('wrongCount').innerText = '0';
        return;
      }

      const wellItems = summary.what_went_well || [];
      const wrongItems = summary.what_went_wrong || [];

      document.getElementById('wellCount').innerText = wellItems.length;
      document.getElementById('wrongCount').innerText = wrongItems.length;

      if (wellItems.length === 0) {
        wellContainer.innerHTML = '<div style="padding: 1rem; color: var(--text-muted); font-size: 0.75rem;">Zero verified baseline defenses logged.</div>';
      } else {
        wellItems.forEach(item => {
          const div = document.createElement('div');
          div.className = 'summary-item';
          div.innerHTML = `
            <div class="summary-item-top">
              <span class="summary-item-title">✓ ${escapeHtml(item.title)}</span>
              <span class="summary-item-badge badge-well">${escapeHtml(item.category || 'BASELINE')}</span>
            </div>
            <div class="summary-item-detail">${escapeHtml(item.detail)}</div>
          `;
          wellContainer.appendChild(div);
        });
      }

      if (wrongItems.length === 0) {
        wrongContainer.innerHTML = '<div style="padding: 1rem; color: var(--ok-green); font-size: 0.75rem;">Clean Assessment: Zero active threats, blindspots, or script runtime exceptions detected.</div>';
      } else {
        wrongItems.forEach(item => {
          const div = document.createElement('div');
          div.className = 'summary-item';
          let badgeClass = 'badge-wrong-alert';
          if (item.type === 'WARN') badgeClass = 'badge-wrong-warn';
          if (item.type === 'SCRIPT_ERROR' || item.type === 'EXEC_NOTICE') badgeClass = 'badge-wrong-error';

          div.innerHTML = `
            <div class="summary-item-top">
              <span class="summary-item-title">✗ ${escapeHtml(item.title)}</span>
              <span class="summary-item-badge ${badgeClass}">${escapeHtml(item.category || item.type)}</span>
            </div>
            <div class="summary-item-detail">${escapeHtml(item.detail)}</div>
            ${item.detail ? `<button class="summary-action-btn" onclick="scrollToFinding('${escapeHtml(item.module || '').replace(/'/g, "\\'")}', '${escapeHtml(item.detail.slice(0, 40)).replace(/'/g, "\\'")}')">View Fix Guide →</button>` : ''}
          `;
          wrongContainer.appendChild(div);
        });
      }
    }

    function renderConsoleLogViewer() {
      const consoleCard = document.getElementById('consoleViewerCard');
      const consoleContent = document.getElementById('consoleLogContent');
      if (activeReport && activeReport.console_log && activeReport.console_log.trim().length > 0) {
        consoleCard.style.display = 'block';
        consoleContent.innerText = activeReport.console_log;
      } else {
        consoleCard.style.display = 'none';
      }
    }

    function toggleConsoleLog() {
      const body = document.getElementById('consoleLogContent');
      const label = document.getElementById('consoleToggleLabel');
      body.classList.toggle('open');
      label.innerText = body.classList.contains('open') ? 'Hide Log Output ▲' : 'Show Log Output ▼';
    }

    function scrollToFinding(modName, searchSnip) {
      const cards = document.querySelectorAll('.finding-card');
      for (let c of cards) {
        const text = c.innerText.toLowerCase();
        if (text.includes(searchSnip.toLowerCase()) || (modName && text.includes(modName.toLowerCase()))) {
          c.scrollIntoView({ behavior: 'smooth', block: 'center' });
          c.style.borderColor = 'var(--accent-cyan)';
          c.style.boxShadow = '0 0 16px rgba(6, 182, 212, 0.45)';
          const b = c.querySelector('.finding-body');
          if (b) b.classList.add('open');
          setTimeout(() => {
            c.style.borderColor = '';
            c.style.boxShadow = '';
          }, 2500);
          break;
        }
      }
    }

    function calculateRiskScore() {
      if (!activeReport) return;
      const totalAlerts = (activeReport.findings || []).filter(f => f.severity === 'ALERT' && !resolvedFindings.has(f)).length;
      const totalWarns = (activeReport.findings || []).filter(f => f.severity === 'WARN' && !resolvedFindings.has(f)).length;

      let score = (totalAlerts * 25) + (totalWarns * 8);
      if (score > 100) score = 100;

      const circle = document.getElementById('riskCircle');
      const title = document.getElementById('riskTitle');
      const desc = document.getElementById('riskDesc');

      circle.innerText = score + '%';

      if (score >= 70) {
        circle.style.borderColor = 'var(--alert-red)';
        circle.style.color = 'var(--alert-red)';
        title.innerText = 'CRITICAL RISK LEVEL — IMMEDIATE CONTAINMENT MANDATORY';
        title.style.color = 'var(--alert-red)';
        desc.innerText = 'High-confidence persistence, rootkit indicators, or active RCE primitives discovered on this host.';
      } else if (score >= 25) {
        circle.style.borderColor = 'var(--warn-amber)';
        circle.style.color = 'var(--warn-amber)';
        title.innerText = 'MODERATE SUSPICION — INVESTIGATION & HARDENING REQUIRED';
        title.style.color = 'var(--warn-amber)';
        desc.innerText = 'Non-standard binaries, recent configuration tampering, or missing runtime hardening detected.';
      } else {
        circle.style.borderColor = 'var(--ok-green)';
        circle.style.color = 'var(--ok-green)';
        title.innerText = 'HOST POSTURE SECURE — ZERO ACTIVE CRITICAL THREATS';
        title.style.color = 'var(--ok-green)';
        desc.innerText = 'All inspected sockets, kernel drivers, execution directories, and persistence vectors verified clean.';
      }
    }

    function setFilter(filter, btn) {
      currentFilter = filter;
      document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      renderFindings();
    }

    function toggleFinding(idx) {
      const body = document.getElementById('findingBody_' + idx);
      body.classList.toggle('open');
    }

    function toggleResolved(idx, event) {
      event.stopPropagation();
      const f = activeReport.findings[idx];
      if (resolvedFindings.has(f)) {
        resolvedFindings.delete(f);
      } else {
        resolvedFindings.add(f);
      }
      calculateRiskScore();
      renderFindings();
    }

    function renderFindings() {
      const container = document.getElementById('findingsContainer');
      container.innerHTML = '';

      if (!activeReport || !activeReport.findings || activeReport.findings.length === 0) {
        container.innerHTML = '<div style="padding: 2rem; text-align: center; color: var(--text-muted);">No specific threat findings logged for this audit session.</div>';
        return;
      }

      const query = document.getElementById('searchBox').value.toLowerCase();

      activeReport.findings.forEach((f, idx) => {
        const isResolved = resolvedFindings.has(f);

        // Filter Check
        if (currentFilter === 'ALERT' && f.severity !== 'ALERT') return;
        if (currentFilter === 'WARN' && f.severity !== 'WARN') return;
        if (currentFilter === 'REMAINING' && isResolved) return;

        // Search Check
        const textBlob = (f.message + ' ' + f.module + ' ' + (f.remediation_title || '') + ' ' + JSON.stringify(f.details || {})).toLowerCase();
        if (query && !textBlob.includes(query)) return;

        const card = document.createElement('div');
        card.className = 'finding-card' + (isResolved ? ' resolved' : '');

        const sevClass = f.severity === 'ALERT' ? 'sev-alert' : (f.severity === 'WARN' ? 'sev-warn' : 'sev-info');

        // Build details table
        let detailsHtml = '';
        if (f.details && Object.keys(f.details).length > 0) {
          detailsHtml += '<table class="details-table">';
          for (let [k, v] of Object.entries(f.details)) {
            detailsHtml += `<tr><td class="td-key">${escapeHtml(k)}</td><td class="td-val">${escapeHtml(String(v))}</td></tr>`;
          }
          detailsHtml += '</table>';
        }

        // Build remediation steps
        let stepsHtml = '';
        if (f.remediation_steps && f.remediation_steps.length > 0) {
          f.remediation_steps.forEach(st => {
            let cmdBox = '';
            if (st.command) {
              const safeCmd = escapeHtml(st.command);
              cmdBox = `
                <div class="code-cmd-wrap">
                  <code>${safeCmd}</code>
                  <button class="copy-btn" onclick="copyToClipboard('${safeCmd.replace(/'/g, "\\'")}', this); event.stopPropagation();">Copy</button>
                </div>
              `;
            }
            stepsHtml += `
              <div class="step-item">
                <div class="step-header">${escapeHtml(st.phase || '')}</div>
                <div class="step-action">${escapeHtml(st.action || '')}</div>
                ${cmdBox}
              </div>
            `;
          });
        }

        card.innerHTML = `
          <div class="finding-header" onclick="toggleFinding(${idx})">
            <div class="finding-title-group">
              <span class="severity-tag ${sevClass}">${f.severity}</span>
              <div>
                <div class="finding-headline">${escapeHtml(f.message)}</div>
                <div class="finding-module">${escapeHtml(f.module || 'General')}</div>
              </div>
            </div>
            <div style="display: flex; align-items: center; gap: 0.75rem;">
              <label style="font-size: 0.75rem; color: var(--text-muted); display: flex; align-items: center; gap: 0.35rem; cursor: pointer;" onclick="event.stopPropagation();">
                <input type="checkbox" ${isResolved ? 'checked' : ''} onchange="toggleResolved(${idx}, event)">
                Resolved
              </label>
              <span style="font-size: 0.85rem; color: var(--text-dim);">▼</span>
            </div>
          </div>
          <div class="finding-body" id="findingBody_${idx}">
            ${detailsHtml}
            <div class="remediation-box">
              <div class="remediation-title">
                <span>🛠️</span> ${escapeHtml(f.remediation_title || 'Tactical Remediation Guide')}
              </div>
              <div class="remediation-threat">${escapeHtml(f.threat_analysis || '')}</div>
              ${stepsHtml}
            </div>
          </div>
        `;
        container.appendChild(card);
      });
    }

    function copyToClipboard(text, btn) {
      navigator.clipboard.writeText(text).then(() => {
        const orig = btn.innerText;
        btn.innerText = 'Copied!';
        setTimeout(() => btn.innerText = orig, 1500);
      });
    }

    function escapeHtml(str) {
      if (!str) return '';
      return String(str).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
    }

    function triggerManualUpload() {
      document.getElementById('manualFileInput').click();
    }

    async function handleFileSelected(event) {
      const file = event.target.files[0];
      if (!file) return;
      uploadFileContent(file);
    }

    function handleDrop(event) {
      event.preventDefault();
      if (event.dataTransfer.files.length > 0) {
        uploadFileContent(event.dataTransfer.files[0]);
      }
    }

    async function uploadFileContent(file) {
      const text = await file.text();
      let payload = null;
      try {
        payload = JSON.parse(text);
      } catch (e) {
        payload = { raw_log: text, filename: file.name };
      }

      const res = await fetch('/api/upload_report', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.report_id) {
        await loadReportsList();
        loadReport(data.report_id);
      }
    }

    function exportReportJson() {
      if (!activeReport) return;
      const blob = new Blob([JSON.stringify(activeReport, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${activeReport.scan_id || 'audit_report'}.json`;
      a.click();
    }

    // Auto-poll for incoming reports every 3 seconds
    setInterval(loadReportsList, 3000);
    window.onload = loadReportsList;
  </script>
</body>
</html>
"""

# ------------------------------------------------------------------------------
# Request Handler
# ------------------------------------------------------------------------------
class PortalRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path
        query = urllib.parse.parse_qs(parsed.query)

        # Health check
        if path == "/api/health":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "ok", "version": "1.0.0", "time": time.time()}).encode())
            return

        # List all reports
        if path == "/api/reports":
            reports_summary = []
            if os.path.exists(REPORTS_DIR):
                for fname in sorted(os.listdir(REPORTS_DIR), reverse=True):
                    if fname.endswith(".json"):
                        fpath = os.path.join(REPORTS_DIR, fname)
                        try:
                            with open(fpath, "r", encoding="utf-8") as f:
                                data = json.load(f)
                                stats = data.get("stats", {})
                                reports_summary.append({
                                    "id": data.get("scan_id", fname[:-5]),
                                    "timestamp": data.get("timestamp", "Recent"),
                                    "target_host": data.get("target_host", "Unknown Host"),
                                    "scan_type": data.get("host_type", "audit"),
                                    "alert_count": stats.get("alerts", 0),
                                    "warn_count": stats.get("warnings", 0),
                                    "info_count": stats.get("info", 0)
                                })
                        except Exception:
                            continue

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(reports_summary).encode())
            return

        # Get specific report details
        if path == "/api/report":
            report_id = query.get("id", [""])[0]
            # Sanitize report id
            safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", report_id)
            fpath = os.path.join(REPORTS_DIR, f"{safe_id}.json")

            if os.path.exists(fpath):
                with open(fpath, "r", encoding="utf-8") as f:
                    content = f.read()
                try:
                    data = json.loads(content)
                    data = enhance_report(data)
                    content = json.dumps(data)
                except Exception:
                    pass
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(content.encode())
            else:
                self.send_response(404)
                self.end_headers()
            return

        # Serve Main UI
        if path == "/" or path == "/index.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.end_headers()
            self.wfile.write(PORTAL_HTML.encode("utf-8"))
            return

        self.send_response(404)
        self.end_headers()

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        path = parsed.path

        if path == "/api/upload_report":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)

            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"error": f"Invalid JSON: {str(e)}"}).encode())
                return

            # Check if this is a raw log upload or structured report
            if "raw_log" in payload:
                report = parse_raw_text_report(payload["raw_log"])
            else:
                report = payload
                report = enhance_report(report)

            # Generate ID if missing
            scan_id = report.get("scan_id")
            if not scan_id:
                scan_id = f"scan_{datetime.utcnow().strftime('%Y%m%d_%H%M%S')}"
                report["scan_id"] = scan_id

            safe_id = re.sub(r"[^a-zA-Z0-9_\-]", "", scan_id)
            out_path = os.path.join(REPORTS_DIR, f"{safe_id}.json")

            with open(out_path, "w", encoding="utf-8") as f:
                json.dump(report, f, indent=2)

            print(f"[+] [PORTAL] Successfully ingested report: {safe_id} (Host: {report.get('target_host')})")

            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "success", "report_id": safe_id}).encode())
            return

        self.send_response(404)
        self.end_headers()

    def log_message(self, format, *args):
        # Clean logging
        sys.stderr.write(f"[*] [PORTAL] {self.address_string()} - {format % args}\n")


def start_server():
    server_address = (HOST, PORT)
    httpd = ThreadingHTTPServer(server_address, PortalRequestHandler)
    print("=" * 80)
    print(f"[*] CYBER DEFENSE INCIDENT RESPONSE & REMEDIATION PORTAL ONLINE")
    print(f"[*] Portal URL   : http://{HOST}:{PORT}")
    print(f"[*] Storage Dir  : {REPORTS_DIR}")
    print(f"[*] Listening for incoming audit reports from Windows, Linux, and Mobile...")
    print("=" * 80)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Shutting down portal server...")
        httpd.server_close()


if __name__ == "__main__":
    start_server()

