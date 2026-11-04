# 🛡️ The Watchdog (Cyber Defense Suite)

> **Production-Ready Multi-Platform Compromise Assessment, Rootkit Hunting & Incident Response Toolkit**  
> Comprehensive threat hunting, rootkit detection, and automated remediation for **Windows Endpoints**, **Linux VPS / cPanel Servers**, and **Android / iOS Mobile Devices**, backed by a local **Incident Response Portal** and tactical PDF field manuals.

---

## 📋 Table of Contents
1. [Overview & Threat Architecture](#overview--threat-architecture)
2. [Toolkit Components](#toolkit-components)
3. [Quick Start Guide](#quick-start-guide)
4. [Windows Compromise & Kernel Driver Auditor](#1-windows-endpoint--kernel-driver-auditor)
5. [Linux / VPS / cPanel Webshell & Rootkit Auditor](#2-linux-vps--cpanel-webshell--rootkit-auditor)
6. [Mobile Forensics & Spyware Orchestrator](#3-mobile-endpoint-forensics--mvt-orchestrator)
7. [Cyber Defense Remediation Portal](#4-cyber-defense-remediation-portal)
8. [Automated Tactical Manuals & Playbooks](#5-automated-tactical-playbooks--field-manuals)
9. [Telemetry & Logging Architecture](#telemetry--logging-architecture)
10. [Repository Structure](#repository-structure)

---

## Overview & Threat Architecture

Adversaries establish persistence and evade detection across modern systems using fileless mechanisms, kernel driver abuse (BYOVD), dynamic linker hijacking (`LD_PRELOAD`), living-off-the-land binaries (LOLBins), and mobile accessibility hooks. Standard antivirus scanners often overlook:
- In-memory WMI event subscriptions and scheduled tasks running encoded commands.
- Legitimate Bring-Your-Own-Vulnerable-Driver (BYOVD) exploits that bypass Driver Signature Enforcement.
- PHP webshells hidden in static upload folders using runtime obfuscation (`eval(base64_decode(...))`).
- Userland dynamic linker interception masking listening sockets and webshell files.
- Rogue user Root CA certificates decrypting mobile TLS traffic.

**The Watchdog** provides deep, non-destructive, multi-vector compromise assessments designed to discover active indicators of compromise (IOCs), extract forensic artifacts, classify defensive strengths vs. weaknesses ("What Went Well vs. What Went Wrong"), and guide incident responders through containment and eradication.

---

## Toolkit Components

| Component | Target Architecture | Execution Engine | Primary Output Artifacts |
|:---|:---|:---|:---|
| **`windows_compromise_audit.ps1`** | Windows 10/11, Server 2016–2025 | PowerShell 5.1 / 7+ (Admin) | `Compromise_Assessment_Report.txt`<br/>`console_execution.log`<br/>`Compromise_Report.json` |
| **`server_webshell_rootkit_audit.sh`** | Linux VPS, Dedicated, cPanel/SSH | Bash (`set -u`) | `server_security_audit_<TIMESTAMP>.log`<br/>`console_execution_<TIMESTAMP>.log`<br/>`server_security_audit_<TIMESTAMP>.json` |
| **`mobile_forensics_audit.sh`** | Android (ADB) & Apple iOS (USB) | Bash (`set -u`) + MVT | `mobile_audit_summary.txt`<br/>`console_execution_<TIMESTAMP>.log`<br/>`mobile_forensics_report.json` |
| **`portal_server.py`** | Incident Response Portal | Python 3.8+ (Zero dependencies) | Embedded Web Dashboard at `http://127.0.0.1:8888` |
| **`build_playbook_pdf.py`** | Operational Manual Generator | Python ReportLab | `cyber_defense_playbook.pdf` (8 Pages) |
| **`build_testing_guide_pdf.py`** | Lab Simulation Manual Generator | Python ReportLab | `audit_toolkit_testing_guide.pdf` (7 Pages) |

---

## Quick Start Guide

### 1. Launch the Cyber Defense Remediation Portal
```powershell
python portal_server.py
```
*Open your web browser at **`http://127.0.0.1:8888`** to monitor real-time audit ingestion, executive posture breakdowns, and tactical eradication commands.*

### 2. Run Windows Threat Hunting & Driver Audit
Open PowerShell as **Administrator**:
```powershell
powershell -ExecutionPolicy Bypass -File .\windows_compromise_audit.ps1
```
*The script automatically auto-spawns the portal if offline, exports triple-artifact telemetry, and opens the dashboard.*

### 3. Run Linux / VPS Web Server Audit
```bash
chmod +x ./server_webshell_rootkit_audit.sh
./server_webshell_rootkit_audit.sh /var/www/html
```

### 4. Run Mobile Forensics & Spyware Audit
Connect smartphone via USB with debugging enabled:
```bash
chmod +x ./mobile_forensics_audit.sh

# Android USB Audit:
./mobile_forensics_audit.sh android

# Apple iOS Backup & MVT Audit:
./mobile_forensics_audit.sh ios
```

---

## 1. Windows Endpoint & Kernel Driver Auditor

**File:** [`windows_compromise_audit.ps1`](windows_compromise_audit.ps1)  
**Privileges Required:** Administrator (`#Requires -RunAsAdministrator`)

### Modules Inspected:
1. **External Network Connections & Listeners:** Queries `Get-NetTCPConnection` for `Established` and `Listen` states (filtering loopback). Resolves owning processes, binary paths, and validates Authenticode digital signatures. Safely categorizes OS Kernel (PID 4) and Protected Process Light (PPL) services like `MsMpEng`.
2. **Unsigned Processes & User-Directory Executables:** Enumerates `Win32_Process`, checking `Get-AuthenticodeSignature` against user-writable directories (`AppData`, `Temp`, `Public`, `ProgramData`).
3. **WMI Event Subscription Persistence (Fileless Backdoors):** Inspects `root\subscription` for active `__EventFilter`, `__EventConsumer`, and `__FilterToConsumerBinding` instances while baselining standard Service Control Manager (SCM) providers.
4. **Registry Run Keys & Image File Execution Options (IFEO):** Audits `HKLM` and `HKCU` `Run`, `RunOnce`, `Winlogon`, and scans IFEO subkeys for rogue `Debugger` properties on accessibility utilities (`sethc.exe`, `utilman.exe`).
5. **Non-Standard Services & Unsigned Kernel Drivers:** Audits `Win32_Service` paths outside `System32`, whitelisting Microsoft-signed binaries while flagging unsigned or suspicious services. Scans all active `Win32_SystemDriver` entries for unsigned drivers (BYOVD / rootkit indicator).
6. **Anomalous Scheduled Tasks:** Inspects tasks outside `\Microsoft\` invoking LOLBins (`powershell`, `cmd`, `mshta`, `curl`, `certutil`) or executing encoded script commands.
7. **Windows Defender Exclusions & Tampering:** Audits `Get-MpPreference` for configured path/process exclusions and checks if real-time monitoring is disabled.
8. **Critical Event Log Indicators (Past 7 Days):** Scans Security Event ID `1102` (Audit Log Cleared) and System Event ID `7045` (New Service Installed).

---

## 2. Linux VPS & cPanel Webshell / Rootkit Auditor

**File:** [`server_webshell_rootkit_audit.sh`](server_webshell_rootkit_audit.sh)  
**Target:** Linux VPS, Dedicated Servers, Shared/cPanel Hosting running PHP/MySQL.

### Modules Inspected:
1. **PHP Webshell & RCE Scanner:** Scans `.php`, `.phtml`, `.phar`, and `.inc` files for high-risk primitives:
   - `eval\s*\(\s*(base64_decode|gzinflate|str_rot13)`
   - `shell_exec\s*\(`, `passthru\s*\(`, `proc_open\s*\(`, `popen\s*\(`
   - `assert\s*\(\s*\$_(GET|POST|REQUEST)`, `preg_replace\s*\(.*\/e`
   - `create_function\s*\(`, `system\s*\(\s*\$_(GET|POST|REQUEST|COOKIE)`
2. **Rogue Upload Directory Executables:** Flags scripts in static asset folders (`*upload*`, `*images*`, `*assets*`, `*cache*`, `*tmp*`).
3. **Recent File Modifications:** Identifies code modified in the last 7 days (`-mtime -7`).
4. **`.htaccess` Injections:** Detects `auto_prepend_file`, `auto_append_file`, and SEO cloaking rules.
5. **PHP Runtime Hardening & PHP2Shell:** Audits `session.upload_progress.enabled` (to prevent LFI race condition exploitation) and `allow_url_include`.
6. **Persistence Audit:** Dumps user crontabs, inspects `~/.ssh/authorized_keys`, and flags processes running from `/tmp`, `/var/tmp`, or `/dev/shm`.
7. **Userland Rootkit (`LD_PRELOAD`) & Sockets:** Checks `/etc/ld.so.preload` and dynamic environment variables; dumps listening sockets via `ss -tulnp`.
8. **World-Writable File Permissions:** Locates world-writable (`-perm -0002`) code and `.env` files.

---

## 3. Mobile Endpoint Forensics & MVT Orchestrator

**File:** [`mobile_forensics_audit.sh`](mobile_forensics_audit.sh)  
**Host Environment:** Linux, WSL2, or macOS with `adb`, `libimobiledevice`, and `mvt`.

### Modules Inspected:
1. **Android Verified Boot & SELinux:** Checks `ro.boot.verifiedbootstate` (expect `green`) and `getenforce` (expect `Enforcing`).
2. **Root & Su Binary Scanner:** Detects unauthorized `su` binaries across `/system/bin`, `/system/xbin`, and `/sbin`.
3. **Accessibility Stalkerware Vectors:** Audits `enabled_accessibility_services` for rogue keyloggers and screen tap interceptors.
4. **Device Admin Persistence:** Checks active device administrator privileges that block package uninstallation.
5. **Non-Play Store Sideloaded Packages:** Audits 3rd-party packages where `installer != com.android.vending`.
6. **Rogue User Root CA Certificates:** Scans `/data/misc/user/0/cacerts-added/` for user-installed trust anchors capable of intercepting TLS traffic.
7. **Active Network Listeners:** Dumps listening TCP/UDP sockets via ADB shell.
8. **Amnesty International STIX2 Spyware Matching:** Integrates `mvt-android` and `mvt-ios` with real-time STIX2 indicators for **NSO Group Pegasus**, **Predator**, and **Cytrox** spyware.
9. **Full iOS Forensic Backup Acquisition:** Automates `idevicebackup2 backup --full` over USB and conducts deep sqlite database triage.

---

## 4. Cyber Defense Remediation Portal

**File:** [`portal_server.py`](portal_server.py)  
**Port:** `8888` (Default URL: `http://127.0.0.1:8888`)  
**Dependencies:** Zero external libraries (built on standard Python `http.server`, `urllib`, `re`, `json`).

### Key Features:
- **Autonomous Auto-Spawn:** Starts automatically in the background when any audit script is executed.
- **Multi-Format Ingestion:** Accepts structured `.json` reports, raw `.log` execution logs, and `.txt` reports via REST API (`POST /api/upload_report`) or drag-and-drop.
- **Executive Posture Review ("What Went Well vs. What Went Wrong"):**
  - 🟢 **What Went Well:** Summarizes verified clean baselines (Real-time protection enabled, 0 WMI backdoors, clean kernel drivers, 0 IFEO overrides, clean event logs, 0 webshells, clean upload folders).
  - 🔴 **What Went Wrong:** Categorizes active threats (`[ALERT]`), blindspots (`[WARN]`), and any script execution exceptions (`[SCRIPT_ERROR]`), complete with one-click navigation to the remediation steps.
- **Composite Host Risk Meter (0–100%):** Weighted calculation updated dynamically as the operator marks items resolved.
- **4-Phase Remediation Guides:** Generates exact copyable commands for:
  - *Phase 1: Immediate Containment* (Host isolation, process termination)
  - *Phase 2: Forensic Staging* (Memory dumps, quarantine extraction)
  - *Phase 3: Eradication* (Persistence removal, firewall rule insertion)
  - *Phase 4: Post-Fix Verification* (Registry, service, and task inspection)
- **Embedded Console Execution Stream Viewer:** Collapsible terminal log viewer displaying real-time script execution traces and timestamps.

---

## 5. Automated Tactical Playbooks & Field Manuals

The workspace includes dedicated generator scripts using ReportLab to build PDF documentation:

### `cyber_defense_playbook.pdf` (8 Pages)
- **Generator:** [`build_playbook_pdf.py`](build_playbook_pdf.py)
- **Topics Covered:**
  - Executive Threat Architecture & The Reality of Modern Rootkits (Ring 0 vs. Ring 3).
  - Complete operational runbooks for Windows, Linux VPS/cPanel, and Mobile endpoints.
  - Incident Response Containment Protocols (NIST SP 800-61 Rev 2 alignment).
  - Remediation Portal architecture, REST API routes, and telemetric data flows.

### `audit_toolkit_testing_guide.pdf` (7 Pages)
- **Generator:** [`build_testing_guide_pdf.py`](build_testing_guide_pdf.py)
- **Topics Covered:**
  - Step-by-step laboratory testing on compromised or simulated test systems.
  - Atomic simulation commands to safely trigger each module's detection signals.
  - Expected console telemetry, JSON report signatures, and portal validation procedures.
  - Quality Assurance scorecard and sign-off verification matrix.

#### Recompiling the PDFs:
```bash
python build_playbook_pdf.py
python build_testing_guide_pdf.py
```

---

## Telemetry & Logging Architecture

When an assessment executes, it produces three distinct forensic files:
```
Windows_Audit_20261105_021500/
├── Compromise_Assessment_Report.txt   <-- Clean, human-readable forensic report
├── console_execution.log              <-- Verbatim terminal stream & transcript
├── Compromise_Report.json             <-- Machine-readable JSON telemetry
└── raw_evidence/                      <-- CSV dumps of processes, tasks, drivers
```

---

## Repository Structure

```
the-watchdog/
├── windows_compromise_audit.ps1      # Windows Endpoint & Kernel Driver Auditor
├── server_webshell_rootkit_audit.sh   # Linux VPS/cPanel Webshell & Rootkit Auditor
├── mobile_forensics_audit.sh          # Android ADB & iOS MVT Spyware Orchestrator
├── portal_server.py                   # Local Incident Response & Remediation Portal
├── build_playbook_pdf.py              # Tactical Field Manual PDF Generator
├── build_testing_guide_pdf.py         # Lab Validation & Testing Guide PDF Generator
├── cyber_defense_playbook.pdf         # Compiled 8-Page Tactical Playbook
├── audit_toolkit_testing_guide.pdf    # Compiled 7-Page Lab Testing Guide
├── portal_reports/                    # Ingested and baseline scan reports
│   ├── sample_windows_audit.json
│   ├── sample_linux_vps_audit.json
│   └── sample_mobile_forensic_audit.json
├── .gitignore                         # Build and runtime log ignore rules
└── README.md                          # Master documentation & operator guide
```

---

## ⚖️ Legal & Ethical Usage Notice
*This toolkit is developed exclusively for authorized compromise assessments, defensive posture audits, digital forensics, and incident response operations. Always ensure formal written authorization before performing audits on systems or networks you do not own.*

