#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Windows Endpoint, Kernel Driver & Persistence Compromise Assessment Toolkit.
.DESCRIPTION
    Production-ready threat hunting and compromise audit script for Windows 10/11 and Server 2016-2025.
    Audits 8 critical compromise vectors:
      1. External Network Connections & Suspicious Listeners
      2. Unsigned Processes & User-Directory Executables
      3. WMI Event Subscription Persistence (Fileless Backdoors)
      4. Registry Run Keys & Image File Execution Options (IFEO) Debugger Hijacks
      5. Non-Standard Services & Unsigned Running Kernel Drivers (BYOVD / Rootkits)
      6. Anomalous Scheduled Tasks (LOLBins & Encoded Commands)
      7. Windows Defender Exclusions & Tampering
      8. Critical Security & System Event Log Indicators (Event IDs 1102 & 7045)
.NOTES
    Author: Principal Red/Blue Team Systems Architect
    Platform: PowerShell 5.1 / PowerShell 7+ (Administrator Privileges Required)
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $false)]
    [string]$OutputDir
)

# Enforce Administrator Check
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Write-Error "[FATAL] This script requires administrative privileges. Please re-run PowerShell as Administrator."
    exit 1
}

# Setup Output Directory & Report File
$Timestamp = Get-Date -Format 'yyyyMMdd_HHmmss'
if (-not $OutputDir) {
    $OutputDir = Join-Path -Path $PSScriptRoot -ChildPath "Windows_Audit_$Timestamp"
}

if (-not (Test-Path -Path $OutputDir)) {
    $null = New-Item -ItemType Directory -Path $OutputDir -Force
}

$ReportFile = Join-Path -Path $OutputDir -ChildPath "Compromise_Assessment_Report.txt"
$ConsoleLogFile = Join-Path -Path $OutputDir -ChildPath "console_execution.log"
$CsvDir = Join-Path -Path $OutputDir -ChildPath "raw_evidence"
$null = New-Item -ItemType Directory -Path $CsvDir -Force

# Initialize dedicated console execution log & PowerShell transcript
try {
    Start-Transcript -Path $ConsoleLogFile -Append -Force -ErrorAction SilentlyContinue | Out-Null
} catch {}

# Audit Counters & Structured Findings
$Script:AlertCount = 0
$Script:WarnCount = 0
$Script:InfoCount = 0
$Script:CurrentSection = "General Audit"
$Script:StructuredFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

# Auto-Start Local Remediation Portal if Not Running
function Ensure-RemediationPortal {
    $portalUrl = "http://127.0.0.1:8888/api/health"
    $isAlive = $false
    try {
        $res = Invoke-RestMethod -Uri $portalUrl -TimeoutSec 1 -ErrorAction Stop
        if ($res.status -eq 'ok') { $isAlive = $true }
    } catch {
        $isAlive = $false
    }

    if (-not $isAlive) {
        $portalScript = Join-Path $PSScriptRoot "portal_server.py"
        if (-not (Test-Path $portalScript)) {
            $portalScript = Join-Path (Get-Location) "portal_server.py"
        }
        if (Test-Path $portalScript) {
            Write-Host "[*] Launching local Cyber Defense Portal (portal_server.py)..." -ForegroundColor Cyan
            try {
                Start-Process -FilePath "python" -ArgumentList "`"$portalScript`"" -WindowStyle Hidden -ErrorAction SilentlyContinue
                Start-Sleep -Seconds 2
            } catch {
                Write-Host "[!] Could not auto-launch python portal_server.py: $($_.Exception.Message)" -ForegroundColor Yellow
            }
        }
    }
}
Ensure-RemediationPortal

# Helper Logging Function
function Write-AuditLog {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [ValidateSet('INFO', 'WARN', 'ALERT', 'OK', 'HEADER', 'SECTION')]
        [string]$Level,

        [Parameter(Mandatory = $true)]
        [string]$Message,

        [Parameter(Mandatory = $false)]
        [hashtable]$Details
    )

    $timeStr = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss")
    $logLine = "[$timeStr] [$Level] $Message"

    switch ($Level) {
        'HEADER' {
            Write-Host "`n================================================================================" -ForegroundColor Cyan
            Write-Host " $Message" -ForegroundColor Cyan
            Write-Host "================================================================================" -ForegroundColor Cyan
            $logLine = "`n================================================================================`n $Message`n================================================================================"
        }
        'SECTION' {
            $Script:CurrentSection = $Message
            Write-Host "`n--- [MODULE: $Message] ---" -ForegroundColor Cyan
            $logLine = "`n--- [MODULE: $Message] ---"
        }
        'ALERT' {
            Write-Host "[-] $logLine" -ForegroundColor Red
            $Script:AlertCount++
            $detObj = [ordered]@{}
            if ($Details) { foreach ($k in $Details.Keys) { $detObj[$k] = [string]$Details[$k] } }
            $Script:StructuredFindings.Add([PSCustomObject]@{
                severity = 'ALERT'
                module   = $Script:CurrentSection
                message  = $Message
                details  = $detObj
            })
        }
        'WARN' {
            Write-Host "[!] $logLine" -ForegroundColor Yellow
            $Script:WarnCount++
            $detObj = [ordered]@{}
            if ($Details) { foreach ($k in $Details.Keys) { $detObj[$k] = [string]$Details[$k] } }
            $Script:StructuredFindings.Add([PSCustomObject]@{
                severity = 'WARN'
                module   = $Script:CurrentSection
                message  = $Message
                details  = $detObj
            })
        }
        'OK' {
            Write-Host "[+] $logLine" -ForegroundColor Green
            $Script:InfoCount++
        }
        'INFO' {
            Write-Host "[*] $logLine" -ForegroundColor Gray
            $Script:InfoCount++
        }
    }

    Add-Content -Path $ReportFile -Value $logLine
    Add-Content -Path $ConsoleLogFile -Value $logLine -ErrorAction SilentlyContinue

    if ($Details -and $Details.Count -gt 0) {
        foreach ($key in $Details.Keys) {
            $detailLine = "      $key : $($Details[$key])"
            if ($Level -eq 'ALERT') {
                Write-Host $detailLine -ForegroundColor DarkRed
            } elseif ($Level -eq 'WARN') {
                Write-Host $detailLine -ForegroundColor DarkYellow
            } else {
                Write-Host $detailLine -ForegroundColor DarkGray
            }
            Add-Content -Path $ReportFile -Value $detailLine
            Add-Content -Path $ConsoleLogFile -Value $detailLine -ErrorAction SilentlyContinue
        }
    }
}

# Path Resolver Helper
function Resolve-NormalizedBinaryPath {
    param([string]$RawPath)

    if ([string]::IsNullOrWhiteSpace($RawPath)) { return $null }

    $clean = $RawPath.Trim()

    # Strip surrounding quotes
    if ($clean -match '^"([^"]+)"') {
        $clean = $matches[1]
    } elseif ($clean -match '^([^\s]+)') {
        # Check if argument split needed
        if (-not (Test-Path -Path $clean -ErrorAction SilentlyContinue)) {
            $firstToken = ($clean -split '\s+')[0]
            if (Test-Path -Path $firstToken -ErrorAction SilentlyContinue) {
                $clean = $firstToken
            }
        }
    }

    # Remove Device/Kernel prefix
    if ($clean -like '\??\*') {
        $clean = $clean.Substring(4)
    }
    if ($clean -like '\SystemRoot\*') {
        $clean = $clean.Replace('\SystemRoot\', "$env:SystemRoot\")
    }
    if ($clean -like 'system32\*') {
        $clean = Join-Path $env:SystemRoot $clean
    }

    # Expand environment variables
    $clean = [Environment]::ExpandEnvironmentVariables($clean)

    if (Test-Path -Path $clean -ErrorAction SilentlyContinue) {
        return (Get-Item -Path $clean -ErrorAction SilentlyContinue).FullName
    }

    return $clean
}

# User-Writable Path Checker
function Test-UserWritablePath {
    param([string]$Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return $false }
    # Whitelist legitimate protected Microsoft Defender platform directories in ProgramData
    if ($Path -match '(?i)^[A-Z]:\\ProgramData\\Microsoft\\Windows Defender') {
        return $false
    }
    $regex = '(?i)(\\Users\\[^\\]+\\AppData|\\Users\\Public|\\Windows\\Temp|\\PerfLogs|\\ProgramData|\\Temp\\|^[A-Z]:\\Temp)'
    return ($Path -match $regex)
}

# ==============================================================================
# AUDIT BANNER
# ==============================================================================
$os = Get-CimInstance Win32_OperatingSystem
$comp = Get-CimInstance Win32_ComputerSystem
Write-AuditLog -Level HEADER -Message "WINDOWS COMPROMISE ASSESSMENT & ROOTKIT AUDIT TOOLKIT"
Write-AuditLog -Level INFO -Message "Target Host: $($comp.Name) ($($comp.Domain)) | Domain Role: $($comp.DomainRole)"
Write-AuditLog -Level INFO -Message "Operating System: $($os.Caption) (Build: $($os.BuildNumber), Version: $($os.Version))"
Write-AuditLog -Level INFO -Message "Report Location: $ReportFile"
Write-AuditLog -Level INFO -Message "Audit Start Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss UTCzz')"

# ==============================================================================
# MODULE 1: External Network Connections & Suspicious Listeners
# ==============================================================================
Write-AuditLog -Level SECTION -Message "1. External Network Connections & Suspicious Listeners"

try {
    $connections = Get-NetTCPConnection -State Established, Listen -ErrorAction Stop
    $procCache = @{}
    $suspiciousConnFound = $false

    foreach ($conn in $connections) {
        # Exclude loopback and unspecified addresses
        $isLocalLoop = ($conn.LocalAddress -match '^127\.' -or $conn.LocalAddress -eq '::1' -or $conn.LocalAddress -eq '0.0.0.0' -or $conn.LocalAddress -eq '::')
        $isRemoteLoop = ($conn.RemoteAddress -match '^127\.' -or $conn.RemoteAddress -eq '::1' -or $conn.RemoteAddress -eq '0.0.0.0' -or $conn.RemoteAddress -eq '::')

        if ($conn.State -eq 'Listen' -and $isLocalLoop) {
            continue
        }
        if ($conn.State -eq 'Established' -and $isRemoteLoop) {
            continue
        }

        $pidVal = $conn.OwningProcess

        # Handle Windows Kernel System Process (PID 4) and Idle (PID 0)
        if ($pidVal -eq 0 -or $pidVal -eq 4) {
            continue # Kernel NetBIOS/SMB listeners are normal OS kernel functions
        }

        if (-not $procCache.ContainsKey($pidVal)) {
            $procObj = Get-Process -Id $pidVal -ErrorAction SilentlyContinue
            $procPath = $null
            if ($procObj) {
                try { $procPath = $procObj.Path } catch { $procPath = $null }
                if (-not $procPath) {
                    try {
                        $wmiProc = Get-CimInstance Win32_Process -Filter "ProcessId = $pidVal" -ErrorAction SilentlyContinue
                        $procPath = $wmiProc.ExecutablePath
                    } catch { $procPath = $null }
                }

                # Resolve Microsoft Defender Service (MsMpEng is PPL protected)
                if (-not $procPath -and $procObj.Name -match '(?i)MsMpEng') {
                    try {
                        $defSvc = Get-CimInstance Win32_Service -Filter "Name = 'WinDefend'" -ErrorAction SilentlyContinue
                        if ($defSvc.PathName) {
                            $procPath = Resolve-NormalizedBinaryPath -RawPath $defSvc.PathName
                        }
                    } catch { }
                }
            }
            $procCache[$pidVal] = [PSCustomObject]@{
                Name = if ($procObj) { $procObj.Name } else { "PID-$pidVal" }
                Path = $procPath
            }
        }

        $cached = $procCache[$pidVal]
        $procName = $cached.Name
        $execPath = $cached.Path

        $sigStatus = "Unknown"
        $signer = "None"
        if ($execPath -and (Test-Path -Path $execPath -ErrorAction SilentlyContinue)) {
            $sig = Get-AuthenticodeSignature -FilePath $execPath -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate) {
                    $signer = $sig.SignerCertificate.Subject
                }
            }
        }

        $isUnsigned = ($execPath -and ($sigStatus -ne 'Valid'))
        $isUserPath = Test-UserWritablePath -Path $execPath

        if ($isUnsigned -or ($isUserPath -and $execPath)) {
            $suspiciousConnFound = $true
            $details = [ordered]@{
                "Process"          = "$procName (PID: $pidVal)"
                "BinaryPath"       = $execPath
                "State"            = $conn.State
                "LocalEndpoint"    = "$($conn.LocalAddress):$($conn.LocalPort)"
                "RemoteEndpoint"   = "$($conn.RemoteAddress):$($conn.RemotePort)"
                "SignatureStatus"  = $sigStatus
                "SignerSubject"    = $signer
                "UserWritablePath" = $isUserPath
            }
            Write-AuditLog -Level ALERT -Message "Suspicious active connection mapped to unsigned or user-path binary: $procName" -Details $details
        }
    }

    if (-not $suspiciousConnFound) {
        Write-AuditLog -Level OK -Message "No unsigned binaries or user-directory processes found holding external sockets."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Error inspecting TCP connections: $($_.Exception.Message)"
}

# ==============================================================================
# MODULE 2: Unsigned Processes & User-Directory Executables
# ==============================================================================
Write-AuditLog -Level SECTION -Message "2. Unsigned Processes & User-Directory Executables"

try {
    $processes = Get-CimInstance Win32_Process -ErrorAction Stop
    $anomalyProcessFound = $false

    foreach ($proc in $processes) {
        $currentProcId = $proc.ProcessId
        if ($currentProcId -eq 0 -or $currentProcId -eq 4) { continue } # Skip System Idle and System

        $execPath = Resolve-NormalizedBinaryPath -RawPath $proc.ExecutablePath
        $cmdLine = $proc.CommandLine
        $parentPid = $proc.ParentProcessId
        $procName = $proc.Name

        $sigStatus = "MissingFile"
        $signer = "None"

        if ($execPath -and (Test-Path -Path $execPath -ErrorAction SilentlyContinue)) {
            $sig = Get-AuthenticodeSignature -FilePath $execPath -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate) {
                    $signer = $sig.SignerCertificate.Subject
                }
            }
        } elseif ([string]::IsNullOrWhiteSpace($execPath)) {
            $sigStatus = "NoPathReported"
        }

        $isUnsigned = ($sigStatus -ne 'Valid')
        $isUserDir = Test-UserWritablePath -Path $execPath

        $procDetails = [ordered]@{
            "ProcessName"     = $procName
            "ProcessID"       = $currentProcId
            "ParentProcessID" = $parentPid
            "ExecutablePath"  = $execPath
            "SignatureStatus" = $sigStatus
            "SignerSubject"   = $signer
            "CommandLine"     = $cmdLine
        }

        if ($isUnsigned -and $isUserDir) {
            $anomalyProcessFound = $true
            Write-AuditLog -Level ALERT -Message "CRITICAL: Unsigned process executing from user-writable directory: $procName (PID: $currentProcId)" -Details $procDetails
        } elseif ($isUnsigned) {
            # Check if it's outside System32
            if ($execPath -notmatch '(?i)^[A-Z]:\\Windows\\System32\\') {
                $anomalyProcessFound = $true
                Write-AuditLog -Level WARN -Message "Unsigned running process outside standard System32: $procName (PID: $currentProcId)" -Details $procDetails
            }
        } elseif ($isUserDir) {
            $anomalyProcessFound = $true
            Write-AuditLog -Level WARN -Message "Signed process executing from user-writable staging directory: $procName (PID: $currentProcId)" -Details $procDetails
        }
    }

    if (-not $anomalyProcessFound) {
        Write-AuditLog -Level OK -Message "No unsigned processes running from user-writable directories detected."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Error inspecting running processes: $($_.Exception.Message)"
}

# ==============================================================================
# MODULE 3: WMI Event Subscription Persistence (Fileless Backdoors)
# ==============================================================================
Write-AuditLog -Level SECTION -Message "3. WMI Event Subscription Persistence (Fileless Backdoors)"

try {
    $wmiNamespace = "root\subscription"
    $filters = Get-CimInstance -Namespace $wmiNamespace -ClassName __EventFilter -ErrorAction SilentlyContinue
    $consumers = Get-CimInstance -Namespace $wmiNamespace -ClassName __EventConsumer -ErrorAction SilentlyContinue
    $bindings = Get-CimInstance -Namespace $wmiNamespace -ClassName __FilterToConsumerBinding -ErrorAction SilentlyContinue
    $cmdConsumers = Get-CimInstance -Namespace $wmiNamespace -ClassName CommandLineEventConsumer -ErrorAction SilentlyContinue
    $scriptConsumers = Get-CimInstance -Namespace $wmiNamespace -ClassName ActiveScriptEventConsumer -ErrorAction SilentlyContinue

    $wmiThreatFound = $false

    if ($filters) {
        foreach ($flt in $filters) {
            if ($flt.Name -eq 'SCM Event Log Filter') {
                Write-AuditLog -Level INFO -Message "Default Windows Service Control Manager Event Log filter audited: $($flt.Name)"
                continue
            }
            $wmiThreatFound = $true
            $fltDetails = [ordered]@{
                "FilterName"      = $flt.Name
                "QueryLanguage"   = $flt.QueryLanguage
                "EventQuery"      = $flt.Query
                "EventNamespace"  = $flt.EventNamespace
            }
            Write-AuditLog -Level ALERT -Message "Active WMI Event Filter detected: $($flt.Name)" -Details $fltDetails
        }
    }

    if ($cmdConsumers) {
        foreach ($cc in $cmdConsumers) {
            $wmiThreatFound = $true
            $ccDetails = [ordered]@{
                "ConsumerName"        = $cc.Name
                "CommandLineTemplate" = $cc.CommandLineTemplate
                "ExecutablePath"      = $cc.ExecutablePath
                "WorkingDirectory"    = $cc.WorkingDirectory
            }
            Write-AuditLog -Level ALERT -Message "Active WMI CommandLineEventConsumer detected (Fileless execution vector): $($cc.Name)" -Details $ccDetails
        }
    }

    if ($scriptConsumers) {
        foreach ($sc in $scriptConsumers) {
            $wmiThreatFound = $true
            $scDetails = [ordered]@{
                "ConsumerName"   = $sc.Name
                "ScriptingEngine"= $sc.ScriptingEngine
                "ScriptText"     = if ($sc.ScriptText.Length -gt 200) { $sc.ScriptText.Substring(0, 200) + "... [TRUNCATED]" } else { $sc.ScriptText }
                "ScriptFileName" = $sc.ScriptFileName
            }
            Write-AuditLog -Level ALERT -Message "Active WMI ActiveScriptEventConsumer detected (Embedded script persistence): $($sc.Name)" -Details $scDetails
        }
    }

    if ($bindings) {
        foreach ($b in $bindings) {
            Write-AuditLog -Level WARN -Message "WMI Filter-To-Consumer Binding: Filter=[$($b.Filter)] -> Consumer=[$($b.Consumer)]"
        }
    }

    if (-not $wmiThreatFound) {
        Write-AuditLog -Level OK -Message "No active WMI event filters, CommandLineConsumers, or ActiveScriptConsumers detected in root\subscription."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Error accessing root\subscription WMI namespace: $($_.Exception.Message)"
}

# ==============================================================================
# MODULE 4: Registry Run Keys & Image File Execution Options (IFEO)
# ==============================================================================
Write-AuditLog -Level SECTION -Message "4. Registry Run Keys & Image File Execution Options (IFEO)"

$regRunKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
)

$suspiciousPattern = '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|curl|certutil|bitsadmin|Users\\[^\\]+\\AppData|Windows\\Temp|Users\\Public|ProgramData)'

foreach ($keyPath in $regRunKeys) {
    if (Test-Path -Path $keyPath) {
        try {
            $regItem = Get-Item -Path $keyPath -ErrorAction Stop
            $values = $regItem.GetValueNames()
            foreach ($valName in $values) {
                if ([string]::IsNullOrWhiteSpace($valName)) { continue }
                $valData = $regItem.GetValue($valName)

                $isSuspicious = ($valData -match $suspiciousPattern)
                $resolvedPath = Resolve-NormalizedBinaryPath -RawPath $valData
                $isUserPath = Test-UserWritablePath -Path $resolvedPath

                $details = [ordered]@{
                    "RegistryKey" = $keyPath
                    "ValueName"   = $valName
                    "ValueData"   = $valData
                    "Resolved"    = $resolvedPath
                }

                if ($isSuspicious -or $isUserPath) {
                    Write-AuditLog -Level ALERT -Message "Suspicious Registry Persistence entry invoking LOLBin or user-writable path: $valName" -Details $details
                } else {
                    Write-AuditLog -Level INFO -Message "Registry Run entry audited: [$keyPath] $valName = $valData"
                }
            }
        } catch {
            Write-AuditLog -Level WARN -Message "Could not read Registry key $keyPath : $($_.Exception.Message)"
        }
    }
}

# Audit Winlogon Keys
$winlogonKey = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
if (Test-Path -Path $winlogonKey) {
    try {
        $wl = Get-ItemProperty -Path $winlogonKey -ErrorAction Stop
        $shellVal = $wl.Shell
        $userinitVal = $wl.Userinit

        if ($shellVal -and ($shellVal -ne 'explorer.exe' -and $shellVal -notmatch '(?i)^explorer\.exe$')) {
            Write-AuditLog -Level ALERT -Message "Tampered Winlogon Shell detected: '$shellVal' (Expected: explorer.exe)" -Details @{ "Key" = $winlogonKey; "Shell" = $shellVal }
        }
        if ($userinitVal -and ($userinitVal -notmatch '(?i)^C:\\Windows\\system32\\userinit\.exe,?$')) {
            Write-AuditLog -Level ALERT -Message "Tampered Winlogon Userinit detected: '$userinitVal' (Expected: C:\Windows\system32\userinit.exe,)" -Details @{ "Key" = $winlogonKey; "Userinit" = $userinitVal }
        }
    } catch {
        Write-AuditLog -Level WARN -Message "Error auditing Winlogon registry keys: $($_.Exception.Message)"
    }
}

# Audit Image File Execution Options (IFEO) Debugger Backdoors
$ifeoPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
$ifeoBackdoorsFound = $false

if (Test-Path -Path $ifeoPath) {
    try {
        $subKeys = Get-ChildItem -Path $ifeoPath -ErrorAction Stop
        foreach ($sub in $subKeys) {
            $debuggerVal = $sub.GetValue("Debugger")
            if ($debuggerVal) {
                $ifeoBackdoorsFound = $true
                $targetBinary = $sub.PSChildName
                $details = [ordered]@{
                    "TargetBinary"     = $targetBinary
                    "ConfiguredDebugger" = $debuggerVal
                    "SubKey"           = $sub.Name
                }
                Write-AuditLog -Level ALERT -Message "IFEO Debugger Backdoor detected on '$targetBinary'! Execution intercepted by: $debuggerVal" -Details $details
            }
        }
        if (-not $ifeoBackdoorsFound) {
            Write-AuditLog -Level OK -Message "No IFEO Debugger persistence hooks detected."
        }
    } catch {
        Write-AuditLog -Level WARN -Message "Error auditing IFEO registry keys: $($_.Exception.Message)"
    }
}

# ==============================================================================
# MODULE 5: Non-Standard Services & Unsigned Running Kernel Drivers
# ==============================================================================
Write-AuditLog -Level SECTION -Message "5. Non-Standard Services & Unsigned Running Kernel Drivers"

# Service Audit
try {
    $services = Get-CimInstance Win32_Service -ErrorAction Stop
    $anomalousServiceFound = $false

    foreach ($svc in $services) {
        $rawPath = $svc.PathName
        if ([string]::IsNullOrWhiteSpace($rawPath)) { continue }

        $resolved = Resolve-NormalizedBinaryPath -RawPath $rawPath
        $isStandardSystem = ($resolved -match '(?i)^[A-Z]:\\Windows\\(System32|SysWOW64|servicing|WinSxS)\\')

        if (-not $isStandardSystem) {
            $isUserDir = Test-UserWritablePath -Path $resolved
            $isShellInvoke = ($rawPath -match '(?i)(cmd\.exe|powershell|wscript|cscript|mshta|rundll32)')

            $sigStatus = "MissingFile"
            $signer = "None"
            if ($resolved -and (Test-Path -Path $resolved -ErrorAction SilentlyContinue)) {
                $sig = Get-AuthenticodeSignature -FilePath $resolved -ErrorAction SilentlyContinue
                if ($sig) {
                    $sigStatus = $sig.Status.ToString()
                    if ($sig.SignerCertificate) { $signer = $sig.SignerCertificate.Subject }
                }
            }

            $svcDetails = [ordered]@{
                "ServiceName"     = $svc.Name
                "DisplayName"     = $svc.DisplayName
                "State"           = $svc.State
                "StartMode"       = $svc.StartMode
                "PathName"        = $rawPath
                "ResolvedPath"    = $resolved
                "SignatureStatus" = $sigStatus
                "Signer"          = $signer
            }

            $isMicrosoftSigned = ($sigStatus -eq 'Valid' -and ($signer -match 'Microsoft Windows|Microsoft Corporation'))

            if ($isMicrosoftSigned) {
                Write-AuditLog -Level INFO -Message "Verified Microsoft platform service: $($svc.Name)"
            } elseif ($isShellInvoke -or ($isUserDir -and $sigStatus -ne 'Valid')) {
                $anomalousServiceFound = $true
                Write-AuditLog -Level ALERT -Message "High-Risk Non-Standard Service detected: $($svc.Name)" -Details $svcDetails
            } elseif ($sigStatus -ne 'Valid') {
                $anomalousServiceFound = $true
                Write-AuditLog -Level WARN -Message "Unsigned non-standard service outside System32: $($svc.Name)" -Details $svcDetails
            } else {
                # Validly signed 3rd-party commercial service (e.g. Seagate, Intel, Asus)
                Write-AuditLog -Level INFO -Message "Third-party signed service: $($svc.Name) (Signer: $signer)"
            }
        }
    }

    if (-not $anomalousServiceFound) {
        Write-AuditLog -Level OK -Message "No unsigned or shell-invoking services detected in non-standard paths."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Error inspecting Win32_Service: $($_.Exception.Message)"
}

# Kernel Driver Rootkit Audit (State = Running)
try {
    $drivers = Get-CimInstance Win32_SystemDriver -Filter "State = 'Running'" -ErrorAction Stop
    $unsignedDriverFound = $false

    foreach ($drv in $drivers) {
        $rawDrvPath = $drv.PathName
        $resolvedDrv = Resolve-NormalizedBinaryPath -RawPath $rawDrvPath

        $sigStatus = "Unknown"
        $signer = "None"

        if ($resolvedDrv -and (Test-Path -Path $resolvedDrv -ErrorAction SilentlyContinue)) {
            $sig = Get-AuthenticodeSignature -FilePath $resolvedDrv -ErrorAction SilentlyContinue
            if ($sig) {
                $sigStatus = $sig.Status.ToString()
                if ($sig.SignerCertificate) {
                    $signer = $sig.SignerCertificate.Subject
                }
            }
        } elseif ([string]::IsNullOrWhiteSpace($resolvedDrv)) {
            $sigStatus = "NoPathReported"
        } else {
            $sigStatus = "FileNotFoundOnDisk"
        }

        if ($sigStatus -ne 'Valid') {
            $unsignedDriverFound = $true
            $drvDetails = [ordered]@{
                "DriverName"      = $drv.Name
                "DisplayName"     = $drv.DisplayName
                "State"           = $drv.State
                "RawPath"         = $rawDrvPath
                "ResolvedPath"    = $resolvedDrv
                "SignatureStatus" = $sigStatus
                "Signer"          = $signer
            }
            Write-AuditLog -Level ALERT -Message "CRITICAL ROOTKIT INDICATOR: Unsigned running kernel driver: $($drv.Name)" -Details $drvDetails
        }
    }

    if (-not $unsignedDriverFound) {
        Write-AuditLog -Level OK -Message "All active running kernel drivers possess valid digital signatures."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Error inspecting Win32_SystemDriver: $($_.Exception.Message)"
}

# ==============================================================================
# MODULE 6: Anomalous Scheduled Tasks
# ==============================================================================
Write-AuditLog -Level SECTION -Message "6. Anomalous Scheduled Tasks (LOLBins & Stagers)"

try {
    $tasks = Get-ScheduledTask -ErrorAction Stop | Where-Object {
        $_.TaskPath -notmatch '^\\Microsoft\\' -and $_.State -ne 'Disabled'
    }

    $lolbinPattern = '(?i)(powershell|cmd\.exe|wscript|cscript|mshta|curl|certutil|bitsadmin|rundll32|regsvr32)'
    $suspiciousArgsPattern = '(?i)(-enc|-encodedcommand|-e\s+|Hidden|Bypass|DownloadString|DownloadFile|IEX|Invoke-Expression|http:\/\/|https:\/\/)'
    $anomalousTaskFound = $false

    foreach ($task in $tasks) {
        $actions = $task.Actions
        foreach ($act in $actions) {
            $exec = $act.Execute
            $args = $act.Arguments

            $isLolbin = ($exec -and ($exec -match $lolbinPattern))
            $hasSuspiciousArgs = ($args -and ($args -match $suspiciousArgsPattern))
            $resolvedExec = Resolve-NormalizedBinaryPath -RawPath $exec
            $isUserPath = Test-UserWritablePath -Path $resolvedExec

            $taskDetails = [ordered]@{
                "TaskName"     = $task.TaskName
                "TaskPath"     = $task.TaskPath
                "State"        = $task.State
                "Execute"      = $exec
                "Arguments"    = $args
                "ResolvedExec" = $resolvedExec
                "Author"       = $task.Author
            }

            $taskSigStatus = "Unknown"
            if ($resolvedExec -and (Test-Path -Path $resolvedExec -ErrorAction SilentlyContinue)) {
                $tsig = Get-AuthenticodeSignature -FilePath $resolvedExec -ErrorAction SilentlyContinue
                if ($tsig) { $taskSigStatus = $tsig.Status.ToString() }
            }

            if ($isLolbin -or $hasSuspiciousArgs -or ($isUserPath -and $taskSigStatus -ne 'Valid')) {
                $anomalousTaskFound = $true
                Write-AuditLog -Level ALERT -Message "Suspicious non-Microsoft Scheduled Task detected: $($task.TaskName)" -Details $taskDetails
            } elseif ($isUserPath) {
                # Signed 3rd-party user updater (e.g. GoToMeeting, OneDrive, Google Update)
                Write-AuditLog -Level WARN -Message "Signed 3rd-party task executing from user path: $($task.TaskName)" -Details $taskDetails
            } else {
                Write-AuditLog -Level INFO -Message "Audited active 3rd-party task: $($task.TaskName) -> $exec"
            }
        }
    }

    if (-not $anomalousTaskFound) {
        Write-AuditLog -Level OK -Message "No suspicious scheduled tasks utilizing LOLBins or suspicious arguments detected."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Error inspecting Scheduled Tasks: $($_.Exception.Message)"
}

# ==============================================================================
# MODULE 7: Windows Defender Exclusions & Tampering
# ==============================================================================
Write-AuditLog -Level SECTION -Message "7. Windows Defender Exclusions & Tampering"

try {
    $mpPref = Get-MpPreference -ErrorAction Stop
    $tamperFound = $false

    # Check Real-Time Protection
    if ($mpPref.DisableRealtimeMonitoring -eq $true) {
        $tamperFound = $true
        Write-AuditLog -Level ALERT -Message "CRITICAL: Windows Defender Real-time Monitoring is DISABLED (DisableRealtimeMonitoring = True)!"
    } else {
        Write-AuditLog -Level OK -Message "Windows Defender Real-time Monitoring is active."
    }

    # Check Behavior Monitoring
    if ($mpPref.DisableBehaviorMonitoring -eq $true) {
        $tamperFound = $true
        Write-AuditLog -Level ALERT -Message "CRITICAL: Windows Defender Behavior Monitoring is DISABLED!"
    }

    # Check IOAV (Downloaded files)
    if ($mpPref.DisableIOAVProtection -eq $true) {
        $tamperFound = $true
        Write-AuditLog -Level ALERT -Message "CRITICAL: Defender IOAV Protection (attachment/download scanning) is DISABLED!"
    }

    # Check Script Scanning
    if ($mpPref.DisableScriptScanning -eq $true) {
        $tamperFound = $true
        Write-AuditLog -Level ALERT -Message "CRITICAL: Defender Script Scanning (AMSI) is DISABLED!"
    }

    # Check Exclusion Paths
    if ($mpPref.ExclusionPath -and $mpPref.ExclusionPath.Count -gt 0) {
        foreach ($exPath in $mpPref.ExclusionPath) {
            $tamperFound = $true
            Write-AuditLog -Level ALERT -Message "Defender Path Exclusion Configured (Potential Blindspot): $exPath" -Details @{ "ExclusionPath" = $exPath }
        }
    }

    # Check Exclusion Processes
    if ($mpPref.ExclusionProcess -and $mpPref.ExclusionProcess.Count -gt 0) {
        foreach ($exProc in $mpPref.ExclusionProcess) {
            $tamperFound = $true
            Write-AuditLog -Level ALERT -Message "Defender Process Exclusion Configured: $exProc" -Details @{ "ExclusionProcess" = $exProc }
        }
    }

    # Check Exclusion Extensions
    if ($mpPref.ExclusionExtension -and $mpPref.ExclusionExtension.Count -gt 0) {
        foreach ($exExt in $mpPref.ExclusionExtension) {
            $tamperFound = $true
            Write-AuditLog -Level ALERT -Message "Defender Extension Exclusion Configured: $exExt"
        }
    }

    # Check Exclusion IPs
    if ($mpPref.ExclusionIpAddress -and $mpPref.ExclusionIpAddress.Count -gt 0) {
        foreach ($exIp in $mpPref.ExclusionIpAddress) {
            $tamperFound = $true
            Write-AuditLog -Level ALERT -Message "Defender IP Exclusion Configured: $exIp"
        }
    }

    if (-not $tamperFound) {
        Write-AuditLog -Level OK -Message "Windows Defender has zero exclusions configured and all real-time protections are fully active."
    }
} catch {
    Write-AuditLog -Level WARN -Message "Unable to query Get-MpPreference (Defender service may be disabled, replaced by 3rd party EDR, or restricted): $($_.Exception.Message)"
}

# ==============================================================================
# MODULE 8: Critical Security & System Event Log Indicators (Last 7 Days)
# ==============================================================================
Write-AuditLog -Level SECTION -Message "8. Critical Security & System Event Log Indicators (Past 7 Days)"

$sevenDaysAgo = (Get-Date).AddDays(-7)

# Security Log: Event ID 1102 (Audit log cleared)
try {
    $clearedEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'Security'
        Id        = 1102
        StartTime = $sevenDaysAgo
    } -ErrorAction Stop

    foreach ($evt in $clearedEvents) {
        $evtDetails = [ordered]@{
            "EventID"     = $evt.Id
            "TimeCreated" = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
            "User"        = $evt.UserId
            "Message"     = $evt.Message
        }
        Write-AuditLog -Level ALERT -Message "SECURITY EVENT LOG CLEARED (Event ID 1102) - Forensic anti-forensic tampering indicator!" -Details $evtDetails
    }
} catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-AuditLog -Level OK -Message "No Security Event Log clearing events (ID 1102) detected in the last 7 days."
    } else {
        Write-AuditLog -Level INFO -Message "Security Log query note: $($_.Exception.Message)"
    }
}

# System Log: Event ID 7045 (New service installed)
try {
    $newServiceEvents = Get-WinEvent -FilterHashtable @{
        LogName   = 'System'
        Id        = 7045
        StartTime = $sevenDaysAgo
    } -ErrorAction Stop

    if ($newServiceEvents) {
        Write-AuditLog -Level WARN -Message "Found $($newServiceEvents.Count) newly installed services in the System event log (Event ID 7045) over the past 7 days:"
        foreach ($evt in $newServiceEvents) {
            $msgSnippet = ($evt.Message -split "`r`n")[0..3] -join " | "
            $evtDetails = [ordered]@{
                "EventID"     = $evt.Id
                "TimeCreated" = $evt.TimeCreated.ToString("yyyy-MM-dd HH:mm:ss")
                "Summary"     = $msgSnippet
            }
            Write-AuditLog -Level WARN -Message "New Service Installed: $($evt.TimeCreated)" -Details $evtDetails
        }
    }
} catch {
    if ($_.Exception.Message -match "No events were found") {
        Write-AuditLog -Level OK -Message "No new service installation events (ID 7045) detected in the last 7 days."
    } else {
        Write-AuditLog -Level INFO -Message "System Log query note: $($_.Exception.Message)"
    }
}

# ==============================================================================
# AUDIT SUMMARY & REMEDIATION NEXT STEPS
# ==============================================================================
Write-AuditLog -Level HEADER -Message "EXECUTIVE AUDIT SUMMARY"
Write-AuditLog -Level INFO -Message "Total Critical Alerts [ALERT] : $Script:AlertCount"
Write-AuditLog -Level INFO -Message "Total Warnings         [WARN]  : $Script:WarnCount"
Write-AuditLog -Level INFO -Message "Total Informational    [INFO]  : $Script:InfoCount"

if ($Script:AlertCount -gt 0) {
    Write-Host "`n[!] CRITICAL COMPROMISE INDICATORS DETECTED!" -ForegroundColor Red
    Write-Host "    Immediate containment actions required:" -ForegroundColor Yellow
    Write-Host "    1. Disconnect network adapters immediately (isolate host)." -ForegroundColor Yellow
    Write-Host "    2. Capture volatile RAM before power cycling (e.g. WinPmem)." -ForegroundColor Yellow
    Write-Host "    3. Run an offline pre-boot rootkit scan: Start-MpWDOScan" -ForegroundColor Yellow
    Write-Host "    4. Refer to cyber_defense_playbook.pdf for incident response workflow." -ForegroundColor Yellow
} else {
    Write-Host "`n[+] HOST COMPROMISE ASSESSMENT COMPLETE: No high-confidence compromise indicators found." -ForegroundColor Green
    Write-Host "    Continue periodic threat hunting and enforce Attack Surface Reduction (ASR) rules." -ForegroundColor Green
}

Write-AuditLog -Level INFO -Message "Audit complete. Full forensic report saved to: $ReportFile"
Write-AuditLog -Level INFO -Message "Console execution log saved to: $ConsoleLogFile"

try {
    Stop-Transcript -ErrorAction SilentlyContinue | Out-Null
} catch {}

# Read raw console log content for report bundling
$rawConsoleLog = ""
if (Test-Path $ConsoleLogFile) {
    try {
        $rawConsoleLog = [System.IO.File]::ReadAllText($ConsoleLogFile)
    } catch {}
}

# ==============================================================================
# REPORT EXPORT & AUTOMATED PORTAL UPLOAD
# ==============================================================================
$JsonReportPath = Join-Path -Path $OutputDir -ChildPath "Compromise_Report.json"
$scanId = "win_audit_$Timestamp"
$reportPayload = [ordered]@{
    "scan_id"     = $scanId
    "timestamp"   = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss UTC")
    "target_host" = "$($comp.Name) ($($comp.Domain))"
    "host_type"   = "windows"
    "stats"       = [ordered]@{
        "alerts"   = $Script:AlertCount
        "warnings" = $Script:WarnCount
        "info"     = $Script:InfoCount
    }
    "findings"    = $Script:StructuredFindings
    "console_log" = $rawConsoleLog
}

try {
    $jsonPayloadStr = $reportPayload | ConvertTo-Json -Depth 6
    Set-Content -Path $JsonReportPath -Value $jsonPayloadStr -Encoding UTF8
    Write-AuditLog -Level OK -Message "Structured JSON scan report exported to: $JsonReportPath"
} catch {
    Write-AuditLog -Level WARN -Message "Error exporting JSON report: $($_.Exception.Message)"
}

# Upload to Cyber Defense Remediation Portal
try {
    $portalUri = "http://127.0.0.1:8888/api/upload_report"
    $uploadRes = Invoke-RestMethod -Uri $portalUri -Method Post -Body $jsonPayloadStr -ContentType "application/json; charset=utf-8" -TimeoutSec 3 -ErrorAction Stop
    $portalUrl = "http://127.0.0.1:8888"
    Write-Host "`n================================================================================" -ForegroundColor Green
    Write-Host " [+] AUDIT REPORT TRANSMITTED TO REMEDIATION PORTAL" -ForegroundColor Green
    Write-Host "================================================================================" -ForegroundColor Green
    Write-Host " Open the Cyber Defense Portal to view interactive threat analysis & fix guides:" -ForegroundColor White
    Write-Host " Portal URL: $portalUrl" -ForegroundColor Cyan
    Write-Host " Log Files Ready for Portal Ingestion:" -ForegroundColor White
    Write-Host "   - Structured JSON: $JsonReportPath" -ForegroundColor Gray
    Write-Host "   - Human Report   : $ReportFile" -ForegroundColor Gray
    Write-Host "   - Console Log    : $ConsoleLogFile" -ForegroundColor Gray
    Write-Host "================================================================================`n" -ForegroundColor Green
    Start-Process $portalUrl -ErrorAction SilentlyContinue
} catch {
    Write-AuditLog -Level INFO -Message "Portal upload notice: Could not auto-upload via HTTP ($($_.Exception.Message))."
    Write-AuditLog -Level INFO -Message "You can launch the portal manually with: python portal_server.py"
    Write-AuditLog -Level INFO -Message "Then drag & drop $JsonReportPath or $ConsoleLogFile into the web dashboard."
}

