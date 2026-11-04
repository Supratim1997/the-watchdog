#!/usr/bin/env python3
"""
build_playbook_pdf.py
================================================================================
Automated PDF Generator for the Tactical Cyber Defense Playbook:
Compromise Assessment, Rootkit Hunting & RCE Mitigation Manual.
================================================================================
Generates 'cyber_defense_playbook.pdf' in the current workspace directory.
"""

import sys
import os
import hashlib

# ------------------------------------------------------------------------------
# OpenSSL / Python 3.8 Hashlib Compatibility Patch for ReportLab 4.x
# ------------------------------------------------------------------------------
_orig_md5 = hashlib.md5
def _safe_md5(*args, **kwargs):
    kwargs.pop('usedforsecurity', None)
    return _orig_md5(*args, **kwargs)
hashlib.md5 = _safe_md5

_orig_sha1 = hashlib.sha1
def _safe_sha1(*args, **kwargs):
    kwargs.pop('usedforsecurity', None)
    return _orig_sha1(*args, **kwargs)
hashlib.sha1 = _safe_sha1

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak, KeepTogether, HRFlowable
    )
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib import colors
    from reportlab.pdfgen import canvas
except ImportError:
    print("[FATAL] ReportLab is not installed. Please install with: pip install reportlab")
    sys.exit(1)


# ------------------------------------------------------------------------------
# Dynamic Numbered Canvas with Running Headers & Footers
# ------------------------------------------------------------------------------
class NumberedCanvas(canvas.Canvas):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._saved_page_states = []

    def showPage(self):
        self._saved_page_states.append(dict(self.__dict__))
        self._startPage()

    def save(self):
        num_pages = len(self._saved_page_states)
        for state in self._saved_page_states:
            self.__dict__.update(state)
            self.draw_page_decorations(num_pages)
            super().showPage()
        super().save()

    def draw_page_decorations(self, total_pages):
        # Skip header and footer on Cover Page (Page 1)
        if self._pageNumber == 1:
            return

        self.saveState()
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#475569"))

        # Running Top Header
        self.drawString(36, 756, "TACTICAL CYBER DEFENSE PLAYBOOK // COMPROMISE ASSESSMENT & ROOTKIT HUNTING")
        self.setFont("Helvetica", 7.5)
        self.drawRightString(576, 756, "OPERATIONAL SECURITY MANUAL")

        # Header Rule Line
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(36, 750, 576, 750)

        # Footer Rule Line
        self.line(36, 45, 576, 45)

        # Running Bottom Footer
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#DC2626"))
        self.drawString(36, 32, "CONFIDENTIAL // INCIDENT RESPONSE FIELD OPERATIONAL MANUAL")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(576, 32, page_str)

        self.restoreState()


# ------------------------------------------------------------------------------
# PDF Builder Function
# ------------------------------------------------------------------------------
def generate_pdf(output_filename="cyber_defense_playbook.pdf"):
    print(f"[*] Compiling Tactical Cyber Defense Playbook: {output_filename}...")

    # Document Geometry: Letter, 36pt (0.5 in) margins -> Printable Width = 540 pt
    doc = SimpleDocTemplate(
        output_filename,
        pagesize=letter,
        leftMargin=36,
        rightMargin=36,
        topMargin=46,
        bottomMargin=46
    )

    PAGE_WIDTH = 540

    # Palette
    C_PRIMARY = colors.HexColor("#0F172A")    # Slate 900
    C_SECONDARY = colors.HexColor("#1E293B")  # Slate 800
    C_ACCENT = colors.HexColor("#1D4ED8")     # Blue 700
    C_TEXT = colors.HexColor("#1E293B")       # Dark Charcoal
    C_MUTED = colors.HexColor("#64748B")      # Muted Slate
    C_BORDER = colors.HexColor("#CBD5E1")     # Light Slate Border
    C_BG_CODE = colors.HexColor("#0F172A")    # Code Dark Background
    C_CODE_TXT = colors.HexColor("#38BDF8")   # Cyan Code Text

    # Alert Palette
    C_ALERT_BG = colors.HexColor("#FEF2F2")
    C_ALERT_BORDER = colors.HexColor("#DC2626")
    C_ALERT_TXT = colors.HexColor("#991B1B")

    # Warning Palette
    C_WARN_BG = colors.HexColor("#FFFBEB")
    C_WARN_BORDER = colors.HexColor("#D97706")
    C_WARN_TXT = colors.HexColor("#92400E")

    # Info / Note Palette
    C_INFO_BG = colors.HexColor("#EFF6FF")
    C_INFO_BORDER = colors.HexColor("#2563EB")
    C_INFO_TXT = colors.HexColor("#1E40AF")

    # Success Palette
    C_SUCCESS_BG = colors.HexColor("#ECFDF5")
    C_SUCCESS_BORDER = colors.HexColor("#059669")
    C_SUCCESS_TXT = colors.HexColor("#065F46")

    # Styles
    styles = getSampleStyleSheet()

    # Custom Typography Styles
    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=24,
        leading=28,
        textColor=C_PRIMARY,
        alignment=0,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=12,
        leading=16,
        textColor=C_ACCENT,
        alignment=0,
        spaceAfter=15
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=14,
        leading=18,
        textColor=C_PRIMARY,
        spaceBefore=14,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10.5,
        leading=14,
        textColor=C_ACCENT,
        spaceBefore=10,
        spaceAfter=4,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        'SectionH3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=9,
        leading=12,
        textColor=C_SECONDARY,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.5,
        leading=11.5,
        textColor=C_TEXT,
        spaceAfter=5
    )

    body_bold = ParagraphStyle(
        'BodyBold',
        parent=body_style,
        fontName='Helvetica-Bold'
    )

    bullet_style = ParagraphStyle(
        'BulletStyle',
        parent=body_style,
        leftIndent=12,
        firstLineIndent=-8,
        spaceAfter=3
    )

    code_style = ParagraphStyle(
        'CodeStyle',
        parent=styles['Normal'],
        fontName='Courier',
        fontSize=7.2,
        leading=9.2,
        textColor=C_CODE_TXT
    )

    tbl_header_style = ParagraphStyle(
        'TblHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=8,
        leading=10,
        textColor=colors.white,
        alignment=0
    )

    tbl_cell_style = ParagraphStyle(
        'TblCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.5,
        leading=9.5,
        textColor=C_TEXT
    )

    tbl_cell_bold = ParagraphStyle(
        'TblCellBold',
        parent=tbl_cell_style,
        fontName='Helvetica-Bold'
    )

    tbl_cell_code = ParagraphStyle(
        'TblCellCode',
        parent=tbl_cell_style,
        fontName='Courier',
        fontSize=7,
        leading=8.5,
        textColor=colors.HexColor("#0F172A")
    )

    # --------------------------------------------------------------------------
    # Flowable Helper Functions
    # --------------------------------------------------------------------------
    def make_callout(level, title, message):
        """Builds a formatted visual callout box with a colored left-hand border."""
        bg_col = C_INFO_BG
        border_col = C_INFO_BORDER
        txt_col = C_INFO_TXT

        if level == 'ALERT':
            bg_col = C_ALERT_BG
            border_col = C_ALERT_BORDER
            txt_col = C_ALERT_TXT
        elif level == 'WARN':
            bg_col = C_WARN_BG
            border_col = C_WARN_BORDER
            txt_col = C_WARN_TXT
        elif level == 'SUCCESS':
            bg_col = C_SUCCESS_BG
            border_col = C_SUCCESS_BORDER
            txt_col = C_SUCCESS_TXT

        title_p = Paragraph(f"<b>[{level}] {title}</b>", ParagraphStyle('CalloutT', parent=body_style, fontName='Helvetica-Bold', fontSize=8.5, leading=11, textColor=txt_col))
        msg_p = Paragraph(message, ParagraphStyle('CalloutM', parent=body_style, fontSize=8, leading=10.5, textColor=txt_col))

        content = [title_p, Spacer(1, 2), msg_p]
        tbl = Table([[content]], colWidths=[PAGE_WIDTH])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), bg_col),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#CBD5E1")),
            ('LINEBEFORE', (0,0), (0,0), 3.5, border_col),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        return tbl

    def make_code_box(code_text):
        """Builds a dark-themed terminal/code box."""
        # Replace spaces or tabs to preserve indentation if needed, wrap in Paragraph
        formatted_text = code_text.replace("\n", "<br/>").replace(" ", "&nbsp;")
        p = Paragraph(formatted_text, code_style)
        tbl = Table([[p]], colWidths=[PAGE_WIDTH])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_BG_CODE),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
            ('TOPPADDING', (0,0), (-1,-1), 5),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        return tbl

    story = []

    # ==========================================================================
    # COVER / EXECUTIVE HEADER
    # ==========================================================================
    # Classification Badge
    badge_p = Paragraph("<b>OPERATIONAL THREAT HUNTING & INCIDENT RESPONSE PROTOCOL // LEVEL 3</b>", ParagraphStyle(
        'Badge', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.HexColor("#DC2626")
    ))
    badge_tbl = Table([[badge_p]], colWidths=[PAGE_WIDTH])
    badge_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#FEF2F2")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#EF4444")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(badge_tbl)
    story.append(Spacer(1, 12))

    story.append(Paragraph("TACTICAL CYBER DEFENSE PLAYBOOK", title_style))
    story.append(Paragraph("Compromise Assessment, Kernel Rootkit Hunting & RCE Mitigation Field Manual", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_PRIMARY, spaceBefore=2, spaceAfter=10))

    # Executive Metadata Grid
    meta_data = [
        [
            Paragraph("<b>Document Version:</b> 3.0-PRODUCTION", tbl_cell_style),
            Paragraph("<b>Target Architectures:</b> Windows x64, Linux VPS/cPanel, Android & iOS", tbl_cell_style)
        ],
        [
            Paragraph("<b>Classification:</b> RED/BLUE TEAM TACTICAL MANUAL", tbl_cell_style),
            Paragraph("<b>Author / Role:</b> Principal Red/Blue Systems Security Architect", tbl_cell_style)
        ],
        [
            Paragraph("<b>Toolkit Components:</b> 3 Audit Scripts + Portal Server (portal_server.py)", tbl_cell_style),
            Paragraph("<b>Remediation Portal:</b> http://127.0.0.1:8888 (Local Auto-Spawn)", tbl_cell_style)
        ]
    ]
    meta_tbl = Table(meta_data, colWidths=[270, 270])
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 4),
        ('BOTTOMPADDING', (0,0), (-1,-1), 4),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
        ('RIGHTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 10))

    story.append(make_callout(
        'ALERT',
        'CRITICAL OPERATIONAL DOCTRINE',
        'Never trust a compromised operating system to report its own compromise. Kernel-level rootkits, '
        'Bring-Your-Own-Vulnerable-Driver (BYOVD) exploits, and Direct Kernel Object Manipulation (DKOM) can '
        'systematically blind live query tools (Task Manager, Get-Process, netstat, ps). This playbook integrates '
        'rigorous live heuristic telemetry with Out-of-Band (OOB) offline verification to ensure complete tactical visibility.'
    ))
    story.append(Spacer(1, 10))

    # ==========================================================================
    # SECTION 1: Threat Architecture & The Reality of Rootkits
    # ==========================================================================
    story.append(Paragraph("1. Threat Architecture & The Reality of Rootkits", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph(
        "Modern advanced persistent threats (APTs), commercial spyware cartels (e.g., NSO Group, Cytrox, Intellexa), "
        "and sophisticated ransomware syndicates (e.g., BlackCat, LockBit) operate predominantly at ring boundaries "
        "below traditional security controls. Understanding the mechanics of system visibility is paramount:",
        body_style
    ))

    story.append(Paragraph("<b>The Dual-Ring Execution Barrier:</b>", h2_style))
    story.append(Paragraph(
        "• <b>User Mode (Ring 3):</b> Standard applications, services, and default administrative tools run in Ring 3. "
        "They rely on Windows API subsystems (NTDLL, KERNEL32) or Linux glibc system call wrappers to interface with the kernel. "
        "Userland rootkits manipulate the dynamic linker (<code>/etc/ld.so.preload</code>, <code>LD_PRELOAD</code>) or inject "
        "hooks into standard memory spaces to filter out malicious files, sockets, and processes.<br/>"
        "• <b>Kernel Mode (Ring 0):</b> The operating system kernel, hardware abstraction layer (HAL), and kernel drivers execute "
        "with unrestricted hardware access. A rootkit executing in Ring 0 possesses total sovereignty over system memory and execution state.",
        bullet_style
    ))

    story.append(Paragraph("<b>How Kernel Rootkits Blind Live Operating System Scanners:</b>", h2_style))
    story.append(Paragraph(
        "1. <b>Direct Kernel Object Manipulation (DKOM):</b> Windows tracks running processes via the doubly-linked list "
        "<code>ActiveProcessLinks</code> within the <code>EPROCESS</code> kernel structure. A kernel rootkit unlinks its malicious "
        "process from this chain. The thread continues executing on the CPU scheduler, but userland query APIs (<code>EnumProcesses</code>, "
        "<code>Process32First/Next</code>, WMI <code>Win32_Process</code>) are blinded.<br/>"
        "2. <b>System Service Descriptor Table (SSDT) & Syscall Filtering:</b> In Linux and pre-PatchGuard Windows, rootkits hook "
        "syscall dispatch tables. On modern 64-bit systems, threat actors employ hypervisor-based virtualization (Type-1/Type-2 VMCS "
        "shadowing) or filter kernel notification routines (<code>PsSetCreateProcessNotifyRoutine</code>) to intercept security callbacks.<br/>"
        "3. <b>Bring Your Own Vulnerable Driver (BYOVD):</b> Threat actors drop legitimately signed, vulnerable kernel drivers "
        "(e.g., <code>RTCore64.sys</code>, <code>gdrv.sys</code>, <code>mhyprot2.sys</code>). Utilizing arbitrary read/write primitives in "
        "these signed drivers, the attacker disables EDR kernel callbacks, zeroes out Defender driver objects, and blinds telemetry without triggering Driver Signature Enforcement (DSE).",
        bullet_style
    ))

    story.append(Spacer(1, 4))

    # Architecture Comparison Table
    arch_tbl_data = [
        [
            Paragraph("<b>Vector / Mechanism</b>", tbl_header_style),
            Paragraph("<b>Live Telemetry (In-Band)</b>", tbl_header_style),
            Paragraph("<b>Out-of-Band (OOB) Offline Verification</b>", tbl_header_style),
            Paragraph("<b>Tactical Mitigation / Defense</b>", tbl_header_style)
        ],
        [
            Paragraph("<b>Kernel Driver / BYOVD</b>", tbl_cell_bold),
            Paragraph("Get-CimInstance Win32_SystemDriver (Can be spoofed if hooked)", tbl_cell_style),
            Paragraph("WinPE / Windows Defender Offline pre-boot signature & disk hash verification", tbl_cell_style),
            Paragraph("HVCI / Core Isolation + Driver Blocklist enforcement", tbl_cell_style)
        ],
        [
            Paragraph("<b>Process Hiding (DKOM)</b>", tbl_cell_bold),
            Paragraph("Query APIs return empty; thread scheduler still dispatches CPU", tbl_cell_style),
            Paragraph("Raw volatile memory acquisition (WinPmem / LiME) & pool tag analysis", tbl_cell_style),
            Paragraph("Hardware-enforced virtualization & Memory Integrity", tbl_cell_style)
        ],
        [
            Paragraph("<b>Userland Preload Hijack</b>", tbl_cell_bold),
            Paragraph("<code>/etc/ld.so.preload</code> intercepting libc <code>readdir()</code>", tbl_cell_style),
            Paragraph("Statically linked binaries (busybox) or offline live USB mount", tbl_cell_style),
            Paragraph("Immutable filesystem attributes (<code>chattr +i</code>), AppArmor", tbl_cell_style)
        ],
        [
            Paragraph("<b>Mobile Memory Implants</b>", tbl_cell_bold),
            Paragraph("App Store sandbox prevents all process/kernel inspection", tbl_cell_style),
            Paragraph("MVT forensic backup extraction & ADB USB system state triage", tbl_cell_style),
            Paragraph("iOS Lockdown Mode + Daily 24h reboot cadence", tbl_cell_style)
        ]
    ]
    arch_tbl = Table(arch_tbl_data, colWidths=[110, 140, 155, 135])
    arch_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(arch_tbl)
    story.append(Spacer(1, 10))

    # ==========================================================================
    # SECTION 2: Module 1 — Windows Laptop Deep Audit & Hardening
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("2. Module 1: Windows Endpoint & Kernel Driver Compromise Assessment", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph(
        "The script <code>windows_compromise_audit.ps1</code> is engineered for Windows 10/11 and Windows Server 2016-2025. "
        "It performs strict, non-destructive heuristic audits of volatile memory artifacts, running drivers, persistence mechanisms, "
        "and security log tampering indicators. It generates a full timestamped report directory: <code>.\\Windows_Audit_&lt;TIMESTAMP&gt;\\</code>.",
        body_style
    ))

    story.append(Paragraph("<b>Exact Command Execution Syntax:</b>", h2_style))
    story.append(make_code_box(
        "# Open an elevated Administrator PowerShell prompt:\n"
        "powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\\windows_compromise_audit.ps1\n\n"
        "# Custom output path execution:\n"
        "powershell.exe -ExecutionPolicy Bypass -File .\\windows_compromise_audit.ps1 -OutputDir C:\\IR_Evidence"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Heuristic Triage Guide: Interpreting Audit Signals:</b>", h2_style))

    # Windows Triage Table
    win_triage_data = [
        [
            Paragraph("<b>Module Check</b>", tbl_header_style),
            Paragraph("<b>[ALERT] Trigger Condition</b>", tbl_header_style),
            Paragraph("<b>[WARN] Trigger Condition</b>", tbl_header_style),
            Paragraph("<b>Tactical Operator Action</b>", tbl_header_style)
        ],
        [
            Paragraph("<b>1. Network Sockets & Listeners</b>", tbl_cell_bold),
            Paragraph("Unsigned binary OR process located in AppData, Temp, Public, ProgramData holding external socket", tbl_cell_style),
            Paragraph("High-numbered ephemeral port listening bound to 0.0.0.0 without remote peer", tbl_cell_style),
            Paragraph("Terminate process, carve binary for sandbox detonation, block remote IP at perimeter firewall.", tbl_cell_style)
        ],
        [
            Paragraph("<b>2. Unsigned Processes</b>", tbl_cell_bold),
            Paragraph("Binary is unsigned AND executing from user-writable staging directory", tbl_cell_style),
            Paragraph("Unsigned process outside System32, or signed process running in user staging path", tbl_cell_style),
            Paragraph("Verify parent process chain. Check hash on VirusTotal. Dump process memory via ProcDump.", tbl_cell_style)
        ],
        [
            Paragraph("<b>3. WMI Fileless Persistence</b>", tbl_cell_bold),
            Paragraph("Any active <code>CommandLineEventConsumer</code> or <code>ActiveScriptEventConsumer</code> in <code>root\\subscription</code>", tbl_cell_style),
            Paragraph("Unbound <code>__EventFilter</code> without consumer attachment", tbl_cell_style),
            Paragraph("Extract <code>CommandLineTemplate</code> / <code>ScriptText</code>. Delete consumer via <code>Remove-CimInstance</code>.", tbl_cell_style)
        ],
        [
            Paragraph("<b>4. Registry Persistence & IFEO</b>", tbl_cell_bold),
            Paragraph("Run key invoking LOLBin (powershell, cmd, mshta) OR any IFEO subkey possessing a <code>Debugger</code> value", tbl_cell_style),
            Paragraph("Unrecognized 3rd party entry in HKLM/HKCU Run keys", tbl_cell_style),
            Paragraph("Immediate Sticky Keys / Accessibility backdoor indicator. Delete registry key; isolate host.", tbl_cell_style)
        ],
        [
            Paragraph("<b>5. Kernel Drivers & Services</b>", tbl_cell_bold),
            Paragraph("CRITICAL: Unsigned running kernel driver (<code>Win32_SystemDriver</code>) or service invoking LOLBins", tbl_cell_style),
            Paragraph("Non-standard service binary path outside Windows directories", tbl_cell_style),
            Paragraph("High confidence rootkit / BYOVD implant. Do not reboot live without memory dump. Execute WDO scan.", tbl_cell_style)
        ],
        [
            Paragraph("<b>6. Scheduled Tasks</b>", tbl_cell_bold),
            Paragraph("Task invoking LOLBins with flags (<code>-enc</code>, <code>Bypass</code>, <code>DownloadString</code>, <code>IEX</code>)", tbl_cell_style),
            Paragraph("Non-Microsoft task executing from user-writable directory", tbl_cell_style),
            Paragraph("Unregister task (<code>Unregister-ScheduledTask</code>); inspect staging directory for dropped payloads.", tbl_cell_style)
        ],
        [
            Paragraph("<b>7. Defender Tampering</b>", tbl_cell_bold),
            Paragraph("<code>DisableRealtimeMonitoring = True</code> OR path/process exclusions configured", tbl_cell_style),
            Paragraph("Behavior monitoring or script scanning disabled", tbl_cell_style),
            Paragraph("Purge exclusions (<code>Remove-MpPreference</code>); re-enable real-time and cloud protections.", tbl_cell_style)
        ],
        [
            Paragraph("<b>8. Critical Event Logs</b>", tbl_cell_bold),
            Paragraph("Event ID 1102 (Security audit log cleared) detected in past 7 days", tbl_cell_style),
            Paragraph("Event ID 7045 (New service installed) logged in past 7 days", tbl_cell_style),
            Paragraph("Correlate timestamp with user identity; check SIEM/syslog backups for purged log history.", tbl_cell_style)
        ]
    ]
    win_triage_tbl = Table(win_triage_data, colWidths=[95, 145, 140, 160])
    win_triage_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 3.5),
        ('RIGHTPADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(win_triage_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Triggering Windows Defender Offline (WDO) Pre-Boot Rootkit Scan:</b>", h2_style))
    story.append(Paragraph(
        "When an <code>[ALERT]</code> triggers on an unsigned running kernel driver or suspicious system service, "
        "in-band scanning cannot be relied upon to cleanse the system. Windows Defender Offline reboots the machine into a dedicated "
        "Windows Recovery Environment (WinRE) container, mounting the disk offline where kernel hooks and active memory filters are inert:",
        body_style
    ))
    story.append(make_code_box(
        "# Save all operator work, then execute pre-boot offline scan:\n"
        "Start-MpWDOScan\n"
        "# The system will immediately initiate a reboot into the offline WDO environment."
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Attack Surface Reduction (ASR) Hardening Rules:</b>", h2_style))
    story.append(Paragraph(
        "ASR rules intercept malicious behaviors before code execution occurs. Operators must enforce these rules in <b>Block Mode</b> "
        "(Action = 1) across all managed endpoints:",
        body_style
    ))

    # ASR Table
    asr_data = [
        [
            Paragraph("<b>ASR Rule Name</b>", tbl_header_style),
            Paragraph("<b>Rule GUID</b>", tbl_header_style),
            Paragraph("<b>Threat Vector Neutralized</b>", tbl_header_style)
        ],
        [
            Paragraph("Block credential stealing from Windows LSASS", tbl_cell_bold),
            Paragraph("<code>9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2</code>", tbl_cell_code),
            Paragraph("Mimikatz, procdump, memory scraping of plaintext credentials & NTLM hashes", tbl_cell_style)
        ],
        [
            Paragraph("Block process creations from PSExec and WMI", tbl_cell_bold),
            Paragraph("<code>d1e49aac-8f56-4280-b9ba-993a6d77406c</code>", tbl_cell_code),
            Paragraph("Lateral movement via remote WMI process spawning and administrative tools", tbl_cell_style)
        ],
        [
            Paragraph("Block executable content from email & webmail", tbl_cell_bold),
            Paragraph("<code>be9ba2d9-53ea-44a7-ac61-759b4f84b0bc</code>", tbl_cell_code),
            Paragraph("Phishing attachments, ISO containers, and downloaded script droppers", tbl_cell_style)
        ],
        [
            Paragraph("Block Office apps from creating child processes", tbl_cell_bold),
            Paragraph("<code>d4f940ab-401b-4efc-aadc-ad5f3c50688a</code>", tbl_cell_code),
            Paragraph("Malicious Word/Excel macros spawning PowerShell, CMD, or WScript", tbl_cell_style)
        ],
        [
            Paragraph("Block untrusted & unsigned processes from USB", tbl_cell_bold),
            Paragraph("<code>b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4</code>", tbl_cell_code),
            Paragraph("Physical USB drop attacks, autorun worms, untrusted technician binaries", tbl_cell_style)
        ],
        [
            Paragraph("Block persistence through WMI event subscription", tbl_cell_bold),
            Paragraph("<code>e6db77e5-3df2-4cf1-b95a-636979351e5b</code>", tbl_cell_code),
            Paragraph("Fileless WMI persistence backdoors and script consumers", tbl_cell_style)
        ]
    ]
    asr_tbl = Table(asr_data, colWidths=[170, 190, 180])
    asr_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(asr_tbl)
    story.append(Spacer(1, 4))

    story.append(make_code_box(
        "# PowerShell Script to Enforce Critical ASR Rules in Block Mode:\n"
        "$asrRules = @(\n"
        "    '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', # LSASS Protection\n"
        "    'd1e49aac-8f56-4280-b9ba-993a6d77406c', # PSExec/WMI Child Process\n"
        "    'be9ba2d9-53ea-44a7-ac61-759b4f84b0bc', # Email Executable Content\n"
        "    'd4f940ab-401b-4efc-aadc-ad5f3c50688a', # Office Child Process Spawning\n"
        "    'b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4', # USB Unsigned Executables\n"
        "    'e6db77e5-3df2-4cf1-b95a-636979351e5b'  # WMI Persistence\n"
        ")\n"
        "foreach ($guid in $asrRules) {\n"
        "    Add-MpPreference -AttackSurfaceReductionRules_Ids $guid -AttackSurfaceReductionRules_Actions Enabled\n"
        "}"
    ))

    # ==========================================================================
    # SECTION 3: Module 2 — Rented Web Server (PHP/MySQL) Audit & Hardening
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("3. Module 2: Rented Web Server (PHP/MySQL VPS/cPanel) Audit & Hardening", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph(
        "Web application hosting environments (cPanel, standard Linux VPS, cloud compute instances) running PHP/MySQL "
        "represent the primary attack surface for initial access, credential exfiltration, and SEO spam redirection. "
        "The script <code>server_webshell_rootkit_audit.sh</code> executes 8 deep checks across the webroot and host environment.",
        body_style
    ))

    story.append(Paragraph("<b>Exact Deployment & Execution Instructions:</b>", h2_style))
    story.append(make_code_box(
        "# Step 1: Securely transfer the auditor to the target VPS via SCP:\n"
        "scp server_webshell_rootkit_audit.sh operator@target-vps.com:/tmp/\n\n"
        "# Step 2: SSH into target and execute against target webroot (e.g. /var/www/html or $HOME/public_html):\n"
        "ssh operator@target-vps.com\n"
        "chmod +x /tmp/server_webshell_rootkit_audit.sh\n"
        "/tmp/server_webshell_rootkit_audit.sh /var/www/html\n\n"
        "# Step 3: Retrieve generated audit log back to your analysis station:\n"
        "scp operator@target-vps.com:/tmp/server_security_audit_*.log ./evidence/"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Web Application Threat Vectors & Triage Protocol:</b>", h2_style))
    story.append(Paragraph(
        "• <b>Obfuscated PHP Primitives:</b> Attackers evade static regex filters by chaining decompression, character arithmetic, "
        "and string transformations (e.g. <code>eval(gzinflate(base64_decode(...)))</code>, <code>str_rot13</code>, or variable functions "
        "<code>$f = 'sys'.'tem'; $f($_POST['cmd']);</code>). Any match on unconstrained system execution primitives constitutes an immediate <code>[ALERT]</code>.<br/>"
        "• <b>Rogue Scripts in Static/Upload Folders:</b> Legitimate web applications store user media (avatars, PDFs, product images) "
        "in dedicated static folders (<code>/uploads/</code>, <code>/media/</code>, <code>/cache/</code>). Threat actors exploit unvalidated file uploads "
        "to drop webshells (<code>.phtml</code>, <code>.php5</code>, <code>.phar</code>) into these directories. Any script in an upload folder is high-confidence malicious.<br/>"
        "• <b>.htaccess Trapping & SEO Poisoning:</b> Apache web servers process directory-level <code>.htaccess</code> directives. "
        "Attackers inject <code>php_value auto_prepend_file /tmp/.backdoor.php</code> to automatically execute malicious code before every page load, "
        "or inject <code>RewriteCond %{HTTP_REFERER} (google|bing)</code> to redirect search engine bots to scam sites while presenting clean pages to administrators.<br/>"
        "• <b>Userland Rootkits (LD_PRELOAD):</b> The Linux dynamic linker (<code>ld-linux.so</code>) consults <code>/etc/ld.so.preload</code> "
        "before loading any shared object. Rootkits (such as Azazel, Jynx, Reptile userland) hook <code>readdir()</code>, <code>open()</code>, and <code>stat()</code> "
        "to hide webshell files from <code>ls</code> and hidden processes from <code>ps</code>. Non-empty <code>/etc/ld.so.preload</code> is a catastrophic compromise.",
        bullet_style
    ))

    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Production Hardening Configurations (Copy-Paste Ready):</b>", h2_style))
    story.append(Paragraph("<b>1. Production php.ini Hardening Directives:</b>", h3_style))
    story.append(make_code_box(
        "# Locate active php.ini (e.g. /etc/php/8.2/fpm/php.ini or /etc/php.ini) and configure:\n"
        "disable_functions = exec,passthru,shell_exec,system,proc_open,popen,curl_exec,curl_multi_exec,parse_ini_file,show_source\n"
        "session.upload_progress.enabled = 0    # CRITICAL: Neutralizes PHP2Shell LFI-to-RCE race conditions\n"
        "allow_url_include = Off               # CRITICAL: Prevents Remote File Inclusion (RFI)\n"
        "allow_url_fopen = Off                 # Restricts remote file streaming unless explicitly required\n"
        "expose_php = Off                      # Suppresses X-Powered-By HTTP response headers\n"
        "display_errors = Off                  # Prevents internal path and database credential leaks\n"
        "open_basedir = /var/www/html/:/tmp/   # Confines PHP file operations strictly to webroot and temp"
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>2. Apache / cPanel .htaccess Execution Lock for Upload Directories:</b>", h3_style))
    story.append(Paragraph(
        "Place this <code>.htaccess</code> file inside every public upload folder (e.g. <code>wp-content/uploads/.htaccess</code>). "
        "It completely forbids the web server from executing any script handler, rendering uploaded webshells inert:",
        body_style
    ))
    story.append(make_code_box(
        "# Prevent direct script execution in static upload folders:\n"
        "<FilesMatch \"\\.(php|phtml|php3|php4|php5|php7|phar|pl|py|jsp|asp|sh|cgi)$\">\n"
        "    Require all denied\n"
        "</FilesMatch>\n"
        "Options -ExecCGI -Indexes"
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>3. Linux Host Permission Hardening:</b>", h3_style))
    story.append(make_code_box(
        "# Enforce secure permission baseline across webroot:\n"
        "find /var/www/html -type d -exec chmod 755 {} +\n"
        "find /var/www/html -type f -exec chmod 644 {} +\n"
        "# Lock sensitive database & environment configuration files:\n"
        "chmod 600 /var/www/html/.env /var/www/html/wp-config.php /var/www/html/configuration.php"
    ))

    # ==========================================================================
    # SECTION 4: Module 3 — iPhone (iOS) & Android Mobile Forensics
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("4. Module 3: iPhone (iOS) & Android Mobile Forensic Audit & Hardening", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph(
        "Smartphones represent high-value espionage targets. Mobile spyware cartels deploy zero-click exploits "
        "(e.g. BlastPass, ForcedEntry, Subzero) targeting image parsers, WebKit rendering engines, and cellular baseband stacks.",
        body_style
    ))

    story.append(Paragraph("<b>The Mobile Sandboxing Paradox:</b>", h2_style))
    story.append(make_callout(
        'ALERT',
        'THE CONSUMER MOBILE "ANTIVIRUS" FALLACY',
        'Commercial "Antivirus" or "Security" apps downloaded from the Apple App Store or Google Play Store CANNOT '
        'detect kernel-level or state-grade spyware. By design, modern mobile operating systems enforce strict application sandboxing. '
        'A userland app has zero visibility into the process table, cannot inspect memory of other applications, '
        'cannot read system logs (syslog/logcat), and cannot inspect the kernel. Only external, out-of-band forensic toolkits '
        'operating via USB (ADB on Android, unencrypted backups on iOS) can extract and analyze threat indicators.'
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Forensic Orchestration via mobile_forensics_audit.sh:</b>", h2_style))
    story.append(Paragraph(
        "The script <code>mobile_forensics_audit.sh</code> automates threat hunting using Amnesty International's "
        "Mobile Verification Toolkit (MVT) combined with deep heuristic device parameter auditing.",
        body_style
    ))
    story.append(make_code_box(
        "# Running Android Forensic Audit over USB:\n"
        "./mobile_forensics_audit.sh android\n\n"
        "# Running Apple iOS Forensic Audit over USB (creates full forensic backup):\n"
        "./mobile_forensics_audit.sh ios\n\n"
        "# Auditing an existing pre-acquired iTunes/Finder unencrypted backup:\n"
        "./mobile_forensics_audit.sh ios /path/to/extracted/ios_backup"
    ))
    story.append(Spacer(1, 6))

    # Mobile Audit Comparison Table
    mob_tbl_data = [
        [
            Paragraph("<b>Mobile Vector</b>", tbl_header_style),
            Paragraph("<b>Diagnostic Inspection Mechanism</b>", tbl_header_style),
            Paragraph("<b>Spyware / Threat Indicator</b>", tbl_header_style),
            Paragraph("<b>Hardening & Containment Step</b>", tbl_header_style)
        ],
        [
            Paragraph("<b>Verified Boot (AVB)</b>", tbl_cell_bold),
            Paragraph("<code>adb shell getprop ro.boot.verifiedbootstate</code>", tbl_cell_code),
            Paragraph("Status <code>orange</code>, <code>yellow</code>, or <code>red</code> indicates unlocked/tampered bootloader", tbl_cell_style),
            Paragraph("OEM re-lock or re-flash stock signed firmware image via fastboot", tbl_cell_style)
        ],
        [
            Paragraph("<b>SELinux State</b>", tbl_cell_bold),
            Paragraph("<code>adb shell getenforce</code>", tbl_cell_code),
            Paragraph("Status <code>Permissive</code> or <code>Disabled</code> (Exploit condition)", tbl_cell_style),
            Paragraph("Re-flash stock partition; device has been permanently rooted/compromised", tbl_cell_style)
        ],
        [
            Paragraph("<b>Accessibility Services</b>", tbl_cell_bold),
            Paragraph("<code>settings get secure enabled_accessibility_services</code>", tbl_cell_code),
            Paragraph("Keylogger / Stalkerware hook intercepting screen and keystrokes", tbl_cell_style),
            Paragraph("Revoke permission immediately; uninstall offending package", tbl_cell_style)
        ],
        [
            Paragraph("<b>Device Administrators</b>", tbl_cell_bold),
            Paragraph("<code>dumpsys device_policy</code>", tbl_cell_code),
            Paragraph("Anti-uninstall persistence preventing user deletion of spyware", tbl_cell_style),
            Paragraph("Deactivate device administrator in settings before uninstallation", tbl_cell_style)
        ],
        [
            Paragraph("<b>User Root CAs</b>", tbl_cell_bold),
            Paragraph("<code>ls -la /data/misc/user/0/cacerts-added/</code>", tbl_cell_code),
            Paragraph("Rogue CA certificates enabling silent HTTPS/TLS proxy MITM", tbl_cell_style),
            Paragraph("Delete all user-installed certificates in Encryption & Credentials settings", tbl_cell_style)
        ],
        [
            Paragraph("<b>STIX2 IOC Scan</b>", tbl_cell_bold),
            Paragraph("<code>mvt-ios check-backup</code> / <code>mvt-android check-adb</code>", tbl_cell_code),
            Paragraph("Matches on known NSO Pegasus, Predator, Cytrox C2 domains/hashes", tbl_cell_style),
            Paragraph("Full hardware retirement / forensic image preservation; rotate all identities", tbl_cell_style)
        ]
    ]
    mob_tbl = Table(mob_tbl_data, colWidths=[90, 160, 145, 145])
    mob_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 3.5),
        ('RIGHTPADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(mob_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Tactical Mobile Hardening Checklist:</b>", h2_style))
    story.append(Paragraph(
        "1. <b>Enable Apple iOS Lockdown Mode:</b> (Settings -> Privacy & Security -> Lockdown Mode). "
        "Strictly disables Just-In-Time (JIT) JavaScript compilation, blocks 2G cellular connections, strips complex WebKit font rendering, "
        "blocks incoming FaceTime and message attachments from unknown senders, and disables wired USB connections when locked.<br/>"
        "2. <b>The 24-Hour Reboot Cadence:</b> Most zero-click mobile exploits (e.g. Pegasus) operate as <i>non-persistent memory-only implants</i> "
        "to evade hardware write protections and avoid bricking devices. Rebooting the device once every 24 hours forces the malware out of memory, "
        "forcing the threat actor to re-infect and burn valuable zero-day exploit bandwidth.<br/>"
        "3. <b>Audit User Root Certificates:</b> Regularly inspect <code>Settings -> Security -> Encryption & Credentials -> User Credentials</code>. "
        "Any certificate not explicitly installed by enterprise MDM must be purged immediately.<br/>"
        "4. <b>Disable Sideloading & USB Debugging:</b> Turn off USB debugging on Android when not actively auditing. Ensure 'Install Unknown Apps' is globally disabled.",
        bullet_style
    ))

    # ==========================================================================
    # SECTION 5: Enterprise Incident Response Containment Protocol
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("5. Enterprise Incident Response & Containment Protocol", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph(
        "When an audit script triggers an <code>[ALERT]</code> (such as an unsigned running kernel driver, an active webshell, "
        "or an MVT STIX2 IOC match), operators must immediately shift from threat hunting to tactical incident containment. "
        "Follow this standardized 6-phase containment protocol:",
        body_style
    ))

    # IR Steps
    story.append(Paragraph("<b>Phase 1: Rapid Threat Triage & Verification</b>", h2_style))
    story.append(Paragraph(
        "Confirm the alert is not a known false positive. Verify file hashes against internal software baselines and VirusTotal. "
        "Establish an isolated out-of-band communications channel (Signal / separate hardware) for incident response personnel.",
        body_style
    ))

    story.append(Paragraph("<b>Phase 2: Immediate Network Isolation (Containment)</b>", h2_style))
    story.append(Paragraph(
        "Sever all network connectivity to halt lateral movement and data exfiltration. "
        "<b>DO NOT POWER OFF THE HOST IMMEDIATELY</b>; powering off destroys critical volatile evidence stored in RAM.",
        body_style
    ))
    story.append(make_code_box(
        "# Windows Network Isolation (Immediate Host Firewall Lockdown):\n"
        "netsh advfirewall set allprofiles state on\n"
        "netsh advfirewall firewall add rule name=\"IR_BLOCK_ALL_OUT\" dir=out action=block\n"
        "netsh advfirewall firewall add rule name=\"IR_BLOCK_ALL_IN\" dir=in action=block\n\n"
        "# Linux VPS Network Isolation (Drop all traffic except forensic SSH if console unavailable):\n"
        "iptables -P INPUT DROP && iptables -P FORWARD DROP && iptables -P OUTPUT DROP"
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 3: Volatile Memory & Forensic Evidence Preservation</b>", h2_style))
    story.append(Paragraph(
        "Extract raw volatile system RAM prior to taking down the system. Memory contains decrypted malware payloads, "
        "network sockets, injected DLLs, and plaintext credentials:",
        body_style
    ))
    story.append(make_code_box(
        "# Windows Memory Acquisition via WinPmem (executed from external USB drive):\n"
        "winpmem.exe -o D:\\evidence\\host_ram_dump.raw\n\n"
        "# Linux Memory Acquisition via LiME (Linux Memory Extractor):\n"
        "insmod lime-$(uname -r).ko \"path=/tmp/evidence/linux_ram.lime format=raw\""
    ))
    story.append(Spacer(1, 4))

    story.append(Paragraph("<b>Phase 4: Scope Assessment & Lateral Movement Investigation</b>", h2_style))
    story.append(Paragraph(
        "Query domain controllers, perimeter firewalls, and proxy logs for connections to the external IP addresses identified "
        "in Module 1. Audit Kerberos ticket granting requests (TGT/TGS) and check for pass-the-hash or token manipulation.",
        body_style
    ))

    story.append(Paragraph("<b>Phase 5: Enterprise Credential & Identity Revocation</b>", h2_style))
    story.append(Paragraph(
        "Assume all credentials stored or processed on the compromised host are compromised. "
        "Execute a global password and token rotation across Active Directory, cloud providers (AWS/Azure/GCP IAM keys), "
        "database connection strings, and SSH authorized keys.",
        body_style
    ))

    story.append(Paragraph("<b>Phase 6: Golden-Image Eradication & Recovery Workflow</b>", h2_style))
    story.append(Paragraph(
        "<b>Never attempt to 'clean' a kernel-compromised or rootkitted operating system while leaving the OS intact.</b> "
        "Eradication must follow the Golden-Image recovery standard:",
        body_style
    ))
    story.append(Paragraph(
        "1. <b>Storage Zeroization:</b> Execute complete disk wipe (secure erase or ATA sanitize) to destroy persistence in boot sectors.<br/>"
        "2. <b>Re-Deploy from Known-Clean Baseline:</b> Reinstall operating system from a cryptographically signed golden image.<br/>"
        "3. <b>Data Restoration:</b> Restore application and user data exclusively from pre-incident offline cold backups. Inspect all restored files with static scanners before placing in production.<br/>"
        "4. <b>Post-Recovery Surveillance:</b> Place the restored host in heightened monitoring status for 30 days to detect persistence re-infection attempts.",
        bullet_style
    ))

    story.append(Spacer(1, 8))
    story.append(make_callout(
        'SUCCESS',
        'POST-INCIDENT POSTURE REINFORCEMENT',
        'Following incident closure, conduct an executive blameless post-mortem. Update firewall perimeter rules, '
        'expand Attack Surface Reduction (ASR) coverage, harden PHP and web server runtime configurations, '
        'and integrate continuous automated threat hunting using the toolkit scripts provided in this repository.'
    ))

    # ==========================================================================
    # SECTION 6: Cyber Defense Remediation Portal & Telemetry Loop
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("6. Cyber Defense Remediation Portal & Automated Telemetry Loop", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=8))

    story.append(Paragraph(
        "The toolkit includes a local, zero-dependency incident response and remediation portal (<code>portal_server.py</code>). "
        "Hosted locally on <b>http://127.0.0.1:8888</b>, the portal bridges raw forensic script telemetry with actionable, "
        "step-by-step eradication procedures.",
        body_style
    ))

    story.append(Paragraph("<b>The Automated Telemetry & Auto-Spawn Loop:</b>", h2_style))
    story.append(Paragraph(
        "1. <b>Autonomous Portal Startup:</b> When any audit script (<code>windows_compromise_audit.ps1</code>, "
        "<code>server_webshell_rootkit_audit.sh</code>, or <code>mobile_forensics_audit.sh</code>) is executed, it first queries "
        "<code>http://127.0.0.1:8888/api/health</code>. If offline, the script automatically spawns <code>portal_server.py</code> "
        "in the background without operator intervention.<br/>"
        "2. <b>Triple-Artifact Telemetry Export:</b> Scans simultaneously generate (1) human-readable reports "
        "(<code>Compromise_Assessment_Report.txt</code>), (2) verbatim console execution logs (<code>console_execution.log</code>), "
        "and (3) machine-readable structured JSON reports (<code>Compromise_Report.json</code>).<br/>"
        "3. <b>Instant REST Ingestion:</b> The audit script transmits the report payload via <code>POST /api/upload_report</code> "
        "to the local portal, storing findings and console traces in <code>./portal_reports/</code>.<br/>"
        "4. <b>Browser Auto-Launch:</b> The script launches the operator's default browser directly into the interactive dashboard.",
        bullet_style
    ))
    story.append(Spacer(1, 6))

    # Portal API Reference Table
    portal_api_data = [
        [
            Paragraph("<b>Endpoint Route</b>", tbl_header_style),
            Paragraph("<b>HTTP Method</b>", tbl_header_style),
            Paragraph("<b>Payload / Parameters</b>", tbl_header_style),
            Paragraph("<b>Operational Function</b>", tbl_header_style)
        ],
        [
            Paragraph("<code>/api/health</code>", tbl_cell_code),
            Paragraph("GET", tbl_cell_bold),
            Paragraph("None", tbl_cell_style),
            Paragraph("Health probe used by audit scripts to check if portal is listening", tbl_cell_style)
        ],
        [
            Paragraph("<code>/api/reports</code>", tbl_cell_code),
            Paragraph("GET", tbl_cell_bold),
            Paragraph("None", tbl_cell_style),
            Paragraph("Lists all available scans with alert/warning counts and host types", tbl_cell_style)
        ],
        [
            Paragraph("<code>/api/report?id=&lt;id&gt;</code>", tbl_cell_code),
            Paragraph("GET", tbl_cell_bold),
            Paragraph("<code>id</code> string", tbl_cell_style),
            Paragraph("Retrieves complete scan details and augmented remediation guide", tbl_cell_style)
        ],
        [
            Paragraph("<code>/api/upload_report</code>", tbl_cell_code),
            Paragraph("POST", tbl_cell_bold),
            Paragraph("JSON payload (structured or <code>raw_log</code>)", tbl_cell_style),
            Paragraph("Ingests report, enhances findings with remediation KB, and saves to disk", tbl_cell_style)
        ],
        [
            Paragraph("<code>/</code>", tbl_cell_code),
            Paragraph("GET", tbl_cell_bold),
            Paragraph("None", tbl_cell_style),
            Paragraph("Serves the single-page Cyber Defense Incident Response Dashboard", tbl_cell_style)
        ]
    ]
    portal_api_tbl = Table(portal_api_data, colWidths=[120, 60, 160, 200])
    portal_api_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 4),
        ('RIGHTPADDING', (0,0), (-1,-1), 4),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(portal_api_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Automated Remediation Engine & Risk Meter:</b>", h2_style))
    story.append(Paragraph(
        "Every ingested finding is matched against the built-in threat remediation knowledge base, providing the operator with:<br/>"
        "• <b>Executive 'What Went Well vs. What Went Wrong' Posture Review:</b> Categorizes verified defensive baselines (clean drivers, "
        "active real-time protection, intact event logs) vs. active threats, blindspots, and script execution warnings in comparative cards.<br/>"
        "• <b>Composite Host Risk Meter (0–100%):</b> Dynamically weighted based on critical alerts (25 pts each) and warnings (8 pts each). "
        "As the operator resolves items, the risk score drops in real time.<br/>"
        "• <b>4-Phase Step-by-Step Fix Guide:</b> For every anomaly, generates exact commands for Phase 1 (Containment), Phase 2 (Forensic Staging), "
        "Phase 3 (Eradication), and Phase 4 (Post-fix Verification).<br/>"
        "• <b>Log & Console Upload with Raw Stream Viewer:</b> For remote or offline hosts, operators can drag & drop <code>console_execution.log</code>, "
        "<code>.txt</code> reports, or <code>.json</code> scans directly into the web UI, toggling the embedded terminal stream at will.",
        bullet_style
    ))
    story.append(Spacer(1, 6))

    story.append(make_code_box(
        "# Manual Portal Launch Command:\n"
        "python portal_server.py\n"
        "# Portal listens on http://127.0.0.1:8888 with zero external dependencies."
    ))
    story.append(Spacer(1, 6))

    # Build Document
    print("[*] Generating PDF pages via ReportLab DocTemplate...")
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully compiled: {output_filename} ({os.path.getsize(output_filename)} bytes)")


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "cyber_defense_playbook.pdf"
    generate_pdf(out_file)

