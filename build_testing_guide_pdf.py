#!/usr/bin/env python3
"""
build_testing_guide_pdf.py
================================================================================
Automated PDF Generator for:
"COMPROMISE ASSESSMENT TOOLKIT: LAB VALIDATION & TESTING GUIDE"
Controlled Heuristic Verification, Benign Artifact Simulation & Unit Testing Field Manual
================================================================================
Generates 'audit_toolkit_testing_guide.pdf' in the current workspace directory.
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
        self.drawString(36, 756, "LAB VALIDATION & TESTING GUIDE // COMPROMISE ASSESSMENT TOOLKIT")
        self.setFont("Helvetica", 7.5)
        self.drawRightString(576, 756, "DETECTION ENGINEERING & QA")

        # Header Rule Line
        self.setStrokeColor(colors.HexColor("#CBD5E1"))
        self.setLineWidth(0.6)
        self.line(36, 750, 576, 750)

        # Footer Rule Line
        self.line(36, 45, 576, 45)

        # Running Bottom Footer
        self.setFont("Helvetica-Bold", 7.5)
        self.setFillColor(colors.HexColor("#DC2626"))
        self.drawString(36, 32, "CONTROLLED LAB MANUAL // BENIGN ADVERSARY EMULATION & UNIT TESTING")

        self.setFont("Helvetica", 7.5)
        self.setFillColor(colors.HexColor("#64748B"))
        page_str = f"Page {self._pageNumber} of {total_pages}"
        self.drawRightString(576, 32, page_str)

        self.restoreState()


# ------------------------------------------------------------------------------
# PDF Builder Function
# ------------------------------------------------------------------------------
def generate_pdf(output_filename="audit_toolkit_testing_guide.pdf"):
    print(f"[*] Compiling Lab Validation & Testing Guide: {output_filename}...")

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

    title_style = ParagraphStyle(
        'CoverTitle',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=23,
        leading=27,
        textColor=C_PRIMARY,
        alignment=0,
        spaceAfter=8
    )

    subtitle_style = ParagraphStyle(
        'CoverSubtitle',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=11.5,
        leading=15,
        textColor=C_ACCENT,
        alignment=0,
        spaceAfter=14
    )

    h1_style = ParagraphStyle(
        'SectionH1',
        parent=styles['Heading1'],
        fontName='Helvetica-Bold',
        fontSize=13.5,
        leading=17,
        textColor=C_PRIMARY,
        spaceBefore=12,
        spaceAfter=6,
        keepWithNext=True
    )

    h2_style = ParagraphStyle(
        'SectionH2',
        parent=styles['Heading2'],
        fontName='Helvetica-Bold',
        fontSize=10,
        leading=13.5,
        textColor=C_ACCENT,
        spaceBefore=9,
        spaceAfter=4,
        keepWithNext=True
    )

    h3_style = ParagraphStyle(
        'SectionH3',
        parent=styles['Heading3'],
        fontName='Helvetica-Bold',
        fontSize=8.5,
        leading=11.5,
        textColor=C_SECONDARY,
        spaceBefore=6,
        spaceAfter=3,
        keepWithNext=True
    )

    body_style = ParagraphStyle(
        'BodyDark',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=8.2,
        leading=11.2,
        textColor=C_TEXT,
        spaceAfter=4
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
        fontSize=7.0,
        leading=9.0,
        textColor=C_CODE_TXT
    )

    tbl_header_style = ParagraphStyle(
        'TblHeader',
        parent=styles['Normal'],
        fontName='Helvetica-Bold',
        fontSize=7.8,
        leading=9.8,
        textColor=colors.white,
        alignment=0
    )

    tbl_cell_style = ParagraphStyle(
        'TblCell',
        parent=styles['Normal'],
        fontName='Helvetica',
        fontSize=7.2,
        leading=9.2,
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
        fontSize=6.8,
        leading=8.5,
        textColor=colors.HexColor("#0F172A")
    )

    # --------------------------------------------------------------------------
    # Flowable Helper Functions
    # --------------------------------------------------------------------------
    def make_callout(level, title, message):
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

        title_p = Paragraph(f"<b>[{level}] {title}</b>", ParagraphStyle('CalloutT', parent=body_style, fontName='Helvetica-Bold', fontSize=8.2, leading=10.5, textColor=txt_col))
        msg_p = Paragraph(message, ParagraphStyle('CalloutM', parent=body_style, fontSize=7.8, leading=10.2, textColor=txt_col))

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
        formatted_text = code_text.replace("\n", "<br/>").replace(" ", "&nbsp;")
        p = Paragraph(formatted_text, code_style)
        tbl = Table([[p]], colWidths=[PAGE_WIDTH])
        tbl.setStyle(TableStyle([
            ('BACKGROUND', (0,0), (-1,-1), C_BG_CODE),
            ('BOX', (0,0), (-1,-1), 0.5, colors.HexColor("#334155")),
            ('TOPPADDING', (0,0), (-1,-1), 4),
            ('BOTTOMPADDING', (0,0), (-1,-1), 5),
            ('LEFTPADDING', (0,0), (-1,-1), 8),
            ('RIGHTPADDING', (0,0), (-1,-1), 8),
        ]))
        return tbl

    story = []

    # ==========================================================================
    # COVER / EXECUTIVE HEADER
    # ==========================================================================
    badge_p = Paragraph("<b>SECURITY VALIDATION & DETECTION ENGINEERING LAB MANUAL // LEVEL 2</b>", ParagraphStyle(
        'Badge', parent=styles['Normal'], fontName='Helvetica-Bold', fontSize=8, leading=10, textColor=colors.HexColor("#1D4ED8")
    ))
    badge_tbl = Table([[badge_p]], colWidths=[PAGE_WIDTH])
    badge_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#EFF6FF")),
        ('BOX', (0,0), (-1,-1), 1, colors.HexColor("#3B82F6")),
        ('TOPPADDING', (0,0), (-1,-1), 3),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3),
        ('LEFTPADDING', (0,0), (-1,-1), 6),
    ]))
    story.append(badge_tbl)
    story.append(Spacer(1, 10))

    story.append(Paragraph("AUDIT TOOLKIT LAB VALIDATION & TESTING GUIDE", title_style))
    story.append(Paragraph("Controlled Heuristic Verification, Benign Artifact Simulation & Unit Testing Field Manual", subtitle_style))
    story.append(HRFlowable(width="100%", thickness=1.5, color=C_PRIMARY, spaceBefore=2, spaceAfter=8))

    # Executive Metadata Grid
    meta_data = [
        [
            Paragraph("<b>Target Scripts:</b> windows_compromise_audit.ps1, server_webshell_rootkit_audit.sh, mobile_forensics_audit.sh", tbl_cell_style),
            Paragraph("<b>Lab Paradigm:</b> Synthetic Benign Artifacts / Atomic Red Team Methodology", tbl_cell_style)
        ],
        [
            Paragraph("<b>Target Lab Environments:</b> Hyper-V / VirtualBox VM, Linux VPS Sandbox, Android Emulator / Test Phone", tbl_cell_style),
            Paragraph("<b>Remediation Portal:</b> http://127.0.0.1:8888 (Auto-Spawned & Verified)", tbl_cell_style)
        ]
    ]
    meta_tbl = Table(meta_data, colWidths=[270, 270])
    meta_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,-1), colors.HexColor("#F8FAFC")),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 3.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 3.5),
        ('LEFTPADDING', (0,0), (-1,-1), 5),
        ('RIGHTPADDING', (0,0), (-1,-1), 5),
    ]))
    story.append(meta_tbl)
    story.append(Spacer(1, 8))

    story.append(make_callout(
        'ALERT',
        'GOLDEN RULE OF DETECTION TESTING: ISOLATED LABS & CONTROLLED SIMULATION',
        'In professional security engineering and detection QA, security tools are NEVER tested by intentionally '
        'infecting production machines or live personal hardware with live malware. Instead, practitioners utilize '
        '<b>Atomic Adversary Emulation</b>—creating inert, synthetic, benign mock artifacts (e.g. harmless dummy registry keys, '
        'inert test scripts with eval wrappers, and non-malicious mock services) inside an isolated Virtual Machine (VM). '
        'This proves detection efficacy with 100% mathematical certainty while preserving zero risk of host destabilization.'
    ))
    story.append(Spacer(1, 8))

    # ==========================================================================
    # SECTION 1: Lab Architecture & Isolation Setup
    # ==========================================================================
    story.append(Paragraph("1. Lab Architecture & Safety Prerequisites", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "To rigorously validate that every <code>[ALERT]</code> and <code>[WARN]</code> trigger functions as designed, "
        "establish the following isolated testing topologies:",
        body_style
    ))

    story.append(Paragraph(
        "• <b>Windows VM Lab:</b> Deploy a Windows 10/11 Enterprise Evaluation or Windows Server 2022 virtual machine "
        "(Hyper-V, VirtualBox, or VMware Workstation). Configure the network adapter to <b>Host-Only</b> or <b>Internal</b>. "
        "Take a baseline snapshot (e.g., <code>Clean_Baseline_Snapshot</code>) prior to test execution.<br/>"
        "• <b>Linux Server Sandbox:</b> Set up a local test directory (e.g. <code>/tmp/audit_test_lab/</code>) on your Kali Linux VM or a dedicated disposable cloud VPS ($5 droplet). "
        "No root-level host destruction is required; all simulated webshells and `.htaccess` rules can be placed inside an isolated mock webroot.<br/>"
        "• <b>Mobile Testing Lab:</b> Use an <b>Android Virtual Device (AVD)</b> via Android Studio or a dedicated, factory-reset physical Android test phone "
        "connected over USB with Developer Options enabled.",
        bullet_style
    ))

    story.append(Spacer(1, 6))

    # ==========================================================================
    # SECTION 2: Windows Compromise Auditor Validation
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("2. Validating windows_compromise_audit.ps1 (Controlled Emulation)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "The following PowerShell procedures plant harmless synthetic triggers in the test environment. "
        "Running <code>windows_compromise_audit.ps1</code> will detect each synthetic anomaly, proving the detection logic works.",
        body_style
    ))

    story.append(Paragraph("<b>Step 2.1: Plant Benign Synthetic Test Triggers (Windows PowerShell Admin):</b>", h2_style))
    story.append(Paragraph(
        "Run the following benign simulation script in an Administrator PowerShell window on your test VM:",
        body_style
    ))
    story.append(make_code_box(
        "# ==============================================================================\n"
        "# STEP 1: SIMULATE TEST ANOMALIES (BENIGN MOCK TRIGGERS)\n"
        "# ==============================================================================\n\n"
        "# Trigger A: Unsigned Mock Executable in User Temp Directory\n"
        "$testDir = Join-Path $env:TEMP 'SimulatedThreatLab'\n"
        "New-Item -ItemType Directory -Path $testDir -Force | Out-Null\n"
        "$mockExe = Join-Path $testDir 'mock_unsigned_beacon.exe'\n"
        "# Copy standard cmd.exe as an unsigned mock payload to Temp\n"
        "Copy-Item (Get-Command cmd.exe).Source -Destination $mockExe -Force\n"
        "$testProc = Start-Process -FilePath $mockExe -ArgumentList '/k timeout /t 300' -PassThru\n"
        "Write-Host \"[+] Spawned mock process: PID $($testProc.Id) from $mockExe\" -ForegroundColor Green\n\n"
        "# Trigger B: Registry Run Key LOLBin Persistence\n"
        "$regPath = 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run'\n"
        "Set-ItemProperty -Path $regPath -Name 'Simulated_Backdoor_Trigger' -Value 'powershell.exe -enc V3JpdGUtSG9zdCAiVW5pdFRlc3Qi'\n\n"
        "# Trigger C: IFEO Debugger Hijack Mock\n"
        "$ifeoKey = 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mock_target_app.exe'\n"
        "New-Item -Path $ifeoKey -Force | Out-Null\n"
        "Set-ItemProperty -Path $ifeoKey -Name 'Debugger' -Value 'cmd.exe'\n\n"
        "# Trigger D: Non-Microsoft Scheduled Task with LOLBin & Encoded Flags\n"
        "$action = New-ScheduledTaskAction -Execute 'powershell.exe' -Argument '-enc V3JpdGUtT3V0cHV0IFRlc3Q= -Bypass'\n"
        "$trigger = New-ScheduledTaskTrigger -AtLogon\n"
        "Register-ScheduledTask -TaskName 'Simulated_APT_Task' -Action $action -Trigger $trigger -Description 'Audit QA Test' -Force | Out-Null\n\n"
        "# Trigger E: Temporary Windows Defender Exclusion\n"
        "Add-MpPreference -ExclusionPath $testDir -ErrorAction SilentlyContinue"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 2.2: Execute the Windows Auditor:</b>", h2_style))
    story.append(make_code_box(
        "# Execute the production auditor against the test machine:\n"
        "powershell.exe -ExecutionPolicy Bypass -NoProfile -File .\\windows_compromise_audit.ps1"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 2.3: Verification Checklist & Expected Outputs:</b>", h2_style))
    story.append(Paragraph(
        "Examine the terminal and the generated <code>Compromise_Assessment_Report.txt</code>. Verify the following detections appear:",
        body_style
    ))

    win_expected_data = [
        [
            Paragraph("<b>Target Synthetic Trigger</b>", tbl_header_style),
            Paragraph("<b>Module Audited</b>", tbl_header_style),
            Paragraph("<b>Expected Report Output Signal</b>", tbl_header_style),
            Paragraph("<b>Status</b>", tbl_header_style)
        ],
        [
            Paragraph("<code>mock_unsigned_beacon.exe</code> in Temp", tbl_cell_bold),
            Paragraph("Module 2: Unsigned Processes", tbl_cell_style),
            Paragraph("<code>[-] CRITICAL: Unsigned process executing from user-writable directory (PID: ...)</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("Run Key with <code>powershell.exe -enc</code>", tbl_cell_bold),
            Paragraph("Module 4: Registry Run Keys", tbl_cell_style),
            Paragraph("<code>[-] Suspicious Registry Persistence entry invoking LOLBin: Simulated_Backdoor_Trigger</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("IFEO Debugger on <code>mock_target_app.exe</code>", tbl_cell_bold),
            Paragraph("Module 4: IFEO Debugger Hijacks", tbl_cell_style),
            Paragraph("<code>[-] IFEO Debugger Backdoor detected on 'mock_target_app.exe'! Execution intercepted by: cmd.exe</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("Task <code>Simulated_APT_Task</code> with <code>-enc</code>", tbl_cell_bold),
            Paragraph("Module 6: Scheduled Tasks", tbl_cell_style),
            Paragraph("<code>[-] Suspicious non-Microsoft Scheduled Task detected: Simulated_APT_Task</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("Exclusion on <code>$testDir</code>", tbl_cell_bold),
            Paragraph("Module 7: Defender Exclusions", tbl_cell_style),
            Paragraph("<code>[-] Defender Path Exclusion Configured (Potential Blindspot): ...\\SimulatedThreatLab</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ]
    ]
    win_exp_tbl = Table(win_expected_data, colWidths=[130, 110, 230, 70])
    win_exp_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 3.5),
        ('RIGHTPADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(win_exp_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 2.4: Immediate Cleanup & Teardown Script:</b>", h2_style))
    story.append(make_code_box(
        "# ==============================================================================\n"
        "# TEARDOWN SCRIPT: PURGE ALL BENIGN TEST ARTIFACTS\n"
        "# ==============================================================================\n"
        "Stop-Process -Id $testProc.Id -Force -ErrorAction SilentlyContinue\n"
        "Remove-Item -Path $testDir -Recurse -Force -ErrorAction SilentlyContinue\n"
        "Remove-ItemProperty -Path 'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Run' -Name 'Simulated_Backdoor_Trigger' -ErrorAction SilentlyContinue\n"
        "Remove-Item -Path 'HKLM:\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\mock_target_app.exe' -Recurse -Force -ErrorAction SilentlyContinue\n"
        "Unregister-ScheduledTask -TaskName 'Simulated_APT_Task' -Confirm:$false -ErrorAction SilentlyContinue\n"
        "Remove-MpPreference -ExclusionPath $testDir -ErrorAction SilentlyContinue\n"
        "Write-Host '[+] All test artifacts eradicated. Baseline state fully restored.' -ForegroundColor Green"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 2.5: Verifying Portal Auto-Spawn & Report Ingestion:</b>", h2_style))
    story.append(Paragraph(
        "1. Confirm that <code>portal_server.py</code> was automatically spawned in the background by the audit script.<br/>"
        "2. Open <b>http://127.0.0.1:8888</b> in your browser and verify that the scan <code>win_audit_...</code> appears in the sidebar.<br/>"
        "3. Inspect the dynamically generated 4-phase remediation steps (Process termination, Carving, Deletion, Verification) for each detected anomaly.<br/>"
        "4. Check the 'Resolved' boxes on the findings to confirm the Host Risk Score drops from 100% to 0%.",
        bullet_style
    ))

    # ==========================================================================
    # SECTION 3: Linux Server Auditor Validation
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("3. Validating server_webshell_rootkit_audit.sh (Linux Sandbox)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "To test the server webshell and rootkit auditor on Kali Linux or a test Linux VPS, create an isolated "
        "synthetic webroot directory populated with harmless inert test files that mimic webshell signatures.",
        body_style
    ))

    story.append(Paragraph("<b>Step 3.1: Construct the Synthetic Webroot Sandbox (Bash):</b>", h2_style))
    story.append(make_code_box(
        "# Create an isolated sandbox directory in /tmp\n"
        "MOCK_WEBROOT=\"/tmp/audit_test_sandbox\"\n"
        "rm -rf \"$MOCK_WEBROOT\"\n"
        "mkdir -p \"$MOCK_WEBROOT/wp-content/uploads/2026/01\"\n"
        "mkdir -p \"$MOCK_WEBROOT/includes\"\n\n"
        "# 1. Create a benign mock PHP file containing obfuscated eval signature\n"
        "# (This executes a harmless 'echo unit test passed', triggering the signature scanner)\n"
        "echo '<?php eval(base64_decode(\"ZWNobyAiVGVzdCBQYXNzZWQiOw==\")); ?>' > \"$MOCK_WEBROOT/includes/mock_eval.php\"\n\n"
        "# 2. Place an inert rogue PHP script inside the upload folder\n"
        "echo '<?php echo \"Mock rogue script in upload folder\"; ?>' > \"$MOCK_WEBROOT/wp-content/uploads/2026/01/avatar.php\"\n\n"
        "# 3. Create a malicious .htaccess file with auto_prepend_file\n"
        "echo 'php_value auto_prepend_file /tmp/backdoor.php' > \"$MOCK_WEBROOT/.htaccess\"\n\n"
        "# 4. Create a world-writable test configuration file\n"
        "echo 'DB_PASSWORD=secret_mock_password' > \"$MOCK_WEBROOT/.env\"\n"
        "chmod 777 \"$MOCK_WEBROOT/.env\"\n\n"
        "echo \"[+] Synthetic mock webroot constructed at $MOCK_WEBROOT\""
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 3.2: Execute the Linux Auditor:</b>", h2_style))
    story.append(make_code_box(
        "chmod +x server_webshell_rootkit_audit.sh\n"
        "./server_webshell_rootkit_audit.sh /tmp/audit_test_sandbox"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 3.3: Verification Checklist & Expected Outputs:</b>", h2_style))

    linux_expected_data = [
        [
            Paragraph("<b>Target Synthetic Trigger</b>", tbl_header_style),
            Paragraph("<b>Module Audited</b>", tbl_header_style),
            Paragraph("<b>Expected Log Output Signal</b>", tbl_header_style),
            Paragraph("<b>Status</b>", tbl_header_style)
        ],
        [
            Paragraph("<code>mock_eval.php</code>", tbl_cell_bold),
            Paragraph("Module 1: Signature Scanner", tbl_cell_style),
            Paragraph("<code>[-] Potential PHP Webshell / RCE primitives detected! eval(base64_decode...</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("<code>avatar.php</code> in uploads", tbl_cell_bold),
            Paragraph("Module 2: Upload Directory", tbl_cell_style),
            Paragraph("<code>[-] HIGH RISK: Found 1 executable script(s) in static/upload directories</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("<code>auto_prepend_file</code> in .htaccess", tbl_cell_bold),
            Paragraph("Module 4: .htaccess Hijacking", tbl_cell_style),
            Paragraph("<code>[-] CRITICAL: Suspicious .htaccess directives detected: auto_prepend_file</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ],
        [
            Paragraph("World-writable <code>.env</code> file", tbl_cell_bold),
            Paragraph("Module 8: File Permissions", tbl_cell_style),
            Paragraph("<code>[-] Found 1 world-writable executable/config file(s): .../.env</code>", tbl_cell_code),
            Paragraph("PASS [ALERT]", tbl_cell_bold)
        ]
    ]
    linux_exp_tbl = Table(linux_expected_data, colWidths=[120, 110, 240, 70])
    linux_exp_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 3.5),
        ('RIGHTPADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(linux_exp_tbl)
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 3.4: Linux Cleanup Command:</b>", h2_style))
    story.append(make_code_box(
        "rm -rf /tmp/audit_test_sandbox\n"
        "echo '[+] Test sandbox deleted cleanly.'"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 3.5: Verifying Linux Report Ingestion into Portal:</b>", h2_style))
    story.append(Paragraph(
        "1. Confirm that <code>server_security_audit_&lt;TIMESTAMP&gt;.json</code> was generated alongside the plain text log.<br/>"
        "2. If testing locally, verify the script transmitted the JSON report to <code>http://127.0.0.1:8888/api/upload_report</code>.<br/>"
        "3. If testing on a remote VPS, drag and drop the JSON report or plain text log directly into the Portal dropzone to view the remediation guide.",
        bullet_style
    ))

    # ==========================================================================
    # SECTION 4: Mobile Forensics Auditor Validation
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("4. Validating mobile_forensics_audit.sh (Android & iOS)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "To test mobile auditing capabilities without risking a production smartphone, utilize an "
        "Android Emulator (AVD) or a dedicated test smartphone with standard testing conditions.",
        body_style
    ))

    story.append(Paragraph("<b>Step 4.1: Android Lab Simulation Setup:</b>", h2_style))
    story.append(Paragraph(
        "1. Start an Android Virtual Device via Android Studio or connect a test phone with USB Debugging enabled.<br/>"
        "2. Sideload any standard open-source APK (e.g. F-Droid, VLC, or a sample Hello-World APK) via ADB. "
        "Because it was installed via ADB and not Google Play, its installer package will be empty or non-standard.<br/>"
        "3. (Optional) Install a test self-signed user Root CA certificate via Settings -> Security -> Install from Storage.",
        bullet_style
    ))
    story.append(make_code_box(
        "# Download and sideload a harmless open-source APK to test sideload detection:\n"
        "curl -L -o /tmp/sample_test_app.apk https://f-droid.org/F-Droid.apk\n"
        "adb install /tmp/sample_test_app.apk"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 4.2: Execute the Mobile Auditor:</b>", h2_style))
    story.append(make_code_box(
        "chmod +x mobile_forensics_audit.sh\n"
        "./mobile_forensics_audit.sh android"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 4.3: Expected Mobile Report Outputs:</b>", h2_style))
    story.append(Paragraph(
        "• <b>Verified Boot Check:</b> Reports <code>[OK]</code> if locked, or <code>[ALERT]</code> if running on an unlocked emulator bootloader.<br/>"
        "• <b>Sideloaded Package Detection:</b> Flags <code>[WARN] Sideloaded / Non-Play-Store Package: org.fdroid.fdroid (Installer: NONE/Direct-APK)</code>.<br/>"
        "• <b>MVT STIX2 IOC Engine:</b> Updates IOCs from Amnesty International and scans system records without crashing.<br/>"
        "• <b>Cleanup:</b> <code>adb uninstall org.fdroid.fdroid</code>.",
        bullet_style
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 4.4: Verifying Mobile Forensics Ingestion into Portal:</b>", h2_style))
    story.append(Paragraph(
        "1. Confirm that <code>mobile_forensics_report.json</code> was created in <code>$OUT_DIR</code>.<br/>"
        "2. Open <b>http://127.0.0.1:8888</b> and select the mobile scan from the sidebar to review the step-by-step uninstallation and root CA removal guides.",
        bullet_style
    ))

    # ==========================================================================
    # SECTION 5: Cyber Defense Portal Verification (portal_server.py)
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("5. Validating the Cyber Defense Portal (portal_server.py)", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=6))

    story.append(Paragraph(
        "The portal operates as an independent, multi-threaded incident response platform. Follow these steps to validate its standalone capabilities:",
        body_style
    ))

    story.append(Paragraph("<b>Step 5.1: Health Check & Standalone Startup:</b>", h2_style))
    story.append(make_code_box(
        "# Launch the portal manually:\n"
        "python portal_server.py\n\n"
        "# In another terminal, verify the REST health probe:\n"
        "curl http://127.0.0.1:8888/api/health\n"
        "# Expected response: {\"status\": \"ok\", \"version\": \"1.0.0\", ...}"
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 5.2: Verifying Pre-Seeded Baseline Reports:</b>", h2_style))
    story.append(Paragraph(
        "Open <b>http://127.0.0.1:8888</b> in your browser. Confirm that the portal immediately loads with three rich baseline reports in the sidebar:<br/>"
        "• <b>sample_windows_audit:</b> Displays 2 Critical Alerts (Unsigned process in Temp, Registry Run LOLBin) and 1 Warning.<br/>"
        "• <b>sample_linux_vps_audit:</b> Displays 3 Critical Alerts (PHP webshell with eval, upload directory script, .htaccess hijack).<br/>"
        "• <b>sample_mobile_forensic_audit:</b> Displays Root CA TLS interception alert and sideloaded APK warning.",
        bullet_style
    ))
    story.append(Spacer(1, 6))

    story.append(Paragraph("<b>Step 5.3: Testing Log File Upload & 'What Went Well / What Went Wrong' Analysis:</b>", h2_style))
    story.append(Paragraph(
        "Upload any saved <code>console_execution.log</code>, <code>Compromise_Assessment_Report.txt</code>, or <code>.json</code> "
        "report using either the top navigation button or central dropzone. Confirm that:<br/>"
        "1. <b>Executive Posture Breakdown:</b> The portal parses the log and generates the side-by-side <b>'What Went Well'</b> "
        "(verified clean baselines) and <b>'What Went Wrong'</b> (threats, blindspots, script runtime warnings) cards.<br/>"
        "2. <b>Tactical Remediation Mapping:</b> Each identified issue links directly to its 4-phase copyable fix commands.<br/>"
        "3. <b>Embedded Console Viewer:</b> The collapsible 'RAW CONSOLE EXECUTION LOG STREAM' card displays verbatim terminal output.",
        bullet_style
    ))
    story.append(Spacer(1, 6))

    # ==========================================================================
    # SECTION 6: Quality Assurance Scorecard & Verification Matrix
    # ==========================================================================
    story.append(PageBreak())
    story.append(Paragraph("6. Quality Assurance Scorecard & Sign-Off Matrix", h1_style))
    story.append(HRFlowable(width="100%", thickness=0.8, color=C_ACCENT, spaceBefore=1, spaceAfter=6))

    scorecard_data = [
        [
            Paragraph("<b>Toolkit Component</b>", tbl_header_style),
            Paragraph("<b>Lab Verification Target</b>", tbl_header_style),
            Paragraph("<b>Test Procedure</b>", tbl_header_style),
            Paragraph("<b>Expected Output</b>", tbl_header_style),
            Paragraph("<b>Operator Sign-Off</b>", tbl_header_style)
        ],
        [
            Paragraph("<code>windows_compromise_audit.ps1</code>", tbl_cell_bold),
            Paragraph("Unsigned User-Path Binary", tbl_cell_style),
            Paragraph("Spawn mock cmd.exe in %TEMP%", tbl_cell_style),
            Paragraph("<code>[ALERT]</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>windows_compromise_audit.ps1</code>", tbl_cell_bold),
            Paragraph("Registry Run LOLBin", tbl_cell_style),
            Paragraph("Set HKCU Run with -enc flag", tbl_cell_style),
            Paragraph("<code>[ALERT]</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>windows_compromise_audit.ps1</code>", tbl_cell_bold),
            Paragraph("IFEO Debugger Hook", tbl_cell_style),
            Paragraph("Set Debugger value on mock key", tbl_cell_style),
            Paragraph("<code>[ALERT]</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>server_webshell_rootkit_audit.sh</code>", tbl_cell_bold),
            Paragraph("PHP Obfuscation Regex", tbl_cell_style),
            Paragraph("eval(base64_decode(...)) mock", tbl_cell_style),
            Paragraph("<code>[ALERT]</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>server_webshell_rootkit_audit.sh</code>", tbl_cell_bold),
            Paragraph("Upload Directory Isolation", tbl_cell_style),
            Paragraph("Place .php in /uploads/ mock", tbl_cell_style),
            Paragraph("<code>[ALERT]</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>mobile_forensics_audit.sh</code>", tbl_cell_bold),
            Paragraph("Sideloaded Package Audit", tbl_cell_style),
            Paragraph("Direct ADB install of sample APK", tbl_cell_style),
            Paragraph("<code>[WARN]</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>portal_server.py</code>", tbl_cell_bold),
            Paragraph("Auto-Spawn Mechanism", tbl_cell_style),
            Paragraph("Run audit script with portal offline", tbl_cell_style),
            Paragraph("<code>AUTO-START</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>portal_server.py</code>", tbl_cell_bold),
            Paragraph("Structured JSON Ingestion", tbl_cell_style),
            Paragraph("POST Compromise_Report.json", tbl_cell_style),
            Paragraph("<code>200 SUCCESS</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ],
        [
            Paragraph("<code>portal_server.py</code>", tbl_cell_bold),
            Paragraph("Dynamic Host Risk Meter", tbl_cell_style),
            Paragraph("Toggle 'Resolved' checkboxes", tbl_cell_style),
            Paragraph("<code>100% -> 0%</code>", tbl_cell_code),
            Paragraph("[  ] VERIFIED", tbl_cell_bold)
        ]
    ]
    score_tbl = Table(scorecard_data, colWidths=[110, 105, 130, 95, 100])
    score_tbl.setStyle(TableStyle([
        ('BACKGROUND', (0,0), (-1,0), C_SECONDARY),
        ('BOX', (0,0), (-1,-1), 0.5, C_BORDER),
        ('INNERGRID', (0,0), (-1,-1), 0.5, C_BORDER),
        ('TOPPADDING', (0,0), (-1,-1), 2.5),
        ('BOTTOMPADDING', (0,0), (-1,-1), 2.5),
        ('LEFTPADDING', (0,0), (-1,-1), 3.5),
        ('RIGHTPADDING', (0,0), (-1,-1), 3.5),
        ('ROWBACKGROUNDS', (0,1), (-1,-1), [colors.white, colors.HexColor("#F8FAFC")])
    ]))
    story.append(score_tbl)
    story.append(Spacer(1, 8))

    story.append(make_callout(
        'SUCCESS',
        'LAB VALIDATION COMPLETE: OPERATIONAL READINESS CONFIRMED',
        'By validating each synthetic trigger against the scorecard, operators establish rigorous scientific proof '
        'that the detection heuristics, regex parsers, and threat intelligence feeds perform flawlessly in enterprise production.'
    ))

    # Build Document
    print("[*] Generating PDF pages via ReportLab DocTemplate...")
    doc.build(story, canvasmaker=NumberedCanvas)
    print(f"[+] Successfully compiled: {output_filename} ({os.path.getsize(output_filename)} bytes)")


if __name__ == "__main__":
    out_file = sys.argv[1] if len(sys.argv) > 1 else "audit_toolkit_testing_guide.pdf"
    generate_pdf(out_file)

