#Requires -Version 5.1
<#
.SYNOPSIS
    Generates the AM Internal Brief and Client Proposal Word documents.
    Output: Docs\ADRemediationAgent-AM-Brief.docx
            Docs\ADRemediationAgent-Client-Proposal.docx

.DESCRIPTION
    Uses Open XML (ZIP + XML) to create DOCX files directly -- no Word process
    or COM automation required.  Compatible with PowerShell 5.1.
#>

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

$repoRoot    = $PSScriptRoot
$docsDir     = Join-Path $repoRoot "Docs"
$amBriefPath = Join-Path $docsDir "ADRemediationAgent-AM-Brief.docx"
$clientPath  = Join-Path $docsDir "ADRemediationAgent-Client-Proposal.docx"

if (-not (Test-Path $docsDir)) {
    New-Item -Path $docsDir -ItemType Directory | Out-Null
    Write-Host "  [+] Created Docs\" -ForegroundColor Gray
}

Write-Host ""
Write-Host "  AD Remediation Agent -- Document Generator" -ForegroundColor Cyan
Write-Host ""

# -----------------------------------------------------------------------
# Static Open XML components
# -----------------------------------------------------------------------
$script:contentTypesXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">
  <Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>
  <Default Extension="xml" ContentType="application/xml"/>
  <Override PartName="/word/document.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.document.main+xml"/>
  <Override PartName="/word/styles.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.styles+xml"/>
  <Override PartName="/word/numbering.xml" ContentType="application/vnd.openxmlformats-officedocument.wordprocessingml.numbering+xml"/>
</Types>
'@

$script:relsXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="word/document.xml"/>
</Relationships>
'@

$script:docRelsXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">
  <Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/styles" Target="styles.xml"/>
  <Relationship Id="rId2" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/numbering" Target="numbering.xml"/>
</Relationships>
'@

$script:stylesXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:styles xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:docDefaults>
    <w:rPrDefault><w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr></w:rPrDefault>
  </w:docDefaults>
  <w:style w:type="paragraph" w:styleId="Normal" w:default="1">
    <w:name w:val="Normal"/>
    <w:pPr><w:spacing w:after="160" w:line="276" w:lineRule="auto"/></w:pPr>
    <w:rPr><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="24"/><w:szCs w:val="24"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading1">
    <w:name w:val="heading 1"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:pPr><w:outlineLvl w:val="0"/><w:spacing w:before="480" w:after="160"/><w:keepNext/></w:pPr>
    <w:rPr><w:b/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="36"/><w:szCs w:val="36"/><w:color w:val="1F3864"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Heading2">
    <w:name w:val="heading 2"/>
    <w:basedOn w:val="Normal"/>
    <w:next w:val="Normal"/>
    <w:pPr><w:outlineLvl w:val="1"/><w:spacing w:before="320" w:after="120"/><w:keepNext/></w:pPr>
    <w:rPr><w:b/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="28"/><w:szCs w:val="28"/><w:color w:val="2E74B5"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Title">
    <w:name w:val="Title"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr><w:jc w:val="center"/><w:spacing w:before="0" w:after="240"/></w:pPr>
    <w:rPr><w:b/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="56"/><w:szCs w:val="56"/><w:color w:val="1F3864"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="Subtitle">
    <w:name w:val="Subtitle"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr><w:jc w:val="center"/><w:spacing w:after="160"/></w:pPr>
    <w:rPr><w:i/><w:rFonts w:ascii="Calibri" w:hAnsi="Calibri"/><w:sz w:val="32"/><w:szCs w:val="32"/><w:color w:val="595959"/></w:rPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="ListBullet">
    <w:name w:val="List Bullet"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:spacing w:after="80"/>
      <w:numPr><w:ilvl w:val="0"/><w:numId w:val="1"/></w:numPr>
    </w:pPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="ListNumber">
    <w:name w:val="List Number"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:spacing w:after="80"/>
      <w:numPr><w:ilvl w:val="0"/><w:numId w:val="2"/></w:numPr>
    </w:pPr>
  </w:style>
  <w:style w:type="paragraph" w:styleId="CodeBlock">
    <w:name w:val="Code Block"/>
    <w:basedOn w:val="Normal"/>
    <w:pPr>
      <w:spacing w:before="120" w:after="120"/>
      <w:shd w:val="clear" w:color="auto" w:fill="F2F2F2"/>
    </w:pPr>
    <w:rPr><w:rFonts w:ascii="Courier New" w:hAnsi="Courier New"/><w:sz w:val="20"/><w:szCs w:val="20"/><w:color w:val="333333"/></w:rPr>
  </w:style>
  <w:style w:type="table" w:styleId="TableGrid">
    <w:name w:val="Table Grid"/>
    <w:tblPr>
      <w:tblBorders>
        <w:top    w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>
        <w:left   w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>
        <w:bottom w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>
        <w:right  w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>
        <w:insideH w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>
        <w:insideV w:val="single" w:sz="4" w:space="0" w:color="BFBFBF"/>
      </w:tblBorders>
    </w:tblPr>
  </w:style>
</w:styles>
'@

$script:numberingXml = @'
<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<w:numbering xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">
  <w:abstractNum w:abstractNumId="0">
    <w:multiLevelType w:val="hybridMultilevel"/>
    <w:lvl w:ilvl="0">
      <w:start w:val="1"/>
      <w:numFmt w:val="bullet"/>
      <w:lvlText w:val="&#x2022;"/>
      <w:lvlJc w:val="left"/>
      <w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>
      <w:rPr><w:sz w:val="24"/></w:rPr>
    </w:lvl>
    <w:lvl w:ilvl="1">
      <w:start w:val="1"/>
      <w:numFmt w:val="bullet"/>
      <w:lvlText w:val="&#x25E6;"/>
      <w:lvlJc w:val="left"/>
      <w:pPr><w:ind w:left="1440" w:hanging="360"/></w:pPr>
    </w:lvl>
  </w:abstractNum>
  <w:abstractNum w:abstractNumId="1">
    <w:multiLevelType w:val="hybridMultilevel"/>
    <w:lvl w:ilvl="0">
      <w:start w:val="1"/>
      <w:numFmt w:val="decimal"/>
      <w:lvlText w:val="%1."/>
      <w:lvlJc w:val="left"/>
      <w:pPr><w:ind w:left="720" w:hanging="360"/></w:pPr>
    </w:lvl>
  </w:abstractNum>
  <w:num w:numId="1"><w:abstractNumId w:val="0"/></w:num>
  <w:num w:numId="2"><w:abstractNumId w:val="1"/></w:num>
</w:numbering>
'@

# -----------------------------------------------------------------------
# XML helper functions
# -----------------------------------------------------------------------
function xEsc([string]$t) {
    return $t -replace '&','&amp;' -replace '<','&lt;' -replace '>','&gt;' -replace '"','&quot;'
}

# Plain paragraph (Normal style by default)
function xP([string]$text = "", [string]$style = "Normal") {
    $pp = if ($style -ne "Normal") { "<w:pPr><w:pStyle w:val=`"$style`"/></w:pPr>" } else { "" }
    if (-not $text) { return "<w:p>$pp</w:p>" }
    $t = xEsc $text
    return "<w:p>$pp<w:r><w:t xml:space=`"preserve`">$t</w:t></w:r></w:p>"
}

# Meta-info paragraph: bold label + normal value
function xMeta([string]$label, [string]$value) {
    $l = xEsc $label
    $v = xEsc $value
    return "<w:p><w:pPr><w:spacing w:after=`"80`"/></w:pPr><w:r><w:rPr><w:b/></w:rPr><w:t xml:space=`"preserve`">$l</w:t></w:r><w:r><w:t xml:space=`"preserve`">$v</w:t></w:r></w:p>"
}

# Code paragraph (monospace, shaded)
function xCode([string]$text) {
    $t = xEsc $text
    return "<w:p><w:pPr><w:pStyle w:val=`"CodeBlock`"/></w:pPr><w:r><w:t xml:space=`"preserve`">$t</w:t></w:r></w:p>"
}

# Page break
function xBrk() { return "<w:p><w:r><w:br w:type=`"page`"/></w:r></w:p>" }

# Table -- auto-width to page (9360 twips = ~6.5 in with 1.25-in margins)
function xTable([string[]]$headers, [string[][]]$rows) {
    $cols     = $headers.Count
    $colWidth = [int](9360 / $cols)
    $hdrFill  = "2E74B5"

    $tblPr  = "<w:tblPr><w:tblStyle w:val=`"TableGrid`"/><w:tblW w:w=`"9360`" w:type=`"dxa`"/></w:tblPr>"
    $tblGrid = "<w:tblGrid>" + (($headers | ForEach-Object { "<w:gridCol w:w=`"$colWidth`"/>" }) -join "") + "</w:tblGrid>"

    # Header row
    $hdrCells = ""
    foreach ($h in $headers) {
        $ht = xEsc $h
        $hdrCells += "<w:tc><w:tcPr><w:tcW w:w=`"$colWidth`" w:type=`"dxa`"/><w:shd w:val=`"clear`" w:color=`"auto`" w:fill=`"$hdrFill`"/></w:tcPr>" +
                     "<w:p><w:pPr><w:spacing w:after=`"80`"/></w:pPr><w:r><w:rPr><w:b/><w:color w:val=`"FFFFFF`"/></w:rPr><w:t xml:space=`"preserve`">$ht</w:t></w:r></w:p></w:tc>"
    }
    $tblRows = "<w:tr>$hdrCells</w:tr>"

    # Data rows (alternating shading)
    $ri = 0
    foreach ($row in $rows) {
        $fill  = if ($ri % 2 -eq 0) { "EBF3FB" } else { "FFFFFF" }
        $cells = ""
        for ($c = 0; $c -lt $cols; $c++) {
            $cv = if ($c -lt $row.Count) { $row[$c] } else { "" }
            $ct = xEsc $cv
            $cells += "<w:tc><w:tcPr><w:tcW w:w=`"$colWidth`" w:type=`"dxa`"/><w:shd w:val=`"clear`" w:color=`"auto`" w:fill=`"$fill`"/></w:tcPr>" +
                      "<w:p><w:pPr><w:spacing w:after=`"80`"/></w:pPr><w:r><w:t xml:space=`"preserve`">$ct</w:t></w:r></w:p></w:tc>"
        }
        $tblRows += "<w:tr>$cells</w:tr>"
        $ri++
    }

    return "<w:tbl>$tblPr$tblGrid$tblRows</w:tbl><w:p/>"
}

# Build the full document.xml string
function Build-DocumentXml([string[]]$bodyParts) {
    $body = $bodyParts -join ""
    return ('<?xml version="1.0" encoding="UTF-8" standalone="yes"?>' +
        '<w:document xmlns:w="http://schemas.openxmlformats.org/wordprocessingml/2006/main">' +
        '<w:body>' + $body +
        '<w:sectPr><w:pgSz w:w="12240" w:h="15840"/><w:pgMar w:top="1440" w:right="1800" w:bottom="1440" w:left="1800"/></w:sectPr>' +
        '</w:body></w:document>')
}

# Write a DOCX file (ZIP containing the Open XML parts)
function Save-Docx([string]$path, [string]$docXml) {
    if (Test-Path $path) { Remove-Item $path -Force }
    $enc    = New-Object System.Text.UTF8Encoding($false)   # no BOM
    $stream = [System.IO.File]::Open($path, [System.IO.FileMode]::Create)
    try {
        $zip = New-Object System.IO.Compression.ZipArchive($stream, [System.IO.Compression.ZipArchiveMode]::Create)
        try {
            $parts = @{
                "[Content_Types].xml"          = $script:contentTypesXml
                "_rels/.rels"                  = $script:relsXml
                "word/_rels/document.xml.rels" = $script:docRelsXml
                "word/styles.xml"              = $script:stylesXml
                "word/numbering.xml"           = $script:numberingXml
                "word/document.xml"            = $docXml
            }
            foreach ($key in $parts.Keys) {
                $entry  = $zip.CreateEntry($key)
                $writer = New-Object System.IO.StreamWriter($entry.Open(), $enc)
                $writer.Write($parts[$key].Trim())
                $writer.Close()
            }
        } finally { $zip.Dispose() }
    } finally { $stream.Dispose() }
}

# -----------------------------------------------------------------------
# Milestone data
# -----------------------------------------------------------------------
$milestonesAM = @(
    [string[]]@("M1",  "DC Health and Baseline",           "Implemented", "No -- flags only",                        "INFO to HIGH"),
    [string[]]@("M2",  "DC Upgrade to Windows Server 2025","Manual",      "N/A -- manual process",                   "HIGH / CRITICAL"),
    [string[]]@("M3",  "OU Structure Cleanup",             "Implemented", "No -- Discover-only",                     "LOW / MEDIUM"),
    [string[]]@("M4",  "Unconstrained Delegation",         "Implemented", "Yes -- per-object approval",              "HIGH / CRITICAL"),
    [string[]]@("M5",  "SPN Audit",                        "Implemented", "Partial -- AES enc. type with approval",  "MEDIUM / HIGH"),
    [string[]]@("M6",  "Kerberos Configuration",           "Implemented", "Partial -- AES enc. type with approval",  "MEDIUM / HIGH"),
    [string[]]@("M7",  "DC Hardening and CIS L1 Baseline", "Implemented", "Yes -- registry changes with approval",   "HIGH / CRITICAL"),
    [string[]]@("M8",  "GPO Cleanup",                      "Implemented", "Yes -- backup-first; disable/delete",     "LOW / MEDIUM"),
    [string[]]@("M9",  "Security Group Cleanup",           "Implemented", "Yes -- with approval",                    "LOW / MEDIUM"),
    [string[]]@("M10", "Delegated Permissions Review",     "Implemented", "Yes -- DC OU ACE removal with approval",  "HIGH / CRITICAL"),
    [string[]]@("M11", "Stale Account Quarantine",         "Implemented", "Yes -- bulk approval; disable and move",  "LOW / MEDIUM"),
    [string[]]@("M12", "Privileged Group Review",          "Implemented", "Yes -- per-member approval",              "HIGH / CRITICAL")
)

# -----------------------------------------------------------------------
# DOCUMENT 1: AM INTERNAL BRIEF
# -----------------------------------------------------------------------
Write-Host "  Building AM Brief..." -ForegroundColor Gray

$amBody = @(
    # Cover
    xP "AD Remediation Agent" "Title"
    xP "Account Manager Internal Brief" "Subtitle"
    xP ""
    xMeta "Client:  "         "MetLife"
    xMeta "Prepared by:  "    "Fusion5"
    xMeta "Date:  "           "March 2026"
    xMeta "Classification:  " "INTERNAL -- Fusion5 Confidential"
    xP ""
    xBrk

    # Section 1
    xP "Engagement Context" "Heading1"
    xP "MetLife engaged Fusion5 to deliver an Active Directory (AD) security assessment and remediation solution to support their planned Domain Controller (DC) upgrade from Windows Server 2019 to Windows Server 2025. The engagement addresses a comprehensive review of AD security posture across 12 defined milestones, covering areas from DC health and baseline configuration through to privileged access governance and delegated permissions review."
    xP "The primary drivers for this engagement are:"
    xP "DC operating system upgrade to Windows Server 2025 (in-place and swing migration approach)" "ListBullet"
    xP "Active Directory security hygiene to reduce attack surface prior to and following the upgrade" "ListBullet"
    xP "CIS Benchmark Level 1 compliance alignment for Windows Server 2022 / 2025" "ListBullet"
    xP "NIST SP 800-53 control evidence generation for governance and audit reporting" "ListBullet"
    xP "Hybrid Azure AD Join environment considerations, including Windows Hello for Business Kerberos hybrid trust" "ListBullet"
    xP "MetLife's environment includes Domain Controllers currently running Windows Server 2019, a hybrid Azure AD join configuration, and legacy applications with IP-bound dependencies on DC addresses -- all of which have been accounted for in the solution design."

    # Section 2
    xP "Solution Delivered" "Heading1"
    xP "The deliverable is the AD Remediation Agent -- a PowerShell 5.1 automation framework that discovers, baselines, and remediates Active Directory security findings across all 12 milestones. It runs from any domain-joined Windows machine or Privileged Access Workstation (PAW) and requires no additional software beyond the ActiveDirectory RSAT module (plus GPMC for GPO-related checks)."
    xP "The agent operates in four modes:"
    xP ""
    xTable @("Mode","Description","Makes Changes") @(
        [string[]]@("Discover",  "Runs all checks, logs findings, produces HTML report with CIS and NIST annotations", "No"),
        [string[]]@("Baseline",  "Snapshots current AD state as the approved reference point for drift tracking",       "No"),
        [string[]]@("Remediate", "Runs checks then prompts for explicit human approval before each change",              "Yes -- with approval only"),
        [string[]]@("Report",    "Generates a historical drift report from stored baselines. No AD queries.",            "No")
    )
    xP "Key Technical Characteristics" "Heading2"
    xP "PowerShell 5.1 only -- ships in-box on Windows Server 2019 and 2025; no additional runtime required" "ListBullet"
    xP "Compliance-mapped findings -- every finding carries CIS Benchmark Level 1 control and NIST SP 800-53 control ID" "ListBullet"
    xP "Human-in-the-loop -- no change is ever made without explicit operator approval at the CLI" "ListBullet"
    xP "Typed confirmation required for HIGH and CRITICAL risk changes (operator must type the target name)" "ListBullet"
    xP "DC Upgrade Gate -- blocks M3-M12 remediation until all DCs are confirmed on the target OS" "ListBullet"
    xP "Safe-by-default -- no AD objects are ever deleted; stale accounts are quarantined (disabled and moved)" "ListBullet"
    xP "Full audit trail -- every run, finding, approval, and denial is logged to a structured CSV and HTML report" "ListBullet"
    xP "Baseline and drift tracking -- subsequent runs compare against a stored baseline and label findings as New, Persisting, or Resolved" "ListBullet"

    # Section 3
    xP "Milestone Coverage" "Heading1"
    xP "All 11 scripted milestones are fully implemented. M2 (DC Upgrade) is intentionally not scripted -- it is a manual, change-controlled process. M1 produces a DC inventory with upgrade readiness flags used to gate M3-M12 remediation."
    xP ""
    xTable @("ID","Milestone","Status","Remediates","Risk Level") $milestonesAM

    # Section 4
    xP "Key Design Decisions" "Heading1"
    xP "M3 -- OU Structure Cleanup: Discover-Only" "Heading2"
    xP "M3 is deliberately Discover-only. OU path changes break existing GPO links and membership-by-location assumptions; any restructuring must be planned with the MetLife AD team and executed via formal change management. M3 produces a comprehensive audit report (7 checks including default container usage, block inheritance gaps, policy gap OUs, and non-standard OU delegation ACEs) that gives the AD team everything they need to plan changes manually."
    xP "M10 -- Delegated Permissions: Conservative Remediation Scope" "Heading2"
    xP "M10 offers automated per-ACE removal only for the DC OU (OU=Domain Controllers). Checks covering DCSync rights, AdminSDHolder backdoor ACEs, and domain root high-risk ACEs are Discover-only because those changes require deliberate review and a separate change request. This is intentional -- the blast radius of incorrect ACL changes at the domain root or AdminSDHolder level is a full domain compromise."
    xP "M7 -- DC Hardening: WinRM-Based Remote Checks" "Heading2"
    xP "All 12 DC hardening checks run remotely against each DC via WinRM (Invoke-Command). DCs where WinRM is unavailable receive a HIGH finding -- WinRM unavailability is itself a hardening gap. LSASS PPL and Credential Guard changes require a reboot; the agent tracks affected DCs and prints a consolidated banner after the remediation loop."
    xP "Hybrid Azure AD Awareness" "Heading2"
    xP "LastLogonDate on AD user objects reflects on-premises Kerberos logons only. Users authenticating exclusively via Entra ID will appear stale in M11. The config ships with HybridAAD = true, which triggers a warning before M11 Remediate mode runs, prompting the operator to cross-reference Entra ID sign-in logs before bulk-quarantining accounts."

    # Section 5
    xP "Client Presentation Talking Points" "Heading1"
    xP "Opening the Conversation" "Heading2"
    xP "The tool is ready to use today -- no additional installation, licensing, or infrastructure required" "ListBullet"
    xP "First recommended action: run Mode Discover to get a current-state security report against CIS Level 1" "ListBullet"
    xP "The report is suitable for management review -- it maps every finding to a CIS control and NIST SP 800-53 family" "ListBullet"
    xP "Control and Safety" "Heading2"
    xP "Nothing changes in the environment without the operator explicitly typing Approve at the CLI" "ListBullet"
    xP "For HIGH and CRITICAL risk changes, the operator must type the target object name exactly before the approval prompt appears" "ListBullet"
    xP "No AD objects are ever deleted -- stale accounts are disabled and moved, not removed" "ListBullet"
    xP "All actions are logged with timestamps, object DNs, CIS/NIST references, and rollback steps" "ListBullet"
    xP "The DC Upgrade Story" "Heading2"
    xP "M1 Discover produces a DC inventory with upgrade readiness flags -- use this to plan the Server 2025 upgrade sequence" "ListBullet"
    xP "The upgrade gate prevents remediation running against a pre-upgrade environment -- reduces the risk of double-handling" "ListBullet"
    xP "After upgrade, run Mode Baseline to snapshot the post-upgrade state, then proceed through M3-M12 remediation" "ListBullet"
    xP "Anticipated Questions" "Heading2"
    xP "Can we schedule this to run automatically? -- Discover and Report modes can be scheduled via Task Scheduler. Remediate mode requires a human operator by design." "ListBullet"
    xP "Does it touch Azure AD? -- No. The tool works entirely against on-premises AD. M6 checks WHfB Kerberos hybrid trust objects in on-prem AD but does not write to Entra ID." "ListBullet"
    xP "What credentials does it use? -- The operator's current Windows session (Kerberos token). No credentials are stored or prompted for." "ListBullet"
    xP "Can we extend it? -- Yes. The extending guide in README.md covers adding new milestone modules in approximately 50-100 lines of PowerShell." "ListBullet"

    # Section 6
    xP "Follow-On Opportunities" "Heading1"
    xP "Immediate (Post-Discovery)" "Heading2"
    xP "Guided Remediation Engagement -- work through M4, M10, M7, M6, M12 in risk priority order with a Fusion5 consultant present" "ListBullet"
    xP "DC Upgrade Project -- use M1 findings to plan and execute the Server 2019 to Server 2025 swing migration" "ListBullet"
    xP "Ongoing" "Heading2"
    xP "Managed Monitoring -- weekly scheduled Discover runs with a Fusion5 consultant reviewing the drift report" "ListBullet"
    xP "Baseline Review Cadence -- quarterly Baseline resets following each remediation wave" "ListBullet"
    xP "Expansion Opportunities" "Heading2"
    xP "Entra ID Hardening -- extend M6's WHfB and hybrid trust checks into a dedicated cloud identity assessment" "ListBullet"
    xP "Fine-Grained Password Policy Review -- additional M11 capability flagged for future development" "ListBullet"
    xP "Privileged Access Workstation Audit -- additional M12 capability for PAW configuration review" "ListBullet"
    xP "Authentication Policy and Silo Design -- M6 currently flags the gap; a silo design engagement would complete the picture" "ListBullet"
    xP "Custom Module Development -- the agent's extension model supports adding organisation-specific checks with minimal effort" "ListBullet"
)

Save-Docx $amBriefPath (Build-DocumentXml $amBody)
Write-Host "  [OK] AM Brief saved: $amBriefPath" -ForegroundColor Green

# -----------------------------------------------------------------------
# DOCUMENT 2: CLIENT PROPOSAL
# -----------------------------------------------------------------------
Write-Host "  Building Client Proposal..." -ForegroundColor Gray

$reqsTraceability = @(
    [string[]]@("Upgrade Domain Controllers to Windows Server 2025",                                  "M1, M2",  "M1 produces a DC health and upgrade readiness report. M2 is the upgrade itself -- Fusion5 will lead the migration planning and execution."),
    [string[]]@("Active Directory structure cleanup and hygiene improvements",                         "M3",      "OU inventory, default container usage, empty OUs, block inheritance gaps, and non-standard OU delegation are assessed and reported."),
    [string[]]@("Review and remediate unconstrained delegation",                                       "M4",      "All computer and user accounts with unconstrained Kerberos delegation (excluding DCs) are identified and delegation can be removed with approval."),
    [string[]]@("Identify duplicate or incorrect Service Principal Names (SPNs)",                      "M5",      "Duplicate SPNs, Kerberoastable accounts, SPNs on disabled accounts, and Tier 0 accounts with SPNs are flagged and reported."),
    [string[]]@("Review Kerberos configuration including encryption types and authentication settings", "M6",      "RC4-only accounts, ticket policy, WHfB Kerberos hybrid trust, and authentication policy gaps are assessed. AES encryption types can be enforced with approval."),
    [string[]]@("Domain Controller hardening including auditing and security baseline review",          "M7",      "12 CIS Level 1 checks run remotely against each DC via WinRM: LDAP signing, SMB signing, NLA, Print Spooler, LSASS protection, Credential Guard, audit policy, and more."),
    [string[]]@("Group Policy cleanup -- redundant, unused or conflicting GPOs",                       "M8",      "Unlinked, empty, disabled, and orphaned GPOs are identified. GPOs are backed up before any disable or delete action is taken with approval."),
    [string[]]@("Identify and clean up unused or redundant security groups and OUs",                   "M3, M9",  "M3 audits empty and redundant OUs. M9 identifies empty groups, disabled account memberships, circular nesting, and AdminSDHolder remnants."),
    [string[]]@("Review delegated permissions and remove unnecessary elevated access",                  "M10",     "DCSync rights, domain root ACEs, AdminSDHolder ACEs, DC OU delegation, DnsAdmins membership, and DC object delegation are all assessed. DC OU ACE removal is available with approval."),
    [string[]]@("Identify and remove stale or inactive user, computer and service accounts",           "M11",     "Accounts inactive beyond a configurable threshold (default 90 days) are identified. Bulk quarantine (disable and move to Quarantine OU) is available with approval."),
    [string[]]@("Review and clean up privileged AD groups including Domain Admins",                    "M12",     "Domain Admins, Enterprise Admins, Schema Admins and six further privileged groups are reviewed. New members, stale accounts, service accounts, and nested groups are flagged. Members can be removed with per-member approval.")
)

$clientBody = @(
    # Cover
    xP "Active Directory Remediation and Cleanup" "Title"
    xP "Proposal for MetLife" "Subtitle"
    xP ""
    xMeta "Prepared for:  " "MetLife"
    xMeta "Prepared by:  "  "Fusion5"
    xMeta "Date:  "          "March 2026"
    xMeta "Classification:  " "COMMERCIAL IN CONFIDENCE"
    xP ""
    xBrk

    # Section 1
    xP "Background and Understanding" "Heading1"
    xP "Thank you for reaching out to Fusion5. We understand that a recent issue impacting mapped drives has highlighted the need to prioritise Active Directory remediation and cleanup activities within your on-premise AD environment. We appreciate the trust MetLife has placed in Fusion5 to respond to this need and are pleased to present this proposal."
    xP "Based on the scope you have outlined, we understand MetLife is looking for a partner to deliver a focused, practical AD remediation engagement covering configuration hygiene, security settings hardening, legacy configuration cleanup, and the upgrade of Domain Controllers to Windows Server 2025. This proposal sets out how Fusion5 proposes to address each of those requirements, the tooling we will bring to the engagement, and how we will ensure that all work is performed in a safe and controlled manner in your production environment."
    xP "Our proposed approach addresses all eleven areas identified in your scope request. The table in the Scope Coverage section below maps each of your requirements directly to the solution components we will deliver."

    # Section 2
    xP "Proposed Solution" "Heading1"
    xP "To deliver this engagement, Fusion5 proposes to develop and deploy the AD Remediation Agent -- a purpose-built PowerShell automation framework designed specifically around MetLife's stated requirements. The agent will run directly from any domain-joined Windows machine or Privileged Access Workstation and requires no additional software, licensing, or infrastructure beyond the standard Windows Remote Server Administration Tools (RSAT) that are already available in your environment."
    xP "The agent will operate in four modes, giving MetLife full control over discovery, remediation, and ongoing monitoring:"
    xP ""
    xTable @("Mode","Purpose","Changes to Active Directory") @(
        [string[]]@("Discover",  "Runs all assessment checks across every in-scope area and produces a findings report annotated with CIS Benchmark Level 1 control references. Safe to run at any time -- no changes are made.", "None"),
        [string[]]@("Baseline",  "Snapshots the current state of Active Directory as the approved reference point. All subsequent Discover or Remediate runs compare against this snapshot, highlighting what is new, persisting, or resolved.", "None"),
        [string[]]@("Remediate", "Runs all checks and presents each finding to the operator with full impact detail, rollback steps, and an explicit approve-or-skip prompt. No action is taken without the operator's deliberate approval.", "Yes -- with explicit operator approval only"),
        [string[]]@("Report",    "Generates a management-ready drift report from stored baseline data. No Active Directory connection required.", "None")
    )
    xP "Every run produces a structured HTML report and a CSV activity log. All findings are mapped to CIS Benchmark Level 1 controls (Windows Server 2022/2025) and NIST SP 800-53 control identifiers, making the output directly suitable for audit evidence packages and risk register updates."

    # Section 3
    xP "Scope Coverage" "Heading1"
    xP "The table below maps each requirement from your engagement brief to the corresponding milestone in our proposed solution. All eleven scripted milestones are fully automated for assessment. Remediation -- where applicable -- is available with explicit operator approval at each step."
    xP ""
    xTable @("Your Requirement","Milestone(s)","How We Will Address It") $reqsTraceability

    # Section 4
    xP "Engagement Approach" "Heading1"
    xP "We propose to structure the engagement in four sequential phases. Phases 1 and 2 can be run in parallel where the risk profile allows, and the DC upgrade (Phase 3) is sequenced to follow the initial remediation wave so that hardening work is not duplicated across OS versions."
    xP "Phase 1 -- Discovery and Assessment" "Heading2"
    xP "Run the agent in Discover mode across all milestones to establish a current-state findings report. Fusion5 will review the output with MetLife's AD team, prioritise findings by risk severity, and agree a remediation sequence. This phase makes no changes to Active Directory and can begin promptly upon engagement confirmation. Typical output includes a ranked findings list, a CIS compliance gap summary, and a recommended remediation roadmap."
    xP "Phase 2 -- Remediation" "Heading2"
    xP "Work through the agreed milestones in Remediate mode. Each finding is presented to the operator with the exact proposed action, impact if applied incorrectly, and step-by-step rollback instructions before any approval prompt is shown. We recommend prioritising in risk order: unconstrained delegation (M4), delegated permissions (M10), DC hardening (M7), privileged group review (M12), and Kerberos configuration (M6) before addressing hygiene items such as stale accounts, GPO cleanup, and security group cleanup."
    xP "Phase 3 -- Domain Controller Upgrade to Windows Server 2025" "Heading2"
    xP "Following the initial remediation wave, Fusion5 will lead the Domain Controller upgrade to Windows Server 2025. We recommend a swing migration approach to preserve DC IP addresses and avoid disruption to any applications with IP-bound dependencies on DC addresses. The M1 health and readiness report produced in Phase 1 will be used to sequence the upgrade and validate each DC post-migration. DFSR SYSVOL replication mode will be confirmed prior to commencing the upgrade."
    xP "Phase 4 -- Post-Upgrade Baseline and Ongoing Monitoring" "Heading2"
    xP "Once all DCs are confirmed on Windows Server 2025, the agent will snapshot the post-upgrade, post-remediation state as the approved baseline. Fusion5 recommends scheduling regular Discover runs to maintain ongoing visibility of AD configuration drift. This positions the tooling as a sustainable monitoring capability that MetLife can continue to operate after the initial engagement concludes."

    # Section 5
    xP "How We Will Keep Your Environment Safe" "Heading1"
    xP "We understand that this work will be performed in a production Active Directory environment. Our approach is designed from the ground up to be safe, reversible, and fully under MetLife's control at every step."
    xP "Explicit approval before every change" "Heading2"
    xP "No change will be made to Active Directory without the operator reviewing and approving it at the command line. For every remediable finding, the operator is shown the exact action proposed, the potential impact if applied incorrectly, and rollback steps before any prompt is presented. For HIGH and CRITICAL risk changes -- such as removing delegation rights or modifying DC-level ACLs -- the operator must type the name of the target object exactly before the approval prompt appears."
    xP "No accounts or objects will be deleted" "Heading2"
    xP "Stale user and computer accounts are quarantined -- disabled and moved to a dedicated Quarantine OU with a date-stamped description -- never deleted. Group Policy Objects are backed up and disabled before any deletion is offered, with a distinct second approval step required. AD objects can be recovered at any time from the Quarantine OU or from GPO backups."
    xP "Full audit trail of all actions" "Heading2"
    xP "Every run produces a structured CSV activity log and an HTML report recording the timestamp, finding, target object, operator decision, and outcome for every item processed. These logs are suitable for direct submission as audit evidence and are retained in a configurable output directory."
    xP "Baseline comparison and drift tracking" "Heading2"
    xP "After the post-upgrade baseline is set, all subsequent runs will clearly distinguish findings that are New, Persisting, or Resolved -- providing a clear record of remediation progress and any configuration drift that occurs after the initial cleanup."

    # Section 6
    xP "Why Fusion5" "Heading1"
    xP "Purpose-built for your environment" "Heading2"
    xP "Rather than adapting a generic scanning tool, Fusion5 will develop a framework built specifically around MetLife's stated requirements and environment -- including the Hybrid Azure AD Join configuration, Windows Hello for Business Kerberos hybrid trust objects, and IP-bound application dependencies on DC addresses. Every finding and every remediation step will be directly applicable to MetLife, not generic."
    xP "Practical remediation focus" "Heading2"
    xP "Our approach aligns with your stated intent: focused, practical remediation and cleanup. The engagement is not an audit that produces a report and walks away -- we will work alongside MetLife's AD team through each remediation step, with Fusion5 consultants present during any Remediate mode sessions."
    xP "Compliance-ready output" "Heading2"
    xP "Every finding maps to a CIS Benchmark Level 1 control and a NIST SP 800-53 identifier. The HTML reports are structured for direct use in audit evidence packages, reducing the overhead of translating technical remediation work into governance documentation."
    xP "Knowledge transfer and ongoing capability" "Heading2"
    xP "The AD Remediation Agent and all tooling will be handed over to MetLife at the conclusion of the engagement. Your AD team will be able to continue running Discover and Report modes independently on an ongoing basis, with Fusion5 available for support, follow-on remediation sessions, or additional module development as your requirements evolve."

    # Section 7
    xP "Proposed Next Steps" "Heading1"
    xP "We would welcome a short discovery call as you suggested to confirm scope and timelines before preparing a full Statement of Work. In the meantime, the following steps are proposed:"
    xP "Schedule a brief scoping call between Fusion5 and MetLife's AD team to walk through requirements and confirm any environment-specific considerations" "ListNumber"
    xP "Fusion5 to prepare and issue a Statement of Work based on confirmed scope" "ListNumber"
    xP "MetLife to confirm access arrangements -- a domain-joined machine and a read-privileged account are sufficient to begin Phase 1 in Discover mode with no changes to AD" "ListNumber"
    xP "Agree a start date and milestone sequencing that fits MetLife's DC upgrade timeline" "ListNumber"
    xP "Commence Phase 1 -- Discovery and Assessment" "ListNumber"
    xP ""
    xP "We look forward to discussing this further. Please do not hesitate to reach out to arrange the scoping call or if you have any questions about this proposal."
)

Save-Docx $clientPath (Build-DocumentXml $clientBody)
Write-Host "  [OK] Client Proposal saved: $clientPath" -ForegroundColor Green

Write-Host ""
Write-Host "  Done. Documents written to Docs\" -ForegroundColor Cyan
Write-Host "    $(Split-Path $amBriefPath -Leaf)" -ForegroundColor White
Write-Host "    $(Split-Path $clientPath  -Leaf)" -ForegroundColor White
Write-Host ""
