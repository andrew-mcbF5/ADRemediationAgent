#Requires -Version 5.1
<#
.SYNOPSIS
    Generates the AM Internal Brief and Client Summary Word documents.
    Output: Docs\ADRemediationAgent-AM-Brief.docx
            Docs\ADRemediationAgent-Client-Summary.docx

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
$clientPath  = Join-Path $docsDir "ADRemediationAgent-Client-Summary.docx"

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

$milestonesClient = @(
    [string[]]@("M1",  "Domain Controller Health",       "Replication status, FSMO roles, DNS health, SYSVOL mode, time sync, OS versions, krbtgt age, AS-REP roastable accounts",                        "Audit report only"),
    [string[]]@("M2",  "DC Upgrade to Server 2025",      "In-place upgrade readiness, DFSR migration status, IP-bound application risk assessment",                                                        "Manual -- change-controlled"),
    [string[]]@("M3",  "OU Structure",                   "Default container usage, empty OUs, block inheritance gaps, deep nesting, non-standard OU permissions",                                          "Audit report only"),
    [string[]]@("M4",  "Unconstrained Delegation",       "Computer and user accounts with unconstrained Kerberos delegation (excluding DCs) -- high-value attack path",                                    "Removes delegation with approval"),
    [string[]]@("M5",  "Service Principal Name Audit",   "Duplicate SPNs, Kerberoastable accounts, SPNs on disabled accounts, Tier 0 accounts with SPNs",                                                 "Sets AES encryption with approval"),
    [string[]]@("M6",  "Kerberos Configuration",         "RC4-only accounts, Kerberos ticket policy, WHfB Kerberos hybrid trust, authentication policy coverage",                                          "Sets AES encryption with approval"),
    [string[]]@("M7",  "DC Hardening (CIS Level 1)",     "LDAP signing, LDAP channel binding, SMB signing, NLA for RDP, Print Spooler, LSASS protection, WDigest, Credential Guard, audit policy",       "Registry/GPO changes with approval"),
    [string[]]@("M8",  "Group Policy Cleanup",           "Unlinked GPOs, empty GPOs, disabled GPOs, Default Domain Policy modifications, SYSVOL orphans, non-standard GPO permissions",                   "Backup-first; disable or delete with approval"),
    [string[]]@("M9",  "Security Group Hygiene",         "Empty groups, disabled accounts in groups, circular nesting, large universal groups, AdminSDHolder remnants, mail-enabled security groups",       "Removes disabled accounts; clears AdminCount with approval"),
    [string[]]@("M10", "Delegated Permissions",          "DCSync rights, domain root high-risk ACEs, AdminSDHolder backdoor ACEs, DC OU delegation, DnsAdmins membership, DC object delegation",           "DC OU ACE removal with approval; others audit-only"),
    [string[]]@("M11", "Stale Account Quarantine",       "User and computer accounts inactive beyond configurable threshold (default 90 days), with Hybrid Azure AD cross-reference guidance",              "Bulk approval; disables and moves to Quarantine OU"),
    [string[]]@("M12", "Privileged Group Review",        "Domain Admins, Enterprise Admins, Schema Admins and six further privileged groups -- new members, stale accounts, service accounts, nested groups","Removes members with approval (account not deleted)")
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
# DOCUMENT 2: CLIENT-READY SUMMARY
# -----------------------------------------------------------------------
Write-Host "  Building Client Summary..." -ForegroundColor Gray

$clientBody = @(
    # Cover
    xP "Active Directory Remediation and Hardening" "Title"
    xP "Delivery Summary" "Subtitle"
    xP ""
    xMeta "Prepared for:  " "MetLife"
    xMeta "Prepared by:  "  "Fusion5"
    xMeta "Date:  "          "March 2026"
    xP ""
    xBrk

    # Section 1
    xP "Executive Summary" "Heading1"
    xP "Fusion5 has delivered the AD Remediation Agent -- a purpose-built Active Directory security assessment and remediation tool developed specifically for MetLife's environment. The solution provides a structured, repeatable, and fully auditable approach to identifying and resolving Active Directory security risks across 12 defined areas, from Domain Controller health and baseline configuration through to privileged access governance and delegated permissions."
    xP "The tool is designed to operate safely in a production environment. Every remediation action requires explicit operator approval before it is executed, and a full audit trail is maintained for all findings, approvals, and actions taken. No Active Directory objects are ever deleted -- stale accounts are quarantined through a disable-and-move process, and all changes can be rolled back using documented steps provided at the time of approval."
    xP "The AD Remediation Agent maps every finding to the CIS Benchmark Level 1 controls for Windows Server 2022/2025 and to NIST SP 800-53 control identifiers. This means the output is directly suitable for inclusion in audit evidence packages and risk register updates, in addition to its operational use as a remediation guide."

    # Section 2
    xP "Engagement Objectives" "Heading1"
    xP "Assess MetLife's Active Directory security posture against the CIS Benchmark Level 1 standard for Windows Server 2022/2025" "ListBullet"
    xP "Identify and remediate security risks across 12 Active Directory domains, from DC health to privileged access" "ListBullet"
    xP "Support the planned Domain Controller upgrade from Windows Server 2019 to Windows Server 2025, including upgrade readiness assessment and post-upgrade hardening" "ListBullet"
    xP "Establish a repeatable, audit-ready AD security review process that MetLife can run on an ongoing basis" "ListBullet"
    xP "Generate compliance evidence aligned to NIST SP 800-53 for governance and audit reporting" "ListBullet"
    xP "Account for MetLife's Hybrid Azure AD Join environment and Windows Hello for Business Kerberos hybrid trust configuration" "ListBullet"

    # Section 3
    xP "Solution Overview" "Heading1"
    xP "The AD Remediation Agent is a PowerShell-based tool that runs from any domain-joined Windows machine or Privileged Access Workstation. It requires no additional software installation beyond standard Windows Remote Server Administration Tools (RSAT) and is compatible with PowerShell 5.1, which ships in-box on both Windows Server 2019 and 2025."
    xP "The agent operates in four modes, providing flexibility to run as an audit-only tool, a one-time remediation assistant, or a recurring monitoring solution:"
    xP ""
    xTable @("Mode","Purpose","Changes Made") @(
        [string[]]@("Discover",  "Runs all checks and produces a findings report with CIS and NIST annotations. Recommended for initial assessment and ongoing monitoring.", "None"),
        [string[]]@("Baseline",  "Snapshots the current state of Active Directory as the approved reference point. Future runs compare against this baseline.",               "None"),
        [string[]]@("Remediate", "Runs all checks, then presents each remediable finding to the operator with full impact detail and requires explicit approval before acting.", "Yes -- with approval only"),
        [string[]]@("Report",    "Generates a drift report comparing the current baseline against historical run data. Requires no Active Directory access.",                    "None")
    )
    xP "Each run produces an HTML report containing the full findings list with CIS and NIST control references, a delta comparison against the stored baseline (showing which issues are new, persisting, or resolved), and a complete action log of all changes made during the session."

    # Section 4
    xP "Milestone Coverage" "Heading1"
    xP "The tool covers 12 Active Directory security and hygiene milestones. Milestone 2 (DC Upgrade to Windows Server 2025) is a manual, change-controlled process supported by the readiness reporting from Milestone 1. All remaining milestones are fully automated for both discovery and, where appropriate, remediation."
    xP ""
    xTable @("Milestone","Area","What It Assesses","Automated Remediation") $milestonesClient

    # Section 5
    xP "Compliance Framework" "Heading1"
    xP "CIS Benchmark Level 1 -- Windows Server 2022 / 2025" "Heading2"
    xP "Every technical check in the tool is sourced from the CIS (Center for Internet Security) Benchmark Level 1 profile for Windows Server 2022 and 2025. CIS Level 1 represents the baseline security configuration recommended for all servers -- the controls are specific, directly auditable, and implementable without significant impact to business operations. Each finding in the output includes the CIS control reference number and level."
    xP "NIST SP 800-53" "Heading2"
    xP "In addition to CIS controls, every finding is tagged with the corresponding NIST Special Publication 800-53 control identifier. NIST SP 800-53 is the US federal standard for information security controls and is widely used as the basis for enterprise risk registers and third-party audit frameworks. The HTML report includes a NIST control cross-reference table that groups findings by control family (AC, CM, IA, SC, AU, SI), making it straightforward to map remediation activity to governance obligations."

    # Section 6
    xP "Key Security Principles" "Heading1"
    xP "Human Approval Before Every Change" "Heading2"
    xP "The tool will never modify Active Directory without explicit operator approval. For each remediable finding, the operator is shown the exact action that will be taken, the full impact (what will break if the change is wrong), and step-by-step rollback instructions before being asked to approve or skip. For HIGH and CRITICAL risk changes -- such as removing delegation rights or modifying DC configurations -- the operator must type the target object name exactly before the approval prompt is displayed."
    xP "No Objects Are Ever Deleted" "Heading2"
    xP "The agent follows a safe-by-default principle. Stale user and computer accounts are quarantined: disabled, moved to a dedicated Quarantine OU, and stamped with a description recording the date and reason. They are never deleted. Similarly, Group Policy Objects are disabled before deletion is offered, giving administrators a window to recover them if needed. Deletion of any object requires a second, distinct approval step."
    xP "Complete Audit Trail" "Heading2"
    xP "Every agent run produces a structured CSV log and an HTML report. Each entry records the timestamp, milestone, finding type, target object, severity, CIS and NIST control references, the operator's decision (approved, skipped, or quit), and the outcome of any change. This log is suitable for submission as audit evidence and can be retained for as long as required using the configurable log retention setting."
    xP "Baseline and Drift Tracking" "Heading2"
    xP "After establishing a known-good state -- typically after the DC upgrade is complete and an initial remediation wave has been run -- the agent can snapshot Active Directory into a baseline. All subsequent runs compare the current findings against this baseline, clearly identifying issues that are new (potential regression or new threat), persisting (known and accepted), or resolved (successfully remediated). This makes the tool suitable for use as an ongoing monitoring solution."

    # Section 7
    xP "Getting Started" "Heading1"
    xP "The agent is ready to run from the provided package. Launch PowerShell as a Domain Admin (or delegated read account for Discover mode) from a domain-joined machine and navigate to the ADRemediationAgent folder."
    xP "Initial Discovery (no changes)" "Heading2"
    xCode ".\Start-ADRemediationAgent.ps1 -Mode Discover"
    xP "Runs all milestone checks and produces an HTML report in .\ADAgent-Output\Reports\. Review this report before taking any remediation action."
    xP "Run Specific Milestones" "Heading2"
    xCode ".\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4,M12"
    xP "Targets specific milestones in Remediate mode. Findings are presented one by one with full impact detail; the operator approves or skips each item."
    xP "Set a Baseline" "Heading2"
    xCode ".\Start-ADRemediationAgent.ps1 -Mode Baseline"
    xP "Snapshots current AD findings as the approved reference. Run this after the DC upgrade is complete and the environment is in a known-good state."

    # Section 8
    xP "Recommended Next Steps" "Heading1"
    xP "Run Mode Discover -- establish a current-state findings report across all milestones. Review the HTML output with your AD team and Fusion5 consultant to understand the risk landscape." "ListNumber"
    xP "Review M1 (DC Health) findings -- confirm SYSVOL is using DFSR replication (required for Server 2025 upgrade), review the DC inventory, and identify any upgrade blockers." "ListNumber"
    xP "Plan and execute the DC upgrade to Windows Server 2025 (Milestone 2) -- use the swing migration approach documented in the tool's README to preserve DC IP addresses." "ListNumber"
    xP "Set a post-upgrade baseline -- once all DCs are on Server 2025, run Mode Baseline to record the approved reference state." "ListNumber"
    xP "Remediate high-risk milestones first -- begin with M4 (Unconstrained Delegation), M10 (Delegated Permissions), M7 (DC Hardening), and M12 (Privileged Group Review)." "ListNumber"
    xP "Complete remaining milestones -- address M6 (Kerberos), M5 (SPN Audit), M11 (Stale Accounts), M8 (GPO Cleanup), M9 (Security Groups), and M3 (OU Structure)." "ListNumber"
    xP "Establish ongoing monitoring -- schedule weekly Mode Discover runs and review the drift report to detect new risks and track remediation progress over time." "ListNumber"
)

Save-Docx $clientPath (Build-DocumentXml $clientBody)
Write-Host "  [OK] Client Summary saved: $clientPath" -ForegroundColor Green

Write-Host ""
Write-Host "  Done. Two documents written to Docs\" -ForegroundColor Cyan
Write-Host "    $(Split-Path $amBriefPath -Leaf)" -ForegroundColor White
Write-Host "    $(Split-Path $clientPath  -Leaf)" -ForegroundColor White
Write-Host ""
