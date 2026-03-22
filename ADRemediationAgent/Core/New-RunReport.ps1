<#
.SYNOPSIS
    New-RunReport -- Generates a per-run HTML summary report.
    Called at the end of every Discover / Remediate / Baseline run.

    v2.0 additions:
      - DC OS Progression card (from DCInventory finding Data)
      - CIS L1 Compliance card (counts CIS-tagged findings)
      - CISControl and NISTControl columns in All Findings table
      - NIST control cross-reference section
#>

function New-RunReport {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $RunId,
        [Parameter(Mandatory)] [string]   $Mode,
        [Parameter(Mandatory)] [string[]] $Milestones,
        [AllowEmptyCollection()] [PSObject[]] $Findings = @(),
        [AllowEmptyCollection()] [PSObject[]] $Actions  = @(),
        [Parameter(Mandatory)] [string]   $OutputPath,
        [Parameter(Mandatory)] [string]   $Domain
    )

    $reportsDir = "$OutputPath\Reports"
    New-Item -ItemType Directory $reportsDir -Force | Out-Null

    $reportFile = "$reportsDir\RunReport-$RunId.html"
    $ts         = Get-Date -Format "yyyy-MM-dd HH:mm:ss"

    # Ensure arrays under StrictMode
    $Findings = @($Findings)
    $Actions  = @($Actions)

    # =========================================================================
    # Helper: HTML-encode a string (avoid XSS in object DNs / descriptions)
    # =========================================================================
    function HtmlEncode {
        param([string]$s)
        if (-not $s) { return "" }
        $s = $s.Replace("&","&amp;").Replace("<","&lt;").Replace(">","&gt;").Replace('"',"&quot;")
        return $s
    }

    # =========================================================================
    # DC OS Progression Card
    # =========================================================================
    $dcProgressionHtml = ""
    $dcInvFinding = @($Findings | Where-Object { $_.FindingType -eq "DCInventory" })

    if ($dcInvFinding.Count -gt 0 -and $dcInvFinding[0].Data) {
        $dcList = @($dcInvFinding[0].Data)

        $dcRows = ($dcList | ForEach-Object {
            $flagColour = ""
            $flagText   = ""
            if ($_.UpgradeFlag -eq "COMPLETE") {
                $flagColour = "#2ecc71"
                $flagText   = "COMPLETE"
            } elseif ($_.UpgradeFlag -eq "URGENT") {
                $flagColour = "#e74c3c"
                $flagText   = "URGENT"
            } else {
                $flagColour = "#f39c12"
                $flagText   = "PENDING"
            }

            $dcName  = HtmlEncode $_.Name
            $dcHost  = HtmlEncode $_.HostName
            $dcIP    = HtmlEncode $_.IPv4
            $dcOS    = HtmlEncode $_.OS
            $dcSite  = HtmlEncode $_.Site
            $dcGC    = if ($_.IsGC)   { "Yes" } else { "No" }
            $dcRODC  = if ($_.IsRODC) { "Yes" } else { "No" }
            $dcFSMO  = HtmlEncode $_.FSMORoles

            "<tr><td>$dcName</td><td>$dcIP</td><td>$dcOS</td><td>$dcSite</td><td>$dcGC</td><td>$dcRODC</td><td>$dcFSMO</td><td style='color:$flagColour;font-weight:bold'>$flagText</td></tr>"
        }) -join "`n"

        $totalDCs    = $dcList.Count
        $completeDCs = @($dcList | Where-Object { $_.UpgradeFlag -eq "COMPLETE" }).Count
        $pendingDCs  = @($dcList | Where-Object { $_.UpgradeFlag -eq "PENDING"  }).Count
        $urgentDCs   = @($dcList | Where-Object { $_.UpgradeFlag -eq "URGENT"   }).Count

        $dcProgressionHtml = @"
<div class="card">
  <h3>DC OS Progression ($totalDCs controller(s))</h3>
  <div class="metric"><span class="val" style="color:#2ecc71">$completeDCs</span><span class="lbl">On 2025</span></div>
  <div class="metric"><span class="val" style="color:#f39c12">$pendingDCs</span><span class="lbl">Pending</span></div>
  <div class="metric"><span class="val" style="color:#e74c3c">$urgentDCs</span><span class="lbl">Urgent</span></div>
  <br style="clear:both"><br>
  <table>
    <tr><th>DC Name</th><th>IPv4</th><th>OS</th><th>Site</th><th>GC</th><th>RODC</th><th>FSMO Roles</th><th>Upgrade Flag</th></tr>
    $dcRows
  </table>
</div>
"@
    }

    # =========================================================================
    # CIS L1 Compliance Card -- per-control pass/fail breakdown
    # =========================================================================
    # Build a map of unique CIS control IDs to their worst severity and
    # whether they are compliant (INFO/LOW only) or non-compliant (MEDIUM+).
    # A finding may list multiple comma-separated controls; each is split out.
    $cisControls = @{}
    $sevRank = @{ "INFO"=1; "LOW"=2; "MEDIUM"=3; "HIGH"=4; "CRITICAL"=5 }

    foreach ($f in $Findings) {
        if (-not $f.CISControl -or $f.CISControl -eq "") { continue }
        $ctrlIds = $f.CISControl -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
        foreach ($ctrl in $ctrlIds) {
            if (-not $cisControls.ContainsKey($ctrl)) {
                $cisControls[$ctrl] = [PSCustomObject]@{ Compliant = $true; MaxSev = "INFO"; FindingCount = 0 }
            }
            $cisControls[$ctrl].FindingCount++
            if ($f.Severity -in @("CRITICAL","HIGH","MEDIUM")) {
                $cisControls[$ctrl].Compliant = $false
            }
            $curRank = if ($sevRank.ContainsKey($cisControls[$ctrl].MaxSev)) { $sevRank[$cisControls[$ctrl].MaxSev] } else { 1 }
            $newRank = if ($sevRank.ContainsKey($f.Severity))                { $sevRank[$f.Severity]                } else { 1 }
            if ($newRank -gt $curRank) { $cisControls[$ctrl].MaxSev = $f.Severity }
        }
    }

    $totalControls      = $cisControls.Count
    $compliantControls  = @($cisControls.Keys | Where-Object {  $cisControls[$_].Compliant }).Count
    $nonCompliantCtrls  = @($cisControls.Keys | Where-Object { -not $cisControls[$_].Compliant }).Count
    $pct = if ($totalControls -gt 0) { [int](($compliantControls / $totalControls) * 100) } else { 0 }
    $barColour = if ($pct -ge 80) { "#2ecc71" } elseif ($pct -ge 50) { "#f39c12" } else { "#e74c3c" }

    $cisCtrlRows = ($cisControls.Keys | Sort-Object | ForEach-Object {
        $item   = $cisControls[$_]
        $status = if ($item.Compliant) { "<span style='color:#2ecc71;font-weight:bold'>PASS</span>" } `
                  else                 { "<span style='color:#e74c3c;font-weight:bold'>FAIL</span>" }
        $sevCol = switch ($item.MaxSev) {
            "CRITICAL" { "#e74c3c" } "HIGH" { "#e67e22" } "MEDIUM" { "#f39c12" }
            "LOW"      { "#2ecc71" } default { "#3498db" }
        }
        "<tr><td>$(HtmlEncode $_)</td><td style='color:$sevCol;font-weight:bold'>$($item.MaxSev)</td><td>$($item.FindingCount)</td><td>$status</td></tr>"
    }) -join "`n"

    $cisNoDataMsg = if ($totalControls -eq 0) { "<p style='color:#7f8c8d'>No CIS-tagged findings in this run.</p>" } else { "" }

    $cisComplianceHtml = @"
<div class="card">
  <h3>CIS L1 Compliance Summary</h3>
  <div class="metric"><span class="val" style="color:#2ecc71">$compliantControls</span><span class="lbl">Compliant</span></div>
  <div class="metric"><span class="val" style="color:#e74c3c">$nonCompliantCtrls</span><span class="lbl">Non-Compliant</span></div>
  <div class="metric"><span class="val" style="color:#3498db">$totalControls</span><span class="lbl">Controls Assessed</span></div>
  <br style="clear:both"><br>
  <div style="background:#0f3460;border-radius:4px;height:22px;width:100%;margin:10px 0;position:relative">
    <div style="background:$barColour;border-radius:4px;height:22px;width:$pct%;min-width:2%;line-height:22px;text-align:center;font-size:0.75em;font-weight:bold;color:#fff">$pct% compliant</div>
  </div>
  $cisNoDataMsg
  <table>
    <tr><th>CIS Control</th><th>Worst Severity</th><th>Findings</th><th>Status</th></tr>
    $cisCtrlRows
  </table>
</div>
"@

    # =========================================================================
    # NIST Control Cross-Reference
    # =========================================================================
    $nistMap = @{}
    foreach ($f in $Findings) {
        if ($f.NISTControl -and $f.NISTControl -ne "") {
            # A finding may list multiple controls separated by comma
            $controls = $f.NISTControl -split "," | ForEach-Object { $_.Trim() } | Where-Object { $_ -ne "" }
            foreach ($ctrl in $controls) {
                if (-not $nistMap.ContainsKey($ctrl)) {
                    $nistMap[$ctrl] = [System.Collections.Generic.List[string]]::new()
                }
                $nistMap[$ctrl].Add("[$($f.Severity)] $($f.FindingType) ($($f.ObjectDN))")
            }
        }
    }

    $nistRows = ""
    foreach ($ctrl in ($nistMap.Keys | Sort-Object)) {
        $findingList = ($nistMap[$ctrl] | Select-Object -Unique) -join "<br>"
        $nistRows += "<tr><td style='font-weight:bold;color:#00d4ff'>$(HtmlEncode $ctrl)</td><td>$findingList</td></tr>`n"
    }

    $nistSectionHtml = ""
    if ($nistRows -ne "") {
        $nistSectionHtml = @"
<div class="card">
  <h3>NIST SP 800-53 Control Cross-Reference</h3>
  <table>
    <tr><th>Control</th><th>Related Findings</th></tr>
    $nistRows
  </table>
</div>
"@
    }

    # =========================================================================
    # Delta vs Baseline Section
    # =========================================================================
    $deltaSection = ""
    $baselineFile = "$OutputPath\Baselines\baseline-latest.json"

    if ((Test-Path $baselineFile) -and $Findings.Count -gt 0) {
        $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json
        $baseKeys = @{}
        if ($baseline.Findings) {
            $baseline.Findings | ForEach-Object {
                $k = "$($_.ObjectDN)|$($_.FindingType)"
                $baseKeys[$k] = $_
            }
        }

        $newF  = @($Findings | Where-Object { -not $baseKeys.ContainsKey("$($_.ObjectDN)|$($_.FindingType)") })
        $persF = @($Findings | Where-Object {      $baseKeys.ContainsKey("$($_.ObjectDN)|$($_.FindingType)") })

        $newRows  = ($newF | ForEach-Object {
            $cis  = HtmlEncode $_.CISControl
            $nist = HtmlEncode $_.NISTControl
            "<tr class='new'><td>$(HtmlEncode $_.Milestone)</td><td>$(HtmlEncode $_.FindingType)</td><td>$(HtmlEncode $_.ObjectDN)</td><td>$(HtmlEncode $_.Severity)</td><td>$(HtmlEncode $_.Description)</td><td>$cis</td><td>$nist</td></tr>"
        }) -join "`n"

        $persRows = ($persF | ForEach-Object {
            $cis  = HtmlEncode $_.CISControl
            $nist = HtmlEncode $_.NISTControl
            "<tr><td>$(HtmlEncode $_.Milestone)</td><td>$(HtmlEncode $_.FindingType)</td><td>$(HtmlEncode $_.ObjectDN)</td><td>$(HtmlEncode $_.Severity)</td><td>$(HtmlEncode $_.Description)</td><td>$cis</td><td>$nist</td></tr>"
        }) -join "`n"

        $baseRunId = if ($baseline.RunId) { $baseline.RunId } else { "unknown" }

        $deltaSection = @"
<div class="card">
  <h3>Delta vs Baseline ($baseRunId)</h3>
  <p><span class="badge new">NEW</span> $($newF.Count) findings not present at baseline &nbsp;|&nbsp; <span class="badge persist">PERSISTING</span> $($persF.Count) findings unchanged since baseline</p>
  <h4>New Since Baseline</h4>
  <table><tr><th>Milestone</th><th>Type</th><th>Object DN</th><th>Severity</th><th>Description</th><th>CIS Control</th><th>NIST Control</th></tr>
  $newRows
  </table>
  <h4>Persisting From Baseline</h4>
  <table><tr><th>Milestone</th><th>Type</th><th>Object DN</th><th>Severity</th><th>Description</th><th>CIS Control</th><th>NIST Control</th></tr>
  $persRows
  </table>
</div>
"@
    }

    # =========================================================================
    # All Findings Table (with CIS and NIST columns)
    # =========================================================================
    $findingRows = ($Findings | ForEach-Object {
        $sevColour = switch ($_.Severity) {
            "CRITICAL" { "#e74c3c" }
            "HIGH"     { "#e67e22" }
            "MEDIUM"   { "#f39c12" }
            "LOW"      { "#2ecc71" }
            "INFO"     { "#3498db" }
            default    { "#bdc3c7" }
        }
        $cis  = HtmlEncode $_.CISControl
        $nist = HtmlEncode $_.NISTControl
        "<tr><td>$(HtmlEncode $_.Milestone)</td><td>$(HtmlEncode $_.FindingType)</td><td>$(HtmlEncode $_.ObjectDN)</td><td style='color:$sevColour;font-weight:bold'>$(HtmlEncode $_.Severity)</td><td>$(HtmlEncode $_.Description)</td><td>$cis</td><td>$nist</td></tr>"
    }) -join "`n"

    # =========================================================================
    # Actions Table
    # =========================================================================
    $actionRows = ($Actions | ForEach-Object {
        $statusColour = if ($_.Status -eq "SUCCESS") { "#2ecc71" } else { "#e74c3c" }
        "<tr><td>$(HtmlEncode $_.Timestamp)</td><td>$(HtmlEncode $_.Milestone)</td><td>$(HtmlEncode $_.Action)</td><td>$(HtmlEncode $_.Target)</td><td style='color:$statusColour'>$(HtmlEncode $_.Status)</td><td>$(HtmlEncode $_.Detail)</td></tr>"
    }) -join "`n"

    # =========================================================================
    # Summary metric counts
    # =========================================================================
    $critCount   = @($Findings | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $highCount   = @($Findings | Where-Object { $_.Severity -eq "HIGH"     }).Count
    $medCount    = @($Findings | Where-Object { $_.Severity -eq "MEDIUM"   }).Count
    $lowCount    = @($Findings | Where-Object { $_.Severity -eq "LOW"      }).Count
    $actApproved = @($Actions  | Where-Object { $_.Status   -eq "SUCCESS"  }).Count
    $actFailed   = @($Actions  | Where-Object { $_.Status   -eq "FAILED"   }).Count

    $modeColour = switch ($Mode) {
        "Discover"  { "#f39c12" }
        "Remediate" { "#e74c3c" }
        "Baseline"  { "#9b59b6" }
        default     { "#3498db" }
    }

    # =========================================================================
    # Render HTML
    # =========================================================================
    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Agent Run Report -- $RunId</title>
<style>
  body  { font-family: Consolas, monospace; background:#1a1a2e; color:#e0e0e0; margin:0; padding:20px; }
  h1    { color:#00d4ff; border-bottom:2px solid #00d4ff; padding-bottom:10px; }
  h2    { color:#7f8c8d; font-size:0.9em; font-weight:normal; margin-top:-10px; }
  h3    { color:#00d4ff; margin-top:30px; }
  h4    { color:#7f8c8d; margin:15px 0 5px 0; }
  .card { background:#16213e; border:1px solid #0f3460; border-radius:6px; padding:20px; margin:15px 0; }
  .metric { display:inline-block; background:#0f3460; border-radius:4px; padding:10px 20px; margin:5px; text-align:center; min-width:80px; }
  .metric .val { font-size:2em; display:block; }
  .metric .lbl { font-size:0.75em; color:#7f8c8d; }
  .mode-badge { display:inline-block; padding:4px 12px; border-radius:4px; font-weight:bold; font-size:0.85em; background:$modeColour; color:white; }
  table { width:100%; border-collapse:collapse; margin-top:10px; }
  th    { background:#0f3460; color:#00d4ff; text-align:left; padding:8px; font-size:0.85em; }
  td    { padding:6px 8px; border-bottom:1px solid #0f3460; font-size:0.82em; word-break:break-all; }
  tr:hover td { background:#0f3460; }
  tr.new td   { border-left: 3px solid #e74c3c; }
  .badge      { display:inline-block; border-radius:3px; padding:2px 6px; font-size:0.8em; font-weight:bold; }
  .badge.new  { background:#e74c3c; color:white; }
  .badge.persist { background:#7f8c8d; color:white; }
  footer { margin-top:40px; color:#4a4a6a; font-size:0.8em; }
</style>
</head>
<body>

<h1>AD Remediation Agent -- Run Report</h1>
<h2>Run: $RunId &nbsp;|&nbsp; Domain: $Domain &nbsp;|&nbsp; Generated: $ts</h2>
<p>Mode: <span class="mode-badge">$Mode</span> &nbsp; Milestones: $($Milestones -join ', ')</p>

<div class="card">
  <h3>Summary</h3>
  <div class="metric"><span class="val" style="color:#e74c3c">$critCount</span><span class="lbl">CRITICAL</span></div>
  <div class="metric"><span class="val" style="color:#e67e22">$highCount</span><span class="lbl">HIGH</span></div>
  <div class="metric"><span class="val" style="color:#f39c12">$medCount</span><span class="lbl">MEDIUM</span></div>
  <div class="metric"><span class="val" style="color:#2ecc71">$lowCount</span><span class="lbl">LOW</span></div>
  <div class="metric"><span class="val" style="color:#2ecc71">$actApproved</span><span class="lbl">Changes Applied</span></div>
  <div class="metric"><span class="val" style="color:#e74c3c">$actFailed</span><span class="lbl">Failed Actions</span></div>
</div>

$dcProgressionHtml

$cisComplianceHtml

$deltaSection

<div class="card">
  <h3>All Findings ($($Findings.Count))</h3>
  <table>
    <tr><th>Milestone</th><th>Finding Type</th><th>Object DN</th><th>Severity</th><th>Description</th><th>CIS Control</th><th>NIST Control</th></tr>
    $findingRows
  </table>
</div>

$nistSectionHtml

<div class="card">
  <h3>Actions Taken ($($Actions.Count))</h3>
  <table>
    <tr><th>Timestamp</th><th>Milestone</th><th>Action</th><th>Target</th><th>Status</th><th>Detail</th></tr>
    $actionRows
  </table>
</div>

<footer>AD Remediation Agent v2.0 -- Run log: $($Global:AgentLogPath)</footer>
</body>
</html>
"@

    $html | Out-File -FilePath $reportFile -Encoding UTF8 -Force
    return $reportFile
}
