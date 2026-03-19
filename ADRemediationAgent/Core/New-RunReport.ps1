<#
.SYNOPSIS
    New-RunReport -- Generates a per-run HTML summary report.
    Called at the end of every Discover / Remediate / Baseline run.
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

    # Ensure arrays - guard every collection against $null under StrictMode
    $Findings = @($Findings)
    $Actions  = @($Actions)

    # -- Compare to baseline if available ----------------------------------------
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

        $newRows  = ($newF  | ForEach-Object {
            "<tr class='new'><td>$($_.Milestone)</td><td>$($_.FindingType)</td><td>$($_.ObjectDN)</td><td>$($_.Severity)</td><td>$($_.Description)</td></tr>"
        }) -join "`n"

        $persRows = ($persF | ForEach-Object {
            "<tr><td>$($_.Milestone)</td><td>$($_.FindingType)</td><td>$($_.ObjectDN)</td><td>$($_.Severity)</td><td>$($_.Description)</td></tr>"
        }) -join "`n"

        $deltaSection = @"
<div class='card'>
  <h3>Delta vs Baseline ($($baseline.RunId))</h3>
  <p><span class='badge new'>NEW</span> $($newF.Count) findings not present at baseline &nbsp;|&nbsp; <span class='badge persist'>PERSISTING</span> $($persF.Count) findings unchanged since baseline</p>
  <h4>New Since Baseline</h4>
  <table><tr><th>Milestone</th><th>Type</th><th>Object DN</th><th>Severity</th><th>Description</th></tr>
  $newRows
  </table>
  <h4>Persisting From Baseline</h4>
  <table><tr><th>Milestone</th><th>Type</th><th>Object DN</th><th>Severity</th><th>Description</th></tr>
  $persRows
  </table>
</div>
"@
    }

    # -- Build findings table ----------------------------------------------------
    $findingRows = ($Findings | ForEach-Object {
        $sevColour = switch ($_.Severity) {
            "CRITICAL" { "#e74c3c" }
            "HIGH"     { "#e67e22" }
            "MEDIUM"   { "#f39c12" }
            "LOW"      { "#2ecc71" }
            "INFO"     { "#3498db" }
            default    { "#bdc3c7" }
        }
        "<tr><td>$($_.Milestone)</td><td>$($_.FindingType)</td><td>$($_.ObjectDN)</td><td style='color:$sevColour;font-weight:bold'>$($_.Severity)</td><td>$($_.Description)</td></tr>"
    }) -join "`n"

    # -- Build actions table -----------------------------------------------------
    $actionRows = ($Actions | ForEach-Object {
        $statusColour = if ($_.Status -eq "SUCCESS") { "#2ecc71" } else { "#e74c3c" }
        "<tr><td>$($_.Timestamp)</td><td>$($_.Milestone)</td><td>$($_.Action)</td><td>$($_.Target)</td><td style='color:$statusColour'>$($_.Status)</td><td>$($_.Detail)</td></tr>"
    }) -join "`n"

    # -- Severity and action counts (all wrapped in @() to prevent null .Count) --
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

$deltaSection

<div class="card">
  <h3>All Findings ($($Findings.Count))</h3>
  <table>
    <tr><th>Milestone</th><th>Finding Type</th><th>Object DN</th><th>Severity</th><th>Description</th></tr>
    $findingRows
  </table>
</div>

<div class="card">
  <h3>Actions Taken ($($Actions.Count))</h3>
  <table>
    <tr><th>Timestamp</th><th>Milestone</th><th>Action</th><th>Target</th><th>Status</th><th>Detail</th></tr>
    $actionRows
  </table>
</div>

<footer>AD Remediation Agent v1.0 -- Run log: $($Global:AgentLogPath)</footer>
</body>
</html>
"@

    $html | Out-File -FilePath $reportFile -Encoding UTF8 -Force
    return $reportFile
}
