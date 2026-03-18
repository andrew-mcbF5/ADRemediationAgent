<#
.SYNOPSIS
    Save-Baseline  -- Serialise the current $Global:FindingsList state as an approved baseline.
    Compare-Baseline -- Diff current findings against the latest stored baseline.
    Invoke-DriftReport -- Called in Report mode; loads baselines and generates full drift analysis.
#>

function Save-Baseline {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $RunId,
        [Parameter(Mandatory)] [string] $OutputPath
    )

    $baselineDir  = "$OutputPath\Baselines"
    New-Item -ItemType Directory $baselineDir -Force | Out-Null

    $baselineFile = "$baselineDir\baseline-latest.json"
    $archiveFile  = "$baselineDir\baseline-$RunId.json"

    $snapshot = @{
        RunId       = $RunId
        Timestamp   = (Get-Date -Format "o")
        Domain      = $Global:AgentDomain
        Findings    = $Global:FindingsList
    }

    $json = $snapshot | ConvertTo-Json -Depth 10
    $json | Out-File -FilePath $baselineFile  -Encoding UTF8 -Force
    $json | Out-File -FilePath $archiveFile   -Encoding UTF8 -Force

    Write-AgentLog -Level BASELINE -Message "Baseline saved: $baselineFile (archive: $archiveFile)"
}


function Compare-Baseline {
    <#
    .SYNOPSIS
        Compares current $Global:FindingsList against the stored baseline.
        Returns a diff object: New findings, Resolved findings, Persisting findings.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OutputPath
    )

    $baselineFile = "$OutputPath\Baselines\baseline-latest.json"

    if (-not (Test-Path $baselineFile)) {
        Write-AgentLog -Level WARN -Message "No baseline found at $baselineFile -- delta comparison skipped. Run with -Mode Baseline first."
        return $null
    }

    $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json

    # Key findings by ObjectDN + FindingType for stable comparison
    $baseKeys    = @{}
    $baseline.Findings | ForEach-Object {
        $k = "$($_.ObjectDN)|$($_.FindingType)"
        $baseKeys[$k] = $_
    }

    $currentKeys = @{}
    $Global:FindingsList | ForEach-Object {
        $k = "$($_.ObjectDN)|$($_.FindingType)"
        $currentKeys[$k] = $_
    }

    $newFindings        = $currentKeys.Keys | Where-Object { -not $baseKeys.ContainsKey($_) } |
                          ForEach-Object { $currentKeys[$_] }
    $resolvedFindings   = $baseKeys.Keys    | Where-Object { -not $currentKeys.ContainsKey($_) } |
                          ForEach-Object { $baseKeys[$_] }
    $persistingFindings = $currentKeys.Keys | Where-Object { $baseKeys.ContainsKey($_) } |
                          ForEach-Object { $currentKeys[$_] }

    return [PSCustomObject]@{
        BaselineRunId    = $baseline.RunId
        BaselineDate     = $baseline.Timestamp
        NewFindings      = @($newFindings)
        ResolvedFindings = @($resolvedFindings)
        Persisting       = @($persistingFindings)
    }
}


function Invoke-DriftReport {
    <#
    .SYNOPSIS
        Report-only mode: loads the last N run logs and baseline, produces drift analysis.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string] $OutputPath,
        [Parameter(Mandatory)] [string] $Domain
    )

    $baselineFile = "$OutputPath\Baselines\baseline-latest.json"
    $logsDir      = "$OutputPath\Logs"
    $reportsDir   = "$OutputPath\Reports"
    $ts           = Get-Date -Format "yyyyMMdd-HHmmss"

    if (-not (Test-Path $baselineFile)) {
        Write-Host "  [WARN] No baseline found. Run -Mode Baseline first to establish a clean baseline." -ForegroundColor Yellow
        return [PSCustomObject]@{ Path = $null }
    }

    $baseline     = Get-Content $baselineFile -Raw | ConvertFrom-Json
    $allRunLogs   = Get-ChildItem "$logsDir\*.log" -ErrorAction SilentlyContinue |
                    Sort-Object LastWriteTime -Descending | Select-Object -First 10

    # Parse action log entries across runs
    $allActions = foreach ($log in $allRunLogs) {
        Import-Csv $log.FullName -ErrorAction SilentlyContinue |
            Where-Object { $_.Level -in @("APPROVED","ACTION","DENIED","FINDING","ERROR") }
    }

    # Count metrics
    $totalApproved  = ($allActions | Where-Object Level -eq "APPROVED").Count
    $totalDenied    = ($allActions | Where-Object Level -eq "DENIED").Count
    $totalFindings  = ($allActions | Where-Object Level -eq "FINDING").Count
    $totalErrors    = ($allActions | Where-Object Level -eq "ERROR").Count

    # Build drift report as structured text (HTML)
    $reportFile = "$reportsDir\DriftReport-$ts.html"

    $baselineRows = ($baseline.Findings | ForEach-Object {
        "<tr><td>$($_.Milestone)</td><td>$($_.FindingType)</td><td>$($_.ObjectDN)</td><td>$($_.Severity)</td><td>$($_.Description)</td></tr>"
    }) -join "`n"

    $actionRows = ($allActions | Select-Object -First 200 | ForEach-Object {
        $colour = switch ($_.Level) {
            "APPROVED" { "#2ecc71" }
            "DENIED"   { "#f39c12" }
            "FINDING"  { "#e74c3c" }
            "ERROR"    { "#c0392b" }
            default    { "#bdc3c7" }
        }
        "<tr><td>$($_.Timestamp)</td><td style='color:$colour'>$($_.Level)</td><td>$($_.Milestone)</td><td>$($_.Message)</td></tr>"
    }) -join "`n"

    $html = @"
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>AD Remediation Agent - Drift Report</title>
<style>
  body { font-family: Consolas, monospace; background:#1a1a2e; color:#e0e0e0; margin:0; padding:20px; }
  h1   { color:#00d4ff; border-bottom:2px solid #00d4ff; padding-bottom:10px; }
  h2   { color:#7f8c8d; font-size:0.9em; font-weight:normal; margin-top:-10px; }
  h3   { color:#00d4ff; margin-top:30px; }
  .card { background:#16213e; border:1px solid #0f3460; border-radius:6px; padding:20px; margin:15px 0; }
  .metric { display:inline-block; background:#0f3460; border-radius:4px; padding:10px 20px; margin:5px; text-align:center; }
  .metric .val { font-size:2em; color:#00d4ff; display:block; }
  .metric .lbl { font-size:0.8em; color:#7f8c8d; }
  table { width:100%; border-collapse:collapse; margin-top:10px; }
  th { background:#0f3460; color:#00d4ff; text-align:left; padding:8px; }
  td { padding:6px 8px; border-bottom:1px solid #0f3460; font-size:0.85em; }
  tr:hover td { background:#0f3460; }
  .badge-baseline { color:#9b59b6; }
  footer { margin-top:40px; color:#4a4a6a; font-size:0.8em; }
</style>
</head>
<body>
<h1>AD Remediation Agent -- Drift Report</h1>
<h2>Domain: $Domain &nbsp;|&nbsp; Generated: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss") &nbsp;|&nbsp; Baseline Run: $($baseline.RunId)</h2>

<div class="card">
  <h3>Run Metrics (last 10 runs)</h3>
  <div class="metric"><span class="val">$totalFindings</span><span class="lbl">Findings</span></div>
  <div class="metric"><span class="val">$totalApproved</span><span class="lbl">Approved Changes</span></div>
  <div class="metric"><span class="val">$totalDenied</span><span class="lbl">Skipped/Denied</span></div>
  <div class="metric"><span class="val">$totalErrors</span><span class="lbl">Errors</span></div>
</div>

<div class="card">
  <h3>Baseline Snapshot -- $($baseline.RunId) <span class="badge-baseline">($(([datetime]$baseline.Timestamp).ToString("yyyy-MM-dd")))</span></h3>
  <p>Findings present at baseline. Items no longer appearing = resolved drift.</p>
  <table>
    <tr><th>Milestone</th><th>Finding Type</th><th>Object DN</th><th>Severity</th><th>Description</th></tr>
    $baselineRows
  </table>
</div>

<div class="card">
  <h3>Action Log (last 10 runs, max 200 entries)</h3>
  <table>
    <tr><th>Timestamp</th><th>Level</th><th>Milestone</th><th>Message</th></tr>
    $actionRows
  </table>
</div>

<footer>AD Remediation Agent v1.0 &mdash; Report generated by Invoke-DriftReport</footer>
</body>
</html>
"@

    $html | Out-File -FilePath $reportFile -Encoding UTF8 -Force
    Write-AgentLog -Level INFO -Message "Drift report written to $reportFile"

    return [PSCustomObject]@{ Path = $reportFile }
}
