#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    AD Remediation Agent - On-Prem / Hybrid AAD Entry Point

.DESCRIPTION
    Orchestrates discovery, baselining, human-approved remediation, and drift
    reporting across targeted Active Directory milestones.

    Milestones in v1:
        M1  - DC Health & Baseline
        M4  - Unconstrained Delegation
        M11 - Stale / Inactive Accounts
        M12 - Privileged Group Review

.PARAMETER Mode
    Discover   - Run all checks, produce findings, no changes made.
    Remediate  - Run checks, prompt for human approval on each finding before acting.
    Report     - Generate drift/delta report from stored baselines only. No checks run.
    Baseline   - Snapshot current state as the approved baseline (run after a clean build).

.PARAMETER Milestones
    Comma-separated list of milestones to run. Default: all v1 milestones.
    Valid: M1, M4, M11, M12

.PARAMETER OutputPath
    Root path for reports, logs, and baselines. Default: .\ADAgent-Output

.PARAMETER Domain
    FQDN of domain to target. Defaults to current computer's domain.

.EXAMPLE
    .\Start-ADRemediationAgent.ps1 -Mode Discover
    .\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M1,M11
    .\Start-ADRemediationAgent.ps1 -Mode Report
    .\Start-ADRemediationAgent.ps1 -Mode Baseline
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Discover","Remediate","Report","Baseline")]
    [string]$Mode,

    [ValidateSet("M1","M4","M11","M12")]
    [string[]]$Milestones = @("M1","M4","M11","M12"),

    [string]$OutputPath = ".\ADAgent-Output",

    [string]$Domain = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# ── Bootstrap ────────────────────────────────────────────────────────────────
$ScriptRoot   = $PSScriptRoot
$RunTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunId        = "RUN-$RunTimestamp"

# Resolve absolute output path
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
foreach ($sub in @("Logs","Reports","Baselines","Config")) {
    New-Item -ItemType Directory -Path "$OutputPath\$sub" -Force | Out-Null
}

# Import core engine
. "$ScriptRoot\Core\Write-AgentLog.ps1"
. "$ScriptRoot\Core\Invoke-HumanApproval.ps1"
. "$ScriptRoot\Core\Save-Baseline.ps1"
. "$ScriptRoot\Core\Compare-Baseline.ps1"
. "$ScriptRoot\Core\New-RunReport.ps1"

# Initialise run log
$Global:AgentLogPath  = "$OutputPath\Logs\$RunId.log"
$Global:AgentRunId    = $RunId
$Global:AgentMode     = $Mode
$Global:AgentDomain   = $Domain
$Global:OutputPath    = $OutputPath
$Global:RunTimestamp  = $RunTimestamp
$Global:FindingsList  = [System.Collections.Generic.List[PSObject]]::new()
$Global:ActionLog     = [System.Collections.Generic.List[PSObject]]::new()

# ── Banner ────────────────────────────────────────────────────────────────────
Clear-Host
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║        AD REMEDIATION AGENT  v1.0                       ║" -ForegroundColor Cyan
Write-Host "  ║        $RunId                          ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Domain   : $Domain" -ForegroundColor White
Write-Host "  Mode     : " -NoNewline -ForegroundColor White
switch ($Mode) {
    "Discover"  { Write-Host $Mode -ForegroundColor Yellow }
    "Remediate" { Write-Host $Mode -ForegroundColor Red }
    "Report"    { Write-Host $Mode -ForegroundColor Green }
    "Baseline"  { Write-Host $Mode -ForegroundColor Magenta }
}
Write-Host "  Milestones: $($Milestones -join ', ')" -ForegroundColor White
Write-Host "  Output   : $OutputPath" -ForegroundColor White
Write-Host ""

Write-AgentLog -Level INFO -Message "Agent started. Mode=$Mode Domain=$Domain Milestones=$($Milestones -join ',')"

# ── Preflight checks ──────────────────────────────────────────────────────────
Write-Host "  [ Preflight ]" -ForegroundColor DarkCyan
try {
    $null = Get-ADDomain -Identity $Domain
    Write-Host "  ✓ AD connectivity confirmed for $Domain" -ForegroundColor Green
    Write-AgentLog -Level INFO -Message "AD connectivity OK for $Domain"
} catch {
    Write-Host "  ✗ Cannot connect to AD domain '$Domain': $_" -ForegroundColor Red
    Write-AgentLog -Level ERROR -Message "AD connectivity failed: $_"
    exit 1
}

if ($Mode -eq "Report") {
    Write-Host ""
    Write-Host "  [ Report Mode - loading stored baselines ]" -ForegroundColor DarkCyan
    . "$ScriptRoot\Core\Compare-Baseline.ps1"
    $report = Invoke-DriftReport -OutputPath $OutputPath -Domain $Domain
    Write-Host ""
    Write-Host "  Report written to: $($report.Path)" -ForegroundColor Green
    Write-AgentLog -Level INFO -Message "Drift report generated: $($report.Path)"
    exit 0
}

# ── Load & Execute Milestone Modules ─────────────────────────────────────────
$milestoneMap = @{
    "M1"  = "$ScriptRoot\Modules\Invoke-M1-DCHealthBaseline.ps1"
    "M4"  = "$ScriptRoot\Modules\Invoke-M4-UnconstrainedDelegation.ps1"
    "M11" = "$ScriptRoot\Modules\Invoke-M11-StaleAccounts.ps1"
    "M12" = "$ScriptRoot\Modules\Invoke-M12-PrivilegedGroups.ps1"
}

$milestoneNames = @{
    "M1"  = "DC Health & Baseline"
    "M4"  = "Unconstrained Delegation"
    "M11" = "Stale / Inactive Accounts"
    "M12" = "Privileged Group Review"
}

foreach ($ms in $Milestones) {
    $modulePath = $milestoneMap[$ms]
    $msName     = $milestoneNames[$ms]

    Write-Host ""
    Write-Host "  ┌─────────────────────────────────────────────────────────┐" -ForegroundColor DarkGray
    Write-Host "  │  $ms : $msName" -ForegroundColor White
    Write-Host "  └─────────────────────────────────────────────────────────┘" -ForegroundColor DarkGray

    Write-AgentLog -Level INFO -Message "Starting milestone $ms - $msName"

    if (Test-Path $modulePath) {
        . $modulePath
        & "Invoke-$ms" -Mode $Mode -Domain $Domain -OutputPath $OutputPath
    } else {
        Write-Host "  [WARN] Module not found: $modulePath" -ForegroundColor Yellow
        Write-AgentLog -Level WARN -Message "Module missing for $ms at $modulePath"
    }
}

# ── Baseline snapshot (Baseline mode) ────────────────────────────────────────
if ($Mode -eq "Baseline") {
    Write-Host ""
    Write-Host "  [ Saving approved baseline snapshot ]" -ForegroundColor Magenta
    Save-Baseline -RunId $RunId -OutputPath $OutputPath
    Write-Host "  ✓ Baseline saved. Future Discover/Remediate runs will delta against this." -ForegroundColor Green
    Write-AgentLog -Level INFO -Message "Baseline snapshot saved for RunId $RunId"
}

# ── Run Summary ───────────────────────────────────────────────────────────────
Write-Host ""
Write-Host "  ╔══════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
Write-Host "  ║  RUN COMPLETE                                            ║" -ForegroundColor Cyan
Write-Host "  ╚══════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
Write-Host ""

$totalFindings = $Global:FindingsList.Count
$totalActions  = $Global:ActionLog.Count

Write-Host "  Findings logged : $totalFindings" -ForegroundColor Yellow
Write-Host "  Actions taken   : $totalActions" -ForegroundColor $(if($totalActions -gt 0){"Red"}else{"Green"})
Write-Host "  Log             : $Global:AgentLogPath" -ForegroundColor White

# Generate run report
$reportPath = New-RunReport -RunId $RunId -Mode $Mode -Milestones $Milestones `
              -Findings $Global:FindingsList -Actions $Global:ActionLog `
              -OutputPath $OutputPath -Domain $Domain

Write-Host "  Report          : $reportPath" -ForegroundColor White
Write-Host ""

Write-AgentLog -Level INFO -Message "Agent run complete. Findings=$totalFindings Actions=$totalActions Report=$reportPath"
