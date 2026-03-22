#Requires -Version 5.1
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    AD Remediation Agent v2.0 - On-Prem / Hybrid AAD Entry Point

.DESCRIPTION
    Orchestrates discovery, baselining, human-approved remediation, and drift
    reporting across all 12 Active Directory remediation milestones.

    M2 (DC Upgrade) is a manual process -- no automation script.
    M1 produces a DC inventory with upgrade readiness flags used to gate M3-M12.

    Milestone List:
        M1  - DC Health and Baseline (includes DC inventory, AS-REP, Protected Users)
        M2  - DC Upgrade to 2025 [MANUAL -- see DC upgrade checklist in report]
        M3  - OU Structure Cleanup
        M4  - Unconstrained Delegation
        M5  - SPN Duplicate Detection
        M6  - Kerberos Configuration Review
        M7  - DC Hardening and CIS L1 Baseline
        M8  - GPO Cleanup
        M9  - Security Group Cleanup
        M10 - Delegated Permissions Review
        M11 - Stale / Inactive Accounts
        M12 - Privileged Group Review

.PARAMETER Mode
    Discover   - Run all checks, produce findings, no changes made.
    Remediate  - Run checks, prompt for human approval before each change.
    Report     - Generate drift/delta report from stored baselines only.
    Baseline   - Snapshot current state as the approved baseline.

.PARAMETER Milestones
    Milestones to run. Default: M1, M4, M11, M12 (implemented milestones).
    Valid: M1, M3, M4, M5, M6, M7, M8, M9, M10, M11, M12
    Note: M2 is excluded -- DC upgrade is a manual process.

.PARAMETER OutputPath
    Root path for reports, logs, baselines. Default: script directory\ADAgent-Output

.PARAMETER Domain
    FQDN of target domain. Defaults to current computer's domain.

.EXAMPLE
    .\Start-ADRemediationAgent.ps1 -Mode Discover
    .\Start-ADRemediationAgent.ps1 -Mode Discover -Milestones M1,M3,M7
    .\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4,M11,M12
    .\Start-ADRemediationAgent.ps1 -Mode Baseline
    .\Start-ADRemediationAgent.ps1 -Mode Report
#>

[CmdletBinding(SupportsShouldProcess)]
param(
    [Parameter(Mandatory)]
    [ValidateSet("Discover","Remediate","Report","Baseline")]
    [string]$Mode,

    [ValidateSet("M1","M3","M4","M5","M6","M7","M8","M9","M10","M11","M12")]
    [string[]]$Milestones = @("M1","M3","M4","M5","M6","M7","M8","M9","M10","M11","M12"),

    [string]$OutputPath = "",

    [string]$Domain = $env:USERDNSDOMAIN
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

# -- Bootstrap -----------------------------------------------------------------
$ScriptRoot   = $PSScriptRoot
$RunTimestamp = Get-Date -Format "yyyyMMdd-HHmmss"
$RunId        = "RUN-$RunTimestamp"

if (-not $OutputPath) {
    $OutputPath = Join-Path $ScriptRoot "ADAgent-Output"
}
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

# Load config
$configPath = "$ScriptRoot\Config\AgentConfig.psd1"
$config     = $null
if (Test-Path $configPath) {
    $config = & ([scriptblock]::Create((Get-Content $configPath -Raw)))
}

# Initialise run globals
$Global:AgentLogPath  = "$OutputPath\Logs\$RunId.log"
$Global:AgentRunId    = $RunId
$Global:AgentMode     = $Mode
$Global:AgentDomain   = $Domain
$Global:OutputPath    = $OutputPath
$Global:RunTimestamp  = $RunTimestamp
$Global:FindingsList  = [System.Collections.Generic.List[PSObject]]::new()
$Global:ActionLog     = [System.Collections.Generic.List[PSObject]]::new()

# -- Banner --------------------------------------------------------------------
Clear-Host
Write-Host ""
Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |        AD REMEDIATION AGENT  v2.2                        |" -ForegroundColor Cyan
Write-Host "  |        $RunId                        |" -ForegroundColor Cyan
Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""
Write-Host "  Domain    : $Domain" -ForegroundColor White
Write-Host "  Mode      : " -NoNewline -ForegroundColor White
switch ($Mode) {
    "Discover"  { Write-Host $Mode -ForegroundColor Yellow }
    "Remediate" { Write-Host $Mode -ForegroundColor Red }
    "Report"    { Write-Host $Mode -ForegroundColor Green }
    "Baseline"  { Write-Host $Mode -ForegroundColor Magenta }
}
Write-Host "  Milestones: $($Milestones -join ', ')" -ForegroundColor White
Write-Host "  Output    : $OutputPath" -ForegroundColor White
Write-Host ""
Write-Host "  Framework : CIS L1 + NIST SP 800-53" -ForegroundColor DarkCyan
Write-Host ""

Write-AgentLog -Level INFO -Message "Agent started. Mode=$Mode Domain=$Domain Milestones=$($Milestones -join ',')"

# -- Preflight checks ----------------------------------------------------------
Write-Host "  [ Preflight ]" -ForegroundColor DarkCyan
try {
    $null = Get-ADDomain -Identity $Domain
    Write-Host "  [OK] AD connectivity confirmed for $Domain" -ForegroundColor Green
    Write-AgentLog -Level INFO -Message "AD connectivity OK for $Domain"
} catch {
    Write-Host "  [FAIL] Cannot connect to AD domain '$Domain': $_" -ForegroundColor Red
    Write-AgentLog -Level ERROR -Message "AD connectivity failed: $_"
    exit 1
}

# -- Report mode ---------------------------------------------------------------
if ($Mode -eq "Report") {
    Write-Host ""
    Write-Host "  [ Report Mode - loading stored baselines ]" -ForegroundColor DarkCyan
    $report = Invoke-DriftReport -OutputPath $OutputPath -Domain $Domain
    Write-Host ""
    Write-Host "  Report written to: $($report.Path)" -ForegroundColor Green
    Write-AgentLog -Level INFO -Message "Drift report generated: $($report.Path)"
    exit 0
}

# -- DC Upgrade Gate -----------------------------------------------------------
# M3-M12 are post-upgrade milestones. If DCUpgradeGateEnabled=$true and any DC
# is not yet on TargetDCOS, warn (Discover) or block (Remediate).
$gateEnabled     = $false
$targetOS        = "2025"
$postUpgradeMils = @("M3","M5","M6","M7","M8","M9","M10","M11","M12")

if ($config) {
    if ($config.DCUpgradeGateEnabled) { $gateEnabled = $true }
    if ($config.TargetDCOS)           { $targetOS    = $config.TargetDCOS }
}

$postUpgradeMilsRequested = @($Milestones | Where-Object { $postUpgradeMils -contains $_ })

if ($gateEnabled -and $postUpgradeMilsRequested.Count -gt 0) {
    try {
        $nonUpgradedDCs = @(Get-ADDomainController -Filter * -Server $Domain |
            Where-Object { $_.OperatingSystem -notmatch $targetOS })

        if ($nonUpgradedDCs.Count -gt 0) {
            Write-Host ""
            Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
            Write-Host "  |  DC UPGRADE GATE                                          |" -ForegroundColor Yellow
            Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
            Write-Host ""
            Write-Host "  $($nonUpgradedDCs.Count) DC(s) are not yet on Windows Server $targetOS." -ForegroundColor Yellow
            Write-Host "  M3-M12 remediation should not commence until all DCs are upgraded." -ForegroundColor Yellow
            Write-Host ""
            foreach ($dc in $nonUpgradedDCs) {
                $dcOS = if ($dc.OperatingSystem) { $dc.OperatingSystem } else { "Unknown" }
                Write-Host "    - $($dc.Name): $dcOS" -ForegroundColor Yellow
            }
            Write-Host ""

            if ($Mode -eq "Remediate") {
                Write-Host "  [BLOCK] Remediate mode is blocked until DC upgrade is complete." -ForegroundColor Red
                Write-Host "          Run with -Mode Discover to audit in the current state." -ForegroundColor Red
                Write-AgentLog -Level ERROR -Message "DC upgrade gate BLOCKED Remediate run. $($nonUpgradedDCs.Count) DCs not on $targetOS."
                exit 1
            } else {
                $ack = Read-Host "  Type CONTINUE to proceed in Discover/Baseline mode anyway, or STOP to halt"
                if ($ack.Trim().ToUpper() -ne "CONTINUE") {
                    Write-AgentLog -Level WARN -Message "Operator halted at DC upgrade gate."
                    exit 0
                }
                Write-AgentLog -Level WARN -Message "Operator continued past DC upgrade gate. $($nonUpgradedDCs.Count) DCs not yet on $targetOS."
            }
        } else {
            Write-Host "  [OK] All DCs are on Windows Server $targetOS -- upgrade gate passed." -ForegroundColor Green
            Write-AgentLog -Level INFO -Message "DC upgrade gate: all DCs on $targetOS"
        }
    } catch {
        Write-AgentLog -Level WARN -Message "DC upgrade gate check failed: $($_.Exception.Message)"
    }
}

# -- Milestone Module Map ------------------------------------------------------
$milestoneMap = @{
    "M1"  = "$ScriptRoot\Modules\Invoke-M1-DCHealthBaseline.ps1"
    "M3"  = "$ScriptRoot\Modules\Invoke-M3-OUStructure.ps1"
    "M4"  = "$ScriptRoot\Modules\Invoke-M4-UnconstrainedDelegation.ps1"
    "M5"  = "$ScriptRoot\Modules\Invoke-M5-SPNAudit.ps1"
    "M6"  = "$ScriptRoot\Modules\Invoke-M6-KerberosConfig.ps1"
    "M7"  = "$ScriptRoot\Modules\Invoke-M7-DCHardening.ps1"
    "M8"  = "$ScriptRoot\Modules\Invoke-M8-GPOCleanup.ps1"
    "M9"  = "$ScriptRoot\Modules\Invoke-M9-SecurityGroups.ps1"
    "M10" = "$ScriptRoot\Modules\Invoke-M10-DelegatedPermissions.ps1"
    "M11" = "$ScriptRoot\Modules\Invoke-M11-StaleAccounts.ps1"
    "M12" = "$ScriptRoot\Modules\Invoke-M12-PrivilegedGroups.ps1"
}

$milestoneNames = @{
    "M1"  = "DC Health and Baseline"
    "M3"  = "OU Structure Cleanup"
    "M4"  = "Unconstrained Delegation"
    "M5"  = "SPN Duplicate Detection"
    "M6"  = "Kerberos Configuration Review"
    "M7"  = "DC Hardening and CIS L1 Baseline"
    "M8"  = "GPO Cleanup"
    "M9"  = "Security Group Cleanup"
    "M10" = "Delegated Permissions Review"
    "M11" = "Stale and Inactive Accounts"
    "M12" = "Privileged Group Review"
}

# -- Execute Milestones --------------------------------------------------------
foreach ($ms in $Milestones) {
    $modulePath = $milestoneMap[$ms]
    $msName     = $milestoneNames[$ms]

    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkGray
    Write-Host "    $ms : $msName" -ForegroundColor White
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkGray

    Write-AgentLog -Level INFO -Message "Starting milestone $ms - $msName"

    if (Test-Path $modulePath) {
        . $modulePath
        & "Invoke-$ms" -Mode $Mode -Domain $Domain -OutputPath $OutputPath
    } else {
        Write-Host "  [WARN] Module not found: $modulePath" -ForegroundColor Yellow
        Write-AgentLog -Level WARN -Message "Module missing for $ms at $modulePath"
    }
}

# -- Baseline Snapshot ---------------------------------------------------------
if ($Mode -eq "Baseline") {
    Write-Host ""
    Write-Host "  [ Saving approved baseline snapshot ]" -ForegroundColor Magenta
    Save-Baseline -RunId $RunId -OutputPath $OutputPath
    Write-Host "  [OK] Baseline saved. Future Discover/Remediate runs will delta against this." -ForegroundColor Green
    Write-AgentLog -Level INFO -Message "Baseline snapshot saved for RunId $RunId"
}

# -- Run Summary ---------------------------------------------------------------
Write-Host ""
Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
Write-Host "  |  RUN COMPLETE                                             |" -ForegroundColor Cyan
Write-Host "  +----------------------------------------------------------+" -ForegroundColor Cyan
Write-Host ""

$totalFindings = $Global:FindingsList.Count
$totalActions  = $Global:ActionLog.Count

Write-Host "  Findings logged : $totalFindings" -ForegroundColor Yellow
if ($totalActions -gt 0) {
    Write-Host "  Actions taken   : $totalActions" -ForegroundColor Red
} else {
    Write-Host "  Actions taken   : $totalActions" -ForegroundColor Green
}
Write-Host "  Log             : $Global:AgentLogPath" -ForegroundColor White

$reportFindings = @($Global:FindingsList)
$reportActions  = @($Global:ActionLog)

$reportPath = New-RunReport `
    -RunId      $RunId `
    -Mode       $Mode `
    -Milestones $Milestones `
    -Findings   $reportFindings `
    -Actions    $reportActions `
    -OutputPath $OutputPath `
    -Domain     $Domain

Write-Host "  Report          : $reportPath" -ForegroundColor White
Write-Host ""

Write-AgentLog -Level INFO -Message "Agent run complete. Findings=$totalFindings Actions=$totalActions Report=$reportPath"
