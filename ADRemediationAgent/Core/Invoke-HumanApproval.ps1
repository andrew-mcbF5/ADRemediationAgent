<#
.SYNOPSIS
    Invoke-HumanApproval
    
    The core human-in-the-loop gate for all remediation actions.
    
    Presents a full "blast radius" summary to the operator before any change.
    Requires explicit typed confirmation -- no defaults, no Enter-to-accept.
    
    Returns: $true (approved) | $false (denied/skipped)

.PARAMETER Action
    Short description of what will happen. e.g. "Disable stale user account"

.PARAMETER Target
    The AD object being changed. e.g. "jsmith (CN=jsmith,OU=Users,DC=corp,DC=com)"

.PARAMETER Implications
    Array of strings describing what WILL happen if approved -- written bluntly.

.PARAMETER RiskLevel
    LOW | MEDIUM | HIGH | CRITICAL  -- controls warning colour and extra confirmation step.

.PARAMETER Milestone
    Which milestone this action belongs to.

.PARAMETER DryRunSummary
    Optional: output from a -WhatIf / preview pass to show the operator.
#>

function Invoke-HumanApproval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [string]   $Action,
        [Parameter(Mandatory)] [string]   $Target,
        [Parameter(Mandatory)] [string[]] $Implications,
        [ValidateSet("LOW","MEDIUM","HIGH","CRITICAL")]
        [string]   $RiskLevel        = "MEDIUM",
        [string]   $Milestone        = "UNKNOWN",
        [string[]] $RollbackSteps    = @(),
        [string]   $DryRunSummary    = ""
    )

    # -- Colour scheme per risk ------------------------------------------------
    $riskColour = switch ($RiskLevel) {
        "LOW"      { "Green" }
        "MEDIUM"   { "Yellow" }
        "HIGH"     { "Red" }
        "CRITICAL" { "Magenta" }
    }

    # -- Approval box ----------------------------------------------------------
    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor $riskColour
    Write-Host ("  |  APPROVAL REQUIRED  [{0,-7}]  Milestone: {1,-12}  |" -f $RiskLevel, $Milestone) -ForegroundColor $riskColour
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor $riskColour
    Write-Host ""
    Write-Host "  ACTION  : $Action" -ForegroundColor White
    Write-Host "  TARGET  : $Target" -ForegroundColor White
    Write-Host ""

    Write-Host "  --- What will happen if you approve -----------------------" -ForegroundColor DarkGray
    foreach ($impl in $Implications) {
        Write-Host "    > $impl" -ForegroundColor $riskColour
    }

    if ($RollbackSteps.Count -gt 0) {
        Write-Host ""
        Write-Host "  --- Rollback steps if this causes issues ------------------" -ForegroundColor DarkGray
        foreach ($step in $RollbackSteps) {
            Write-Host "    <- $step" -ForegroundColor DarkCyan
        }
    }

    if ($DryRunSummary) {
        Write-Host ""
        Write-Host "  --- Preview (WhatIf output) --------------------------------" -ForegroundColor DarkGray
        Write-Host "    $DryRunSummary" -ForegroundColor DarkGray
    }

    Write-Host ""

    # -- Extra confirmation for HIGH/CRITICAL ---------------------------------
    if ($RiskLevel -in @("HIGH","CRITICAL")) {
        Write-Host "  [!]  This is a $RiskLevel risk change. Type the target name to unlock approval." -ForegroundColor $riskColour
        Write-Host ""

        # Extract short name for confirmation (last CN= segment)
        $confirmTarget = if ($Target -match "^(.+?)\s+\(") { $Matches[1] } else { $Target.Split(",")[0] -replace "CN=","" }

        $confirmPrompt = Read-Host "  Type [$confirmTarget] exactly to continue, or press Enter to SKIP"

        if ($confirmPrompt -ne $confirmTarget) {
            Write-Host ""
            Write-Host "  [X] Confirmation did not match. Change SKIPPED." -ForegroundColor Yellow
            Write-AgentLog -Level DENIED -Milestone $Milestone `
                -Message "HIGH/CRITICAL confirmation failed for: $Target ($Action)"
            return $false
        }
    }

    # -- Standard approve / deny -----------------------------------------------
    Write-Host "  Options:  [A] Approve   [S] Skip this item   [Q] Quit milestone" -ForegroundColor White
    Write-Host ""

    do {
        $choice = Read-Host "  Your choice"
        $choice = $choice.Trim().ToUpper()
    } while ($choice -notin @("A","S","Q"))

    Write-Host ""

    switch ($choice) {
        "A" {
            Write-Host "  [OK] APPROVED -- executing change..." -ForegroundColor Green
            Write-AgentLog -Level APPROVED -Milestone $Milestone `
                -Message "Approved: $Action on $Target"
            return $true
        }
        "S" {
            Write-Host "  -> Skipped." -ForegroundColor Yellow
            Write-AgentLog -Level DENIED -Milestone $Milestone `
                -Message "Skipped: $Action on $Target"
            return $false
        }
        "Q" {
            Write-Host "  [X]  Quitting milestone $Milestone -- no further changes in this milestone." -ForegroundColor Yellow
            Write-AgentLog -Level DENIED -Milestone $Milestone `
                -Message "Operator quit milestone at: $Target"
            throw "MILESTONE_QUIT"
        }
    }
}


<#
.SYNOPSIS
    Invoke-BulkApproval

    Used when a milestone produces a large list of low-risk items (e.g. stale accounts).
    Shows the full list, lets the operator approve ALL, approve NONE, or enter
    individual SamAccountNames to exclude before bulk-approving the rest.

    Returns: Array of approved objects from $Items
#>
function Invoke-BulkApproval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)] [PSObject[]] $Items,
        [Parameter(Mandatory)] [string]     $Action,
        [Parameter(Mandatory)] [string]     $Milestone,
        [Parameter(Mandatory)] [string[]]   $Implications,
        [string]   $DisplayProperty  = "SamAccountName",
        [string]   $RiskLevel        = "MEDIUM"
    )

    $riskColour = switch ($RiskLevel) {
        "LOW"      { "Green" }
        "MEDIUM"   { "Yellow" }
        "HIGH"     { "Red" }
        "CRITICAL" { "Magenta" }
    }

    Write-Host ""
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor $riskColour
    Write-Host ("  |  BULK APPROVAL REQUIRED  [{0,-7}]  Milestone: {1,-9}  |" -f $RiskLevel, $Milestone) -ForegroundColor $riskColour
    Write-Host "  +----------------------------------------------------------+" -ForegroundColor $riskColour
    Write-Host ""
    Write-Host "  ACTION    : $Action" -ForegroundColor White
    Write-Host "  ITEM COUNT: $($Items.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "  --- Full item list -----------------------------------------" -ForegroundColor DarkGray

    $Items | ForEach-Object {
        $displayVal = if ($_ -is [string]) { $_ } else { $_.$DisplayProperty }
        $extra = ""
        if ($_.LastLogonDate) { $extra += "  LastLogon: $($_.LastLogonDate.ToString('yyyy-MM-dd'))" }
        if ($_.Enabled -ne $null) { $extra += "  Enabled: $($_.Enabled)" }
        Write-Host "    * $displayVal$extra" -ForegroundColor Gray
    }

    Write-Host ""
    Write-Host "  --- Implications -------------------------------------------" -ForegroundColor DarkGray
    foreach ($impl in $Implications) {
        Write-Host "    > $impl" -ForegroundColor $riskColour
    }

    Write-Host ""
    Write-Host "  Options:" -ForegroundColor White
    Write-Host "    [A] Approve ALL items above" -ForegroundColor Green
    Write-Host "    [E] Exclude specific accounts then approve the rest" -ForegroundColor Yellow
    Write-Host "    [N] Skip ALL -- no changes" -ForegroundColor DarkYellow
    Write-Host ""

    do {
        $choice = (Read-Host "  Your choice").Trim().ToUpper()
    } while ($choice -notin @("A","E","N"))

    Write-Host ""

    if ($choice -eq "N") {
        Write-Host "  -> All items skipped." -ForegroundColor Yellow
        Write-AgentLog -Level DENIED -Milestone $Milestone -Message "Bulk skipped: $Action ($($Items.Count) items)"
        return @()
    }

    $approved = $Items

    if ($choice -eq "E") {
        Write-Host "  Enter SamAccountNames to EXCLUDE (comma-separated):" -ForegroundColor Yellow
        $excludeInput = Read-Host "  Exclude"
        $excludeList  = $excludeInput -split "," | ForEach-Object { $_.Trim() }

        $approved = $Items | Where-Object {
            $val = if ($_ -is [string]) { $_ } else { $_.$DisplayProperty }
            $val -notin $excludeList
        }

        $excluded = $Items.Count - $approved.Count
        Write-Host "  -> Excluded $excluded items. $($approved.Count) items will be processed." -ForegroundColor Yellow
    }

    Write-Host "  [OK] APPROVED -- $($approved.Count) items queued for: $Action" -ForegroundColor Green
    Write-AgentLog -Level APPROVED -Milestone $Milestone `
        -Message "Bulk approved: $Action -- $($approved.Count)/$($Items.Count) items"

    return $approved
}
