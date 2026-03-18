<#
.SYNOPSIS
    Milestone 4 -- Unconstrained Delegation Remediation

    Finds all computer and user accounts with unconstrained Kerberos delegation
    enabled (TrustedForDelegation = $true), excluding Domain Controllers
    (which legitimately carry this flag).

    Risk:  If a privileged user authenticates to a host with unconstrained
           delegation, the host can impersonate that user to ANY service in
           the domain -- a classic lateral movement / privilege escalation path.

    Remediation options (human-selected per object):
      1. Remove unconstrained delegation entirely (if service no longer needs delegation)
      2. Migrate to constrained delegation (operator must specify target SPNs)
      3. Skip -- add to exception list with justification

    Mode Behaviour:
      Discover  -> enumerate and log only
      Remediate -> enumerate + human-approved per-object remediation
      Baseline  -> same as Discover
#>

function Invoke-M4 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    $ms = "M4"

    function Add-Finding {
        param($ObjectDN, $FindingType, $Severity, $Description, $Data = $null)
        $finding = [PSCustomObject]@{
            Milestone   = $ms
            FindingType = $FindingType
            ObjectDN    = $ObjectDN
            Severity    = $Severity
            Description = $Description
            Timestamp   = (Get-Date -Format "o")
            Data        = $Data
        }
        $Global:FindingsList.Add($finding)
        Write-AgentLog -Level FINDING -Milestone $ms -Message "[$Severity] $FindingType -- $ObjectDN" -Data $Data
    }

    function Add-Action {
        param($Action, $Target, $Status, $Detail)
        $Global:ActionLog.Add([PSCustomObject]@{
            Timestamp = (Get-Date -Format "o")
            Milestone = $ms
            Action    = $Action
            Target    = $Target
            Status    = $Status
            Detail    = $Detail
        })
    }

    # -- Enumerate unconstrained delegation -----------------------------------
    Write-Host "  -> Scanning for unconstrained delegation (computers)..." -ForegroundColor DarkCyan

    $flaggedComputers = @()
    $flaggedUsers     = @()

    try {
        $flaggedComputers = @(Get-ADComputer -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, OperatingSystem, Description, LastLogonDate, ServicePrincipalNames `
            -Server $Domain |
            Where-Object { $_.DistinguishedName -notmatch "Domain Controllers" })

        Write-Host "  -> Scanning for unconstrained delegation (user accounts)..." -ForegroundColor DarkCyan
        $flaggedUsers = @(Get-ADUser -Filter { TrustedForDelegation -eq $true } `
            -Properties TrustedForDelegation, Description, LastLogonDate, MemberOf `
            -Server $Domain)

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "DelegationScanFailed" -Severity "HIGH" `
            -Description "Failed to enumerate delegation: $($_.Exception.Message)"
        return
    }

    $totalFlagged = $flaggedComputers.Count + $flaggedUsers.Count

    if ($totalFlagged -eq 0) {
        Write-Host "  [OK] No unconstrained delegation found (excluding DCs)" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "No unconstrained delegation found"
        return
    }

    Write-Host ""
    Write-Host "  [!]  Found $($flaggedComputers.Count) computer(s) and $($flaggedUsers.Count) user(s) with unconstrained delegation" -ForegroundColor Yellow
    Write-Host ""

    # Register findings
    foreach ($c in $flaggedComputers) {
        Add-Finding -ObjectDN $c.DistinguishedName -FindingType "UnconstrainedDelegation_Computer" -Severity "HIGH" `
            -Description "Computer account has TrustedForDelegation=true. OS: $($c.OperatingSystem)" `
            -Data @{ SPNs = $c.ServicePrincipalNames -join "|"; LastLogon = $c.LastLogonDate }
    }
    foreach ($u in $flaggedUsers) {
        Add-Finding -ObjectDN $u.DistinguishedName -FindingType "UnconstrainedDelegation_User" -Severity "CRITICAL" `
            -Description "User account has TrustedForDelegation=true -- high impersonation risk."
    }

    # -- Discover mode exits here ----------------------------------------------
    if ($Mode -ne "Remediate") {
        Write-Host "  M4 discovery complete -- $totalFlagged object(s) flagged." -ForegroundColor Yellow
        Write-AgentLog -Level INFO -Milestone $ms -Message "M4 discover complete. $totalFlagged flagged."
        return
    }

    # -- Remediate mode: per-object approval ----------------------------------
    Write-Host "  [ Remediation mode -- each object requires individual approval ]" -ForegroundColor Red
    Write-Host ""

    # Process computers
    foreach ($c in $flaggedComputers) {
        $displayName = "$($c.Name) ($($c.DistinguishedName))"
        $spns        = if ($c.ServicePrincipalNames) { $c.ServicePrincipalNames -join ", " } else { "(none)" }

        Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Object Type : Computer" -ForegroundColor White
        Write-Host "  SPNs        : $spns" -ForegroundColor Gray
        Write-Host "  OS          : $($c.OperatingSystem)" -ForegroundColor Gray
        Write-Host "  Last Logon  : $($c.LastLogonDate)" -ForegroundColor Gray
        Write-Host ""

        try {
            $approved = Invoke-HumanApproval `
                -Action     "Remove unconstrained delegation from computer account" `
                -Target     $displayName `
                -Milestone  $ms `
                -RiskLevel  "HIGH" `
                -Implications @(
                    "TrustedForDelegation will be set to FALSE on this computer account.",
                    "If any service on this host uses Kerberos unconstrained delegation, it WILL BREAK.",
                    "Affected services: anything relying on this host to delegate Kerberos tickets to other services.",
                    "If SPNs are present ($spns), confirm with the service owner before approving.",
                    "Recommended pre-check: identify what services run on $($c.Name) and whether they use delegation."
                ) `
                -RollbackSteps @(
                    "Set-ADComputer '$($c.SamAccountName)' -TrustedForDelegation `$true",
                    "Verify Kerberos ticket acquisition for affected services",
                    "Run klist purge on affected service hosts"
                )

            if ($approved) {
                try {
                    Set-ADComputer -Identity $c.SamAccountName -TrustedForDelegation $false -Server $Domain
                    Write-Host "  [OK] Unconstrained delegation removed from $($c.Name)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Removed TrustedForDelegation from computer: $($c.DistinguishedName)"
                    Add-Action -Action "RemoveUnconstrainedDelegation" -Target $c.DistinguishedName `
                               -Status "SUCCESS" -Detail "TrustedForDelegation set to false"
                } catch {
                    Write-Host "  [X] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level ERROR -Milestone $ms -Message "Failed to modify $($c.Name): $($_.Exception.Message)"
                    Add-Action -Action "RemoveUnconstrainedDelegation" -Target $c.DistinguishedName `
                               -Status "FAILED" -Detail $_.Exception.Message
                }
            }
        } catch {
            if ($_ -match "MILESTONE_QUIT") { break }
            Write-AgentLog -Level WARN -Milestone $ms -Message "Approval gate exception: $_"
        }
    }

    # Process users
    foreach ($u in $flaggedUsers) {
        $displayName = "$($u.SamAccountName) ($($u.DistinguishedName))"

        Write-Host "  ------------------------------------------------------------" -ForegroundColor DarkGray
        Write-Host "  Object Type : User Account" -ForegroundColor White
        Write-Host "  Description : $($u.Description)" -ForegroundColor Gray
        Write-Host "  Last Logon  : $($u.LastLogonDate)" -ForegroundColor Gray
        Write-Host ""

        try {
            $approved = Invoke-HumanApproval `
                -Action    "Remove unconstrained delegation from USER account" `
                -Target    $displayName `
                -Milestone $ms `
                -RiskLevel "CRITICAL" `
                -Implications @(
                    "TrustedForDelegation will be set to FALSE on this user account.",
                    "User accounts with unconstrained delegation are an extremely high-risk configuration.",
                    "Any service running under this account that relied on unconstrained delegation WILL BREAK.",
                    "Consider migrating to a service account with constrained delegation or gMSA instead.",
                    "If this is a service account, ensure the service owner is consulted BEFORE approving."
                ) `
                -RollbackSteps @(
                    "Set-ADUser '$($u.SamAccountName)' -TrustedForDelegation `$true",
                    "Restart the service that was affected",
                    "Verify authentication works and Kerberos tickets are issued correctly"
                )

            if ($approved) {
                try {
                    Set-ADUser -Identity $u.SamAccountName -TrustedForDelegation $false -Server $Domain
                    Write-Host "  [OK] Unconstrained delegation removed from user $($u.SamAccountName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Removed TrustedForDelegation from user: $($u.DistinguishedName)"
                    Add-Action -Action "RemoveUnconstrainedDelegation_User" -Target $u.DistinguishedName `
                               -Status "SUCCESS" -Detail "TrustedForDelegation set to false on user"
                } catch {
                    Write-Host "  [X] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    Add-Action -Action "RemoveUnconstrainedDelegation_User" -Target $u.DistinguishedName `
                               -Status "FAILED" -Detail $_.Exception.Message
                }
            }
        } catch {
            if ($_ -match "MILESTONE_QUIT") { break }
        }
    }

    $msActions = $Global:ActionLog | Where-Object Milestone -eq $ms
    Write-Host ""
    Write-Host "  M4 complete -- $($msActions.Count) change(s) applied" -ForegroundColor $(if($msActions.Count -gt 0){"Magenta"}else{"Green"})
    Write-AgentLog -Level INFO -Milestone $ms -Message "M4 remediation complete. Changes: $($msActions.Count)"
}
