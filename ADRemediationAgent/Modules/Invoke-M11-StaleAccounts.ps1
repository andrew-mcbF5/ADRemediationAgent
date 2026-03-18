<#
.SYNOPSIS
    Milestone 11 -- Stale / Inactive Account Cleanup

    Identifies and remediates stale user, computer, and service accounts using
    a safe quarantine-first pattern:
        1. Disable account
        2. Move to Quarantine OU
        3. Stamp description with date/reason
        (Deletion is intentionally NOT automated -- requires separate manual step
         after a defined retention window)

    Staleness thresholds (configurable):
      - Users     : no logon in 90 days
      - Computers : no logon in 90 days
      - Service Accounts (OU-based detection): 90 days, flagged separately

    Exclusions:
      - Accounts already disabled
      - Accounts in a defined protected OU list
      - Accounts whose name matches a protected pattern (e.g. svc-*, krbtgt, Guest)

    Mode Behaviour:
      Discover  -> enumerate and report, no changes
      Remediate -> bulk approval UI, then quarantine approved accounts
      Baseline  -> same as Discover
#>

function Invoke-M11 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath,
        [int]    $InactiveDays    = 90,
        [string] $QuarantineOU   = ""   # If empty, agent will prompt or create
    )

    $ms = "M11"

    function Add-Finding {
        param($ObjectDN, $FindingType, $Severity, $Description, $Data = $null)
        $Global:FindingsList.Add([PSCustomObject]@{
            Milestone   = $ms
            FindingType = $FindingType
            ObjectDN    = $ObjectDN
            Severity    = $Severity
            Description = $Description
            Timestamp   = (Get-Date -Format "o")
            Data        = $Data
        })
        Write-AgentLog -Level FINDING -Milestone $ms -Message "[$Severity] $FindingType -- $ObjectDN"
    }

    function Add-Action {
        param($Action, $Target, $Status, $Detail)
        $Global:ActionLog.Add([PSCustomObject]@{
            Timestamp = (Get-Date -Format "o"); Milestone = $ms
            Action = $Action; Target = $Target; Status = $Status; Detail = $Detail
        })
    }

    # Protected account patterns -- never touch these
    $protectedPatterns = @("krbtgt","Guest","Administrator","DefaultAccount","SUPPORT_388945a0","svc-ad-","svc-backup-")
    $cutoffDate        = (Get-Date).AddDays(-$InactiveDays)

    # -- Resolve Quarantine OU -------------------------------------------------
    if (-not $QuarantineOU) {
        $domainDN = (Get-ADDomain -Identity $Domain).DistinguishedName
        $QuarantineOU = "OU=Quarantine-Disabled,$domainDN"
    }

    Write-Host "  -> Quarantine OU: $QuarantineOU" -ForegroundColor DarkCyan

    $quarantineOUExists = $false
    try {
        Get-ADOrganizationalUnit -Identity $QuarantineOU -Server $Domain -ErrorAction Stop | Out-Null
        $quarantineOUExists = $true
        Write-Host "  [OK] Quarantine OU exists" -ForegroundColor Green
    } catch {
        Write-Host "  [!] Quarantine OU does not exist: $QuarantineOU" -ForegroundColor Yellow
        Add-Finding -ObjectDN $QuarantineOU -FindingType "QuarantineOUMissing" -Severity "MEDIUM" `
            -Description "Quarantine OU does not exist. It will be created if remediation is approved."
    }

    # -- Enumerate stale users -------------------------------------------------
    Write-Host "  -> Scanning for stale user accounts (inactive > $InactiveDays days)..." -ForegroundColor DarkCyan

    $staleUsers = @()
    try {
        $staleUsers = @(Search-ADAccount -AccountInactive -TimeSpan ([timespan]::FromDays($InactiveDays)) `
            -UsersOnly -Server $Domain |
            Get-ADUser -Properties LastLogonDate, Description, DistinguishedName, PasswordLastSet |
            Where-Object {
                $_.Enabled -eq $true -and
                $_.DistinguishedName -notmatch "Domain Controllers" -and
                $_.DistinguishedName -notmatch "Quarantine" -and
                -not ($protectedPatterns | Where-Object { $_.SamAccountName -like $_ })
            })

        Write-Host "    Found $($staleUsers.Count) stale enabled user account(s)" -ForegroundColor $(if($staleUsers.Count -gt 0){"Yellow"}else{"Green"})

        foreach ($u in $staleUsers) {
            Add-Finding -ObjectDN $u.DistinguishedName -FindingType "StaleUser" -Severity "MEDIUM" `
                -Description "User inactive since $(if ($u.LastLogonDate) { $u.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never logged in' }). PwdLastSet: $(if ($u.PasswordLastSet) { $u.PasswordLastSet.ToString('yyyy-MM-dd') } else { 'Unknown' })"
        }
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "StaleUserScanFailed" -Severity "HIGH" -Description $_.Exception.Message
    }

    # -- Enumerate stale computers ---------------------------------------------
    Write-Host "  -> Scanning for stale computer accounts (inactive > $InactiveDays days)..." -ForegroundColor DarkCyan

    $staleComputers = @()
    try {
        $staleComputers = @(Search-ADAccount -AccountInactive -TimeSpan ([timespan]::FromDays($InactiveDays)) `
            -ComputersOnly -Server $Domain |
            Get-ADComputer -Properties LastLogonDate, Description, DistinguishedName, OperatingSystem |
            Where-Object {
                $_.Enabled -eq $true -and
                $_.DistinguishedName -notmatch "Domain Controllers" -and
                $_.DistinguishedName -notmatch "Quarantine"
            })

        Write-Host "    Found $($staleComputers.Count) stale enabled computer account(s)" -ForegroundColor $(if($staleComputers.Count -gt 0){"Yellow"}else{"Green"})

        foreach ($c in $staleComputers) {
            Add-Finding -ObjectDN $c.DistinguishedName -FindingType "StaleComputer" -Severity "LOW" `
                -Description "Computer inactive since $(if ($c.LastLogonDate) { $c.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never' }). OS: $($c.OperatingSystem)"
        }
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "StaleComputerScanFailed" -Severity "HIGH" -Description $_.Exception.Message
    }

    $totalStale = $staleUsers.Count + $staleComputers.Count
    Write-Host ""
    Write-Host "  Total stale objects found: $totalStale (Users: $($staleUsers.Count) | Computers: $($staleComputers.Count))" -ForegroundColor Yellow

    if ($totalStale -eq 0) {
        Write-Host "  [OK] No stale accounts found above threshold" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "No stale accounts found"
        return
    }

    # -- Discover mode exits here ----------------------------------------------
    if ($Mode -ne "Remediate") {
        Write-AgentLog -Level INFO -Milestone $ms -Message "M11 discover: $($staleUsers.Count) stale users, $($staleComputers.Count) stale computers"
        return
    }

    # -- Remediate: Create Quarantine OU if needed ----------------------------
    if (-not $quarantineOUExists) {
        Write-Host ""
        Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow
        Write-Host "  |  ACTION REQUIRED: Create Quarantine OU                  |" -ForegroundColor Yellow
        Write-Host "  +----------------------------------------------------------+" -ForegroundColor Yellow

        try {
            $ouApproved = Invoke-HumanApproval `
                -Action    "Create Quarantine OU for disabled accounts" `
                -Target    $QuarantineOU `
                -Milestone $ms `
                -RiskLevel "LOW" `
                -Implications @(
                    "Creates new OU: $QuarantineOU",
                    "This OU will receive disabled/quarantined accounts moved from active OUs.",
                    "Accounts remain in AD -- nothing is deleted. They are disabled and relocated.",
                    "Deletion requires a separate manual step after your defined retention window."
                )

            if ($ouApproved) {
                $ouName   = ($QuarantineOU -split ",")[0] -replace "OU=",""
                $parentDN = $QuarantineOU -replace "^OU=[^,]+,",""
                New-ADOrganizationalUnit -Name $ouName -Path $parentDN -Server $Domain
                Write-Host "  [OK] Quarantine OU created: $QuarantineOU" -ForegroundColor Green
                Write-AgentLog -Level ACTION -Milestone $ms -Message "Created Quarantine OU: $QuarantineOU"
                $quarantineOUExists = $true
                Add-Action -Action "CreateQuarantineOU" -Target $QuarantineOU -Status "SUCCESS" -Detail "OU created for quarantine operations"
            } else {
                Write-Host "  Quarantine OU creation declined -- cannot quarantine accounts. Exiting M11." -ForegroundColor Yellow
                Write-AgentLog -Level DENIED -Milestone $ms -Message "Quarantine OU creation declined -- M11 aborted"
                return
            }
        } catch {
            if ($_ -match "MILESTONE_QUIT") { return }
        }
    }

    # -- Bulk approval: Stale Users --------------------------------------------
    if ($staleUsers.Count -gt 0) {
        Write-Host ""
        Write-Host "  -- Stale User Accounts --------------------------------------" -ForegroundColor DarkCyan

        try {
            $approvedUsers = Invoke-BulkApproval `
                -Items       $staleUsers `
                -Action      "Disable and move stale user accounts to Quarantine OU" `
                -Milestone   $ms `
                -RiskLevel   "MEDIUM" `
                -DisplayProperty "SamAccountName" `
                -Implications @(
                    "Each approved account will be DISABLED in Active Directory.",
                    "Account will be MOVED to $QuarantineOU",
                    "Description field will be stamped with: 'QUARANTINED by AD Agent $(Get-Date -Format yyyy-MM-dd)'",
                    "Users will NOT be able to log in once disabled.",
                    "NO account is deleted -- this is reversible by re-enabling and moving back.",
                    "If a service account is in this list, its service WILL STOP WORKING when disabled."
                )

            foreach ($u in $approvedUsers) {
                try {
                    $stamp = "QUARANTINED by AD Agent $(Get-Date -Format 'yyyy-MM-dd') | Was: $($u.DistinguishedName)"
                    Disable-ADAccount -Identity $u.SamAccountName -Server $Domain
                    Move-ADObject -Identity $u.DistinguishedName -TargetPath $QuarantineOU -Server $Domain
                    Set-ADUser -Identity $u.SamAccountName -Description $stamp -Server $Domain
                    Write-Host "  [OK] Quarantined: $($u.SamAccountName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms -Message "Quarantined user: $($u.DistinguishedName)"
                    Add-Action -Action "QuarantineUser" -Target $u.DistinguishedName -Status "SUCCESS" -Detail "Disabled + moved to quarantine"
                } catch {
                    Write-Host "  [X] Failed for $($u.SamAccountName): $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level ERROR -Milestone $ms -Message "Failed to quarantine $($u.SamAccountName): $($_.Exception.Message)"
                    Add-Action -Action "QuarantineUser" -Target $u.DistinguishedName -Status "FAILED" -Detail $_.Exception.Message
                }
            }
        } catch {
            if ($_ -match "MILESTONE_QUIT") { }
        }
    }

    # -- Bulk approval: Stale Computers ----------------------------------------
    if ($staleComputers.Count -gt 0) {
        Write-Host ""
        Write-Host "  -- Stale Computer Accounts ---------------------------------" -ForegroundColor DarkCyan

        try {
            $approvedComputers = Invoke-BulkApproval `
                -Items       $staleComputers `
                -Action      "Disable and move stale computer accounts to Quarantine OU" `
                -Milestone   $ms `
                -RiskLevel   "LOW" `
                -DisplayProperty "Name" `
                -Implications @(
                    "Each approved computer account will be DISABLED in Active Directory.",
                    "Account will be MOVED to $QuarantineOU",
                    "If the physical machine is still in use, it will fail domain authentication -- requiring a rejoin.",
                    "Verify the machine is decommissioned or off-network before approving.",
                    "NO account is deleted -- this is reversible."
                )

            foreach ($c in $approvedComputers) {
                try {
                    $stamp = "QUARANTINED by AD Agent $(Get-Date -Format 'yyyy-MM-dd') | Was: $($c.DistinguishedName)"
                    Disable-ADAccount -Identity $c.SamAccountName -Server $Domain
                    Move-ADObject -Identity $c.DistinguishedName -TargetPath $QuarantineOU -Server $Domain
                    Set-ADComputer -Identity $c.SamAccountName -Description $stamp -Server $Domain
                    Write-Host "  [OK] Quarantined: $($c.Name)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms -Message "Quarantined computer: $($c.DistinguishedName)"
                    Add-Action -Action "QuarantineComputer" -Target $c.DistinguishedName -Status "SUCCESS" -Detail "Disabled + moved to quarantine"
                } catch {
                    Write-Host "  [X] Failed for $($c.Name): $($_.Exception.Message)" -ForegroundColor Red
                    Add-Action -Action "QuarantineComputer" -Target $c.DistinguishedName -Status "FAILED" -Detail $_.Exception.Message
                }
            }
        } catch {
            if ($_ -match "MILESTONE_QUIT") { }
        }
    }

    $msActions = $Global:ActionLog | Where-Object Milestone -eq $ms
    Write-Host ""
    Write-Host "  M11 complete -- $($msActions.Count) account(s) quarantined" -ForegroundColor $(if($msActions.Count -gt 0){"Magenta"}else{"Green"})
    Write-AgentLog -Level INFO -Milestone $ms -Message "M11 complete. Quarantined: $($msActions.Count)"
}
