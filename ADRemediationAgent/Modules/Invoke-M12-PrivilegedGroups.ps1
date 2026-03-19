<#
.SYNOPSIS
    Milestone 12 -- Privileged Group Review

    Inventories all high-privilege group memberships and compares to the stored
    baseline. Flags:
      - NEW members added since baseline (CRITICAL -- unexpected elevation)
      - Members with no logon activity (stale privileged accounts -- HIGH)
      - Service accounts in Tier 0 groups (HIGH)
      - Non-human accounts (computer accounts) in privileged groups (CRITICAL)
      - Nested group membership in privileged groups (MEDIUM -- visibility gap)

    Groups audited by default:
      Domain Admins, Enterprise Admins, Schema Admins,
      Backup Operators, Account Operators, Print Operators,
      Server Operators, Group Policy Creator Owners,
      Protected Users (membership delta only)

    Remediation:
      - Remove members (human approval per member)
      - Remediate does NOT rename, merge, or delete groups -- membership only

    Mode Behaviour:
      Discover  -> enumerate, diff against baseline if available
      Remediate -> enumerate + per-member removal approval
      Baseline  -> snapshot membership as approved baseline
#>

function Invoke-M12 {
    [CmdletBinding()]
    param(
        [string]   $Mode,
        [string]   $Domain,
        [string]   $OutputPath,
        [string[]] $PrivGroups = @(
            "Domain Admins",
            "Enterprise Admins",
            "Schema Admins",
            "Backup Operators",
            "Account Operators",
            "Print Operators",
            "Server Operators",
            "Group Policy Creator Owners"
        )
    )

    $ms = "M12"

    function Add-Finding {
        param(
            $ObjectDN, $FindingType, $Severity, $Description,
            $CISControl = "", $CISLevel = "", $NISTControl = "", $Data = $null
        )
        $finding = [PSCustomObject]@{
            Milestone   = $ms
            FindingType = $FindingType
            ObjectDN    = $ObjectDN
            Severity    = $Severity
            Description = $Description
            CISControl  = $CISControl
            CISLevel    = $CISLevel
            NISTControl = $NISTControl
            Timestamp   = (Get-Date -Format "o")
            Data        = $Data
        }
        $Global:FindingsList.Add($finding)
        Write-AgentLog -Level FINDING -Milestone $ms -Message "[$Severity] $FindingType -- $($ObjectDN): $Description" -Data $Data
    }

    function Add-Action {
        param($Action, $Target, $Status, $Detail)
        $Global:ActionLog.Add([PSCustomObject]@{
            Timestamp = (Get-Date -Format "o"); Milestone = $ms
            Action = $Action; Target = $Target; Status = $Status; Detail = $Detail
        })
    }

    # -- Load previous baseline membership snapshot ----------------------------
    $baselineFile    = "$OutputPath\Baselines\baseline-latest.json"
    $baselineMembers = @{}

    if (Test-Path $baselineFile) {
        try {
            $baseline = Get-Content $baselineFile -Raw | ConvertFrom-Json
            $baseline.Findings |
                Where-Object { $_.FindingType -eq "PrivGroupMembership" } |
                ForEach-Object {
                    $key = $_.ObjectDN   # "SamAccountName|GroupName"
                    $baselineMembers[$key] = $_
                }
            Write-Host "  [OK] Baseline loaded -- $($baselineMembers.Count) privileged membership records" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "Baseline loaded: $($baselineMembers.Count) priv membership records"
        } catch {
            Write-Host "  [!] Could not load baseline: $($_.Exception.Message)" -ForegroundColor Yellow
        }
    } else {
        Write-Host "  [!] No baseline found -- first run will serve as the reference point" -ForegroundColor Yellow
    }

    # -- Enumerate privileged group memberships --------------------------------
    $allMembers   = [System.Collections.Generic.List[PSObject]]::new()
    $newMembers   = [System.Collections.Generic.List[PSObject]]::new()   # Not in baseline
    $stalePriv    = [System.Collections.Generic.List[PSObject]]::new()   # Inactive privileged accounts
    $svcInPriv    = [System.Collections.Generic.List[PSObject]]::new()   # Service accounts in Tier 0
    $computerPriv = [System.Collections.Generic.List[PSObject]]::new()   # Computer accounts in priv groups
    $nestedGroups = [System.Collections.Generic.List[PSObject]]::new()   # Groups nested in priv groups

    foreach ($groupName in $PrivGroups) {
        Write-Host "  -> Auditing: $groupName" -ForegroundColor DarkCyan

        try {
            $group   = Get-ADGroup -Identity $groupName -Server $Domain -ErrorAction SilentlyContinue
            if (-not $group) {
                Write-Host "    (group not found -- may be forest-level only)" -ForegroundColor DarkGray
                continue
            }

            $members = Get-ADGroupMember -Identity $groupName -Recursive -Server $Domain -ErrorAction Stop

            Write-Host "    Members: $($members.Count)" -ForegroundColor Gray

            foreach ($m in $members) {
                $memberKey = "$($m.SamAccountName)|$groupName"

                # Get extended properties
                $memberDetail = $null
                try {
                    if ($m.objectClass -eq "user") {
                        $memberDetail = Get-ADUser $m.SamAccountName -Properties LastLogonDate, PasswordLastSet, Description, Enabled -Server $Domain
                    } elseif ($m.objectClass -eq "computer") {
                        $memberDetail = Get-ADComputer $m.SamAccountName -Properties LastLogonDate, Enabled -Server $Domain
                    }
                } catch { }

                $memberObj = [PSCustomObject]@{
                    Group          = $groupName
                    GroupDN        = $group.DistinguishedName
                    SamAccountName = $m.SamAccountName
                    Name           = $m.Name
                    ObjectClass    = $m.objectClass
                    DN             = $m.distinguishedName
                    LastLogonDate  = if ($memberDetail) { $memberDetail.LastLogonDate } else { $null }
                    Enabled        = if ($memberDetail) { $memberDetail.Enabled }       else { $null }
                    Description    = if ($memberDetail) { $memberDetail.Description }   else { $null }
                    InBaseline     = $baselineMembers.ContainsKey($memberKey)
                }

                $allMembers.Add($memberObj)

                # Register as baseline finding (so it's captured in snapshots)
                Add-Finding -ObjectDN $memberKey -FindingType "PrivGroupMembership" -Severity "INFO" `
                    -Description "$($m.SamAccountName) is member of $groupName" `
                    -NISTControl "AC-2, AC-6"

                # -- Flag: NEW member not in baseline -------------------------
                if ($baselineMembers.Count -gt 0 -and -not $baselineMembers.ContainsKey($memberKey)) {
                    $newMembers.Add($memberObj)
                    Add-Finding -ObjectDN $m.distinguishedName -FindingType "NewPrivilegedMember" -Severity "CRITICAL" `
                        -Description "NEW member in $groupName since baseline: $($m.SamAccountName). Not previously authorised." `
                        -NISTControl "AC-2, AC-6, AU-9"
                }

                # -- Flag: Computer account in priv group ----------------------
                if ($m.objectClass -eq "computer") {
                    $computerPriv.Add($memberObj)
                    Add-Finding -ObjectDN $m.distinguishedName -FindingType "ComputerInPrivGroup" -Severity "CRITICAL" `
                        -Description "Computer account $($m.SamAccountName) is member of $groupName -- almost certainly unintended." `
                        -NISTControl "AC-2, AC-6"
                }

                # -- Flag: Group nested in priv group -------------------------
                if ($m.objectClass -eq "group") {
                    $nestedGroups.Add($memberObj)
                    Add-Finding -ObjectDN $m.distinguishedName -FindingType "NestedGroupInPrivGroup" -Severity "MEDIUM" `
                        -Description "Group '$($m.Name)' is nested inside $groupName -- indirect membership may be wider than expected." `
                        -NISTControl "AC-2, AC-6"
                }

                # -- Flag: Stale privileged user (no logon in 60 days) ---------
                if ($m.objectClass -eq "user" -and $memberDetail -and $memberDetail.LastLogonDate) {
                    if ($memberDetail.LastLogonDate -lt (Get-Date).AddDays(-60)) {
                        $stalePriv.Add($memberObj)
                        Add-Finding -ObjectDN $m.distinguishedName -FindingType "StalePrivilegedAccount" -Severity "HIGH" `
                            -Description "$($m.SamAccountName) in $groupName has not logged on since $($memberDetail.LastLogonDate.ToString('yyyy-MM-dd')) (>60 days)." `
                            -NISTControl "AC-2, IA-4"
                    }
                }

                # -- Flag: Service account pattern in Domain/Enterprise/Schema Admins --
                $tier0Groups = @("Domain Admins","Enterprise Admins","Schema Admins")
                if ($groupName -in $tier0Groups -and $m.SamAccountName -match "^svc[-_]|service|svc$") {
                    $svcInPriv.Add($memberObj)
                    Add-Finding -ObjectDN $m.distinguishedName -FindingType "ServiceAccountInTier0" -Severity "HIGH" `
                        -Description "Service account pattern detected in $($groupName): $($m.SamAccountName) -- service accounts should not be Tier 0 members." `
                        -NISTControl "AC-6, IA-5"
                }
            }

        } catch {
            Write-Host "    [X] Could not enumerate $($groupName): $($_.Exception.Message)" -ForegroundColor Red
            Write-AgentLog -Level ERROR -Milestone $ms -Message "Failed to enumerate $($groupName): $($_.Exception.Message)"
        }
    }

    # -- Summary display -------------------------------------------------------
    Write-Host ""
    Write-Host "  --- M12 Findings Summary --------------------------------------" -ForegroundColor DarkCyan
    Write-Host "  Total privileged members   : $($allMembers.Count)" -ForegroundColor White
    Write-Host "  NEW since baseline         : $($newMembers.Count)" -ForegroundColor $(if($newMembers.Count   -gt 0){"Red"}else{"Green"})
    Write-Host "  Stale privileged accounts  : $($stalePriv.Count)"    -ForegroundColor $(if($stalePriv.Count    -gt 0){"Yellow"}else{"Green"})
    Write-Host "  Service accounts in Tier 0 : $($svcInPriv.Count)"    -ForegroundColor $(if($svcInPriv.Count    -gt 0){"Yellow"}else{"Green"})
    Write-Host "  Computer accounts in priv  : $($computerPriv.Count)" -ForegroundColor $(if($computerPriv.Count -gt 0){"Red"}else{"Green"})
    Write-Host "  Nested groups in priv      : $($nestedGroups.Count)" -ForegroundColor $(if($nestedGroups.Count -gt 0){"Yellow"}else{"Green"})
    Write-Host ""

    # Save membership CSV snapshot
    $snapFile = "$OutputPath\Reports\M12-PrivGroupSnapshot-$Global:RunTimestamp.csv"
    $allMembers | Export-Csv $snapFile -NoTypeInformation -Encoding UTF8
    Write-Host "  Membership snapshot: $snapFile" -ForegroundColor DarkGray
    Write-AgentLog -Level INFO -Milestone $ms -Message "Membership snapshot saved: $snapFile"

    # -- Discover/Baseline exits here -----------------------------------------
    if ($Mode -ne "Remediate") {
        Write-AgentLog -Level INFO -Milestone $ms -Message "M12 discover complete. Total members: $($allMembers.Count)"
        return
    }

    # -- Remediate: per-member removal approval --------------------------------
    $candidatesForRemoval = [System.Collections.Generic.List[PSObject]]::new()
    $newMembers   | ForEach-Object { $candidatesForRemoval.Add($_) }
    $stalePriv    | ForEach-Object { if ($_ -notin $candidatesForRemoval) { $candidatesForRemoval.Add($_) } }
    $svcInPriv    | ForEach-Object { if ($_ -notin $candidatesForRemoval) { $candidatesForRemoval.Add($_) } }
    $computerPriv | ForEach-Object { if ($_ -notin $candidatesForRemoval) { $candidatesForRemoval.Add($_) } }

    # Deduplicate
    $candidatesForRemoval = $candidatesForRemoval | Sort-Object SamAccountName,Group -Unique

    if ($candidatesForRemoval.Count -eq 0) {
        Write-Host "  [OK] No candidates for removal identified." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "No removal candidates found"
        return
    }

    Write-Host "  [ $($candidatesForRemoval.Count) member(s) flagged for potential removal ]" -ForegroundColor Yellow
    Write-Host ""

    foreach ($candidate in $candidatesForRemoval) {
        # Determine flags for this candidate
        $flags = @()
        if ($newMembers   | Where-Object { $_.SamAccountName -eq $candidate.SamAccountName -and $_.Group -eq $candidate.Group }) { $flags += "NEW since baseline" }
        if ($stalePriv    | Where-Object { $_.SamAccountName -eq $candidate.SamAccountName -and $_.Group -eq $candidate.Group }) { $flags += "Stale account (>60 days no logon)" }
        if ($svcInPriv    | Where-Object { $_.SamAccountName -eq $candidate.SamAccountName -and $_.Group -eq $candidate.Group }) { $flags += "Service account in Tier 0 group" }
        if ($computerPriv | Where-Object { $_.SamAccountName -eq $candidate.SamAccountName -and $_.Group -eq $candidate.Group }) { $flags += "Computer account in privileged group" }

        $riskLevel = if ("NEW since baseline" -in $flags -or "Computer account in privileged group" -in $flags) { "CRITICAL" } else { "HIGH" }

        Write-Host "  Group        : $($candidate.Group)" -ForegroundColor White
        Write-Host "  Last Logon   : $(if ($candidate.LastLogonDate) { $candidate.LastLogonDate.ToString('yyyy-MM-dd') } else { 'Never/Unknown' })" -ForegroundColor Gray
        Write-Host "  Description  : $($candidate.Description)" -ForegroundColor Gray
        Write-Host "  Flags        : $($flags -join ' | ')" -ForegroundColor Yellow
        Write-Host ""

        try {
            $approved = Invoke-HumanApproval `
                -Action    "Remove '$($candidate.SamAccountName)' from $($candidate.Group)" `
                -Target    "$($candidate.SamAccountName) ($($candidate.DN))" `
                -Milestone $ms `
                -RiskLevel $riskLevel `
                -Implications @(
                    "Account '$($candidate.SamAccountName)' will be REMOVED from $($candidate.Group).",
                    "They will lose all rights/access granted by $($candidate.Group) membership.",
                    "Flags on this account: $($flags -join '; ')",
                    "If this account runs services or scheduled tasks with DA rights, those WILL FAIL.",
                    "The account itself is NOT disabled or deleted -- only group membership is changed.",
                    "If this was a legitimate admin account, the admin will need to be re-added manually after review."
                ) `
                -RollbackSteps @(
                    "Add-ADGroupMember -Identity '$($candidate.Group)' -Members '$($candidate.SamAccountName)'",
                    "Verify the account can still perform its required tasks",
                    "Update the approved baseline after re-evaluation"
                )

            if ($approved) {
                try {
                    Remove-ADGroupMember -Identity $candidate.Group -Members $candidate.SamAccountName `
                        -Server $Domain -Confirm:$false
                    Write-Host "  [OK] Removed $($candidate.SamAccountName) from $($candidate.Group)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Removed from $($candidate.Group): $($candidate.DN)"
                    Add-Action -Action "RemoveFromPrivGroup" `
                               -Target "$($candidate.SamAccountName) from $($candidate.Group)" `
                               -Status "SUCCESS" `
                               -Detail "Flags: $($flags -join '; ')"
                } catch {
                    Write-Host "  [X] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    Add-Action -Action "RemoveFromPrivGroup" `
                               -Target "$($candidate.SamAccountName) from $($candidate.Group)" `
                               -Status "FAILED" `
                               -Detail $_.Exception.Message
                }
            }
        } catch {
            if ($_ -match "MILESTONE_QUIT") { break }
        }
    }

    $msActions = $Global:ActionLog | Where-Object Milestone -eq $ms
    Write-Host ""
    Write-Host "  M12 complete -- $($msActions.Count) membership change(s) applied" -ForegroundColor $(if($msActions.Count -gt 0){"Magenta"}else{"Green"})
    Write-AgentLog -Level INFO -Milestone $ms -Message "M12 complete. Changes: $($msActions.Count)"
}
