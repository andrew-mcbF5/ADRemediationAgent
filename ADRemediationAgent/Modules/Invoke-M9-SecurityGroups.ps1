#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 9 -- Security Group Cleanup

    Checks:
      1. Group Inventory  [Always]
         Full security group export: name, scope, category, member count,
         managed-by, mail-enabled flag. CSV export. INFO finding.

      2. Empty Security Groups  [Discover-only]
         Security groups with zero members. May be orphaned, unused, or
         in-progress builds. Flagged for owner review and manual removal.
         Well-known built-in empty groups are excluded.
         NIST: AC-2, IA-4

      3. Disabled Accounts in Security Groups  [Remediable: remove membership]
         Disabled users and computers that are still members of one or more
         security groups. Disabled accounts cannot authenticate; group
         membership is redundant and represents access policy clutter.
         Remediation: Remove-ADGroupMember (member from each group).
         CIS Control 5 (Account Management)
         NIST: AC-2, AC-3

      4. Privileged Group Membership Audit  [Discover-only]
         Membership audit of built-in privileged groups (Domain Admins,
         Enterprise Admins, Schema Admins, Administrators, Backup Operators,
         Account Operators, Print Operators, Server Operators,
         Group Policy Creator Owners, DnsAdmins). Flags:
         - Non-user objects (groups, computers) nested inside privileged groups
         - Total member count above threshold (10 for Tier 0)
         - Member accounts that are disabled
         NIST: AC-2, AC-6, IA-4

      5. Circular Group Nesting  [Discover-only]
         Groups where a nesting chain loops back to itself (A -> B -> A).
         Circular nesting causes unpredictable policy application and can
         cause Get-ADGroupMember -Recursive to hang. Windows DCs resolve
         circular nesting but it is always a configuration defect.
         NIST: AC-3, CM-6

      6. Large Universal Groups  [Discover-only]
         Universal groups with membership above a configurable threshold.
         Universal group membership is replicated to every Global Catalog
         server in the forest. Large universal groups increase GC replication
         traffic and startup latency on member machines.
         NIST: CM-6, SC-5

      7. AdminSDHolder Remnants  [Remediable: clear AdminCount]
         Accounts with AdminCount=1 that are no longer members of any
         protected group. SDProp sets AdminCount=1 and pins the ACL when an
         account joins a protected group. When removed from the group,
         AdminCount is NOT automatically cleared -- the object retains its
         restricted ACL indefinitely. Remediation: set AdminCount=0. Manual
         follow-up: re-enable permission inheritance via ADSI.
         NIST: AC-2, AC-6

      8. Mail-enabled Security Groups  [Discover-only]
         Security groups with a mail attribute or proxyAddresses set.
         Sending email to the group alias reveals its membership to anyone
         with send rights. Review whether these groups should be split into
         separate security and distribution groups.
         NIST: AC-3, SI-12

    Remediation scope:
      - Check 3: Remediable -- remove disabled account from group membership
      - Check 7: Remediable -- clear AdminCount attribute (operator approval)
      - All other checks: Discover-only

    Config keys used (AgentConfig.psd1):
      StaleUserDays     -- used to identify stale members (informational only)
      PrivilegedGroups  -- list of privileged group names to audit in check 4
#>

function Invoke-M9 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M9"

    # =========================================================================
    # Helpers
    # =========================================================================

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
        Write-AgentLog -Level FINDING -Milestone $ms `
            -Message "[$Severity] $FindingType -- $($ObjectDN): $Description" -Data $Data
    }

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M9 - Security Group Cleanup"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M9 : Security Group Cleanup" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # =========================================================================
    # Load config
    # =========================================================================
    $configPath = Join-Path $PSScriptRoot "..\Config\AgentConfig.psd1"
    $agentConfig = $null
    $staleUserDays       = 90
    $largeGroupThreshold = 500   # Universal group member count above this = flag
    $tier0MaxMembers     = 10    # DA/EA/SA above this count = flag

    $privilegedGroupNames = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Backup Operators", "Account Operators",
        "Print Operators", "Server Operators",
        "Group Policy Creator Owners", "DnsAdmins"
    )

    if (Test-Path $configPath) {
        $agentConfig = Import-PowerShellDataFile $configPath
        if ($null -ne $agentConfig -and $agentConfig.ContainsKey("StaleUserDays")) {
            $staleUserDays = [int]$agentConfig.StaleUserDays
        }
        if ($null -ne $agentConfig -and $agentConfig.ContainsKey("PrivilegedGroups") -and
                $agentConfig.PrivilegedGroups.Count -gt 0) {
            $privilegedGroupNames = @($agentConfig.PrivilegedGroups)
        }
    }

    # Well-known built-in groups that are legitimately empty (exclude from check 2)
    $knownEmptyBuiltins = @(
        "Cert Publishers", "RAS and IAS Servers", "Incoming Forest Trust Builders",
        "Windows Authorization Access Group", "Terminal Server License Servers",
        "Allowed RODC Password Replication Group",
        "Denied RODC Password Replication Group",
        "Cloneable Domain Controllers", "Protected Users",
        "Key Admins", "Enterprise Key Admins",
        "DnsUpdateProxy", "Read-only Domain Controllers",
        "Enterprise Read-only Domain Controllers"
    )

    # Protected groups used by AdminSDHolder (SDProp)
    $adminSDProtectedGroups = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Administrators", "Account Operators", "Backup Operators",
        "Print Operators", "Server Operators",
        "Domain Controllers", "Read-only Domain Controllers",
        "Group Policy Creator Owners", "Cryptographic Operators"
    )

    # Tier 0 groups (escalate to CRITICAL for these)
    $tier0Groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")

    # =========================================================================
    # CHECK 1: Group Inventory + CSV
    # =========================================================================
    Write-Host "  -> [1/8] Building security group inventory..." -ForegroundColor DarkCyan

    $allGroups = @()
    try {
        $allGroups = @(Get-ADGroup -Filter * -Server $Domain `
            -Properties Description, ManagedBy, GroupCategory, GroupScope,
                        mail, proxyAddresses, Members, AdminCount `
            -ErrorAction Stop)
        Write-Host "    Found $($allGroups.Count) group(s) in domain" -ForegroundColor Gray
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "GroupEnumerationFailed" `
            -Severity "CRITICAL" `
            -Description "Get-ADGroup -Filter * failed: $($_.Exception.Message)"
        Write-Host "  [!] Could not enumerate groups: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    $securityGroups = @($allGroups | Where-Object { $_.GroupCategory -eq "Security" })
    Write-Host "    $($securityGroups.Count) security group(s) found" -ForegroundColor Gray

    # Build inventory rows
    $inventoryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($grp in $allGroups) {
        $memberCount = 0
        if ($null -ne $grp.Members) { $memberCount = @($grp.Members).Count }
        $isMailEnabled = ($null -ne $grp.mail -and $grp.mail -ne "") -or
                         ($null -ne $grp.proxyAddresses -and @($grp.proxyAddresses).Count -gt 0)
        $inventoryRows.Add([PSCustomObject]@{
            Name         = $grp.Name
            DN           = $grp.DistinguishedName
            Category     = $grp.GroupCategory.ToString()
            Scope        = $grp.GroupScope.ToString()
            MemberCount  = $memberCount
            ManagedBy    = if ($null -ne $grp.ManagedBy) { $grp.ManagedBy } else { "" }
            Description  = if ($null -ne $grp.Description) { $grp.Description } else { "" }
            MailEnabled  = $isMailEnabled
            AdminCount   = if ($null -ne $grp.AdminCount) { $grp.AdminCount } else { 0 }
        })
    }

    $csvPath = "$OutputPath\Reports\M9-GroupInventory-$Global:RunTimestamp.csv"
    $inventoryRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "    Group inventory exported: $csvPath" -ForegroundColor Gray

    Add-Finding -ObjectDN $Domain -FindingType "SecurityGroupInventory" -Severity "INFO" `
        -Description "Group inventory: $($allGroups.Count) total, $($securityGroups.Count) security. Full CSV at $csvPath" `
        -CISControl "5" -NISTControl "AC-2, IA-4" `
        -Data @{ TotalGroups = $allGroups.Count; SecurityGroups = $securityGroups.Count; CSVPath = $csvPath }

    # =========================================================================
    # CHECK 2: Empty Security Groups
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [2/8] Empty security groups..." -ForegroundColor DarkCyan

    $emptyGroups = @($inventoryRows |
        Where-Object {
            $_.Category -eq "Security" -and
            $_.MemberCount -eq 0 -and
            $knownEmptyBuiltins -notcontains $_.Name
        })

    if ($emptyGroups.Count -eq 0) {
        Write-Host "    [OK] No unexpected empty security groups" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($emptyGroups.Count) empty security group(s) (excluding well-known built-ins)" `
            -ForegroundColor Yellow
        foreach ($row in $emptyGroups) {
            Write-Host "    Empty: $($row.Name) [$($row.Scope)]" -ForegroundColor Yellow
            Add-Finding -ObjectDN $row.DN -FindingType "EmptySecurityGroup" -Severity "LOW" `
                -Description "Security group '$($row.Name)' has no members. If unused, it should be removed after confirming it is not referenced in any ACL, GPO filter, or application config. Deletion cannot be automated safely as ACL references are not enumerable from AD alone." `
                -CISControl "5" -NISTControl "AC-2, IA-4" `
                -Data @{ Scope = $row.Scope; ManagedBy = $row.ManagedBy }
        }
    }

    # =========================================================================
    # CHECK 3: Disabled Accounts in Security Groups
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [3/8] Disabled accounts in security groups..." -ForegroundColor DarkCyan

    # Efficient approach: enumerate disabled accounts, check MemberOf
    $disabledUsers     = @(Get-ADUser     -Filter { Enabled -eq $false } -Server $Domain `
                               -Properties MemberOf, DisplayName -ErrorAction SilentlyContinue)
    $disabledComputers = @(Get-ADComputer -Filter { Enabled -eq $false } -Server $Domain `
                               -Properties MemberOf, Name -ErrorAction SilentlyContinue)

    # Build set of security group DNs for fast lookup
    $secGroupDNSet = @{}
    foreach ($sg in $securityGroups) { $secGroupDNSet[$sg.DistinguishedName] = $sg.Name }

    # Remediable: disabled accounts still in security groups
    $disabledMemberItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    $allDisabled = @($disabledUsers) + @($disabledComputers)
    foreach ($acct in $allDisabled) {
        if ($null -eq $acct.MemberOf) { continue }
        $secGroupMemberships = @($acct.MemberOf | Where-Object { $secGroupDNSet.ContainsKey($_) })
        if ($secGroupMemberships.Count -eq 0) { continue }

        $acctName = if ($acct.PSObject.Properties["DisplayName"] -and $acct.DisplayName) {
            $acct.DisplayName
        } else {
            $acct.Name
        }
        $groupNames = @($secGroupMemberships | ForEach-Object { $secGroupDNSet[$_] })
        $groupList  = $groupNames -join ", "

        Write-Host "    Disabled in $($secGroupMemberships.Count) group(s): $acctName" -ForegroundColor Yellow

        Add-Finding -ObjectDN $acct.DistinguishedName `
            -FindingType "DisabledAccountInSecurityGroup" -Severity "MEDIUM" `
            -Description "Disabled account '$acctName' is a member of $($secGroupMemberships.Count) security group(s): $groupList. Disabled accounts cannot authenticate; membership is access policy clutter. Recommend removing from all security groups." `
            -CISControl "5" -NISTControl "AC-2, AC-3" `
            -Data @{ AccountName = $acctName; GroupCount = $secGroupMemberships.Count; Groups = $groupNames }

        $disabledMemberItems.Add([PSCustomObject]@{
            AccountDN   = $acct.DistinguishedName
            AccountName = $acctName
            GroupDNs    = $secGroupMemberships
            GroupNames  = $groupNames
        })
    }

    if ($disabledMemberItems.Count -eq 0) {
        Write-Host "    [OK] No disabled accounts found in security groups" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($disabledMemberItems.Count) disabled account(s) still in security groups" `
            -ForegroundColor Yellow
    }

    # =========================================================================
    # CHECK 4: Privileged Group Membership Audit
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [4/8] Privileged group membership audit..." -ForegroundColor DarkCyan

    foreach ($groupName in $privilegedGroupNames) {
        try {
            $privGrp = Get-ADGroup -Identity $groupName -Server $Domain `
                           -Properties Members -ErrorAction Stop

            # Get direct members (not recursive -- we want to see nesting)
            $directMembers = @(Get-ADGroupMember -Identity $groupName -Server $Domain `
                                   -ErrorAction SilentlyContinue)

            $nestedGroups    = @($directMembers | Where-Object { $_.objectClass -eq "group" })
            $disabledMembers = @()
            $userMembers     = @($directMembers | Where-Object { $_.objectClass -eq "user" })

            # Check disabled user members
            foreach ($u in $userMembers) {
                try {
                    $uObj = Get-ADUser -Identity $u.DistinguishedName -Server $Domain `
                                -Properties Enabled -ErrorAction Stop
                    if (-not $uObj.Enabled) {
                        $disabledMembers += $u.SamAccountName
                    }
                } catch { }
            }

            $isTier0 = $tier0Groups -contains $groupName
            $maxMembers = if ($isTier0) { $tier0MaxMembers } else { 20 }

            Write-Host "    $groupName`: $($directMembers.Count) direct member(s), $($nestedGroups.Count) nested group(s)" `
                -ForegroundColor Gray

            # Flag nested groups (not themselves privileged groups)
            foreach ($nested in $nestedGroups) {
                $isPriv = $privilegedGroupNames -contains $nested.Name
                if (-not $isPriv) {
                    $sev = if ($isTier0) { "CRITICAL" } else { "HIGH" }
                    Add-Finding -ObjectDN $privGrp.DistinguishedName `
                        -FindingType "NonStandardGroupNestedInPrivilegedGroup" -Severity $sev `
                        -Description "Group '$($nested.Name)' is nested inside '$groupName'. All members of '$($nested.Name)' inherit $groupName privileges. This indirection obscures effective privilege and is a common persistence mechanism. Discover-only: review and remove nesting if not intentional." `
                        -CISControl "6" -CISLevel "1" -NISTControl "AC-2, AC-6" `
                        -Data @{ PrivilegedGroup = $groupName; NestedGroup = $nested.Name; NestedDN = $nested.DistinguishedName }
                    Write-Host "    [!] Nested group in $($groupName): $($nested.Name) [$sev]" -ForegroundColor $(if ($sev -eq "CRITICAL") { "Red" } else { "Yellow" })
                }
            }

            # Flag large membership
            if ($directMembers.Count -gt $maxMembers) {
                $sev = if ($isTier0) { "HIGH" } else { "MEDIUM" }
                Add-Finding -ObjectDN $privGrp.DistinguishedName `
                    -FindingType "PrivilegedGroupLargeMembership" -Severity $sev `
                    -Description "'$groupName' has $($directMembers.Count) direct members (threshold: $maxMembers). Large privileged group membership increases attack surface and violates least privilege. Review and reduce membership." `
                    -CISControl "6" -CISLevel "1" -NISTControl "AC-2, AC-6" `
                    -Data @{ GroupName = $groupName; MemberCount = $directMembers.Count; Threshold = $maxMembers }
                Write-Host "    [!] $groupName has $($directMembers.Count) members (threshold $maxMembers) [$sev]" `
                    -ForegroundColor Yellow
            }

            # Flag disabled members in privileged groups
            foreach ($sam in $disabledMembers) {
                Add-Finding -ObjectDN $privGrp.DistinguishedName `
                    -FindingType "DisabledAccountInPrivilegedGroup" -Severity "HIGH" `
                    -Description "Disabled account '$sam' is a direct member of privileged group '$groupName'. Disabled accounts should not hold privilege group membership. Remove from group." `
                    -CISControl "5" -CISLevel "1" -NISTControl "AC-2, AC-6" `
                    -Data @{ GroupName = $groupName; Account = $sam }
                Write-Host "    [!] Disabled account '$sam' in '$groupName' [HIGH]" -ForegroundColor Yellow
            }

        } catch [Microsoft.ActiveDirectory.Management.ADIdentityNotFoundException] {
            Write-Host "    Group '$groupName' not found in domain -- skipping" -ForegroundColor DarkGray
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "Could not audit '$($groupName)': $($_.Exception.Message)"
        }
    }

    # =========================================================================
    # CHECK 5: Circular Group Nesting
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [5/8] Circular group nesting detection..." -ForegroundColor DarkCyan

    # Build adjacency: DN -> list of member group DNs (direct only)
    $groupGraph = @{}
    $groupsByDN = @{}
    foreach ($grp in $allGroups) {
        $groupsByDN[$grp.DistinguishedName] = $grp.Name
    }

    Write-Host "    Building group nesting graph..." -ForegroundColor Gray
    $groupsWithNestedMembers = @($allGroups | Where-Object {
        $null -ne $_.Members -and @($_.Members).Count -gt 0
    })

    foreach ($grp in $groupsWithNestedMembers) {
        $memberGroupDNs = @($grp.Members | Where-Object { $groupsByDN.ContainsKey($_) })
        if ($memberGroupDNs.Count -gt 0) {
            $groupGraph[$grp.DistinguishedName] = $memberGroupDNs
        }
    }

    Write-Host "    Checking $($groupGraph.Count) group(s) with nested group members..." -ForegroundColor Gray

    $circularPairs = @{}   # Dedup: "A||B" -> $true

    foreach ($startDN in $groupGraph.Keys) {
        # Iterative DFS
        $stack   = [System.Collections.Generic.Stack[PSCustomObject]]::new()
        $visited = @{}

        $stack.Push([PSCustomObject]@{ DN = $startDN; Path = @($startDN) })

        while ($stack.Count -gt 0) {
            $current = $stack.Pop()
            $dn      = $current.DN
            $path    = $current.Path

            if ($visited.ContainsKey($dn)) { continue }
            $visited[$dn] = $true

            if (-not $groupGraph.ContainsKey($dn)) { continue }

            foreach ($childDN in $groupGraph[$dn]) {
                if ($childDN -eq $startDN) {
                    # Cycle found
                    $pairKey = ($startDN, $dn | Sort-Object) -join "||"
                    if (-not $circularPairs.ContainsKey($pairKey)) {
                        $circularPairs[$pairKey] = $true
                        $cyclePath = ($path + $childDN) | ForEach-Object {
                            if ($groupsByDN.ContainsKey($_)) { $groupsByDN[$_] } else { $_ }
                        }
                        $cycleStr = $cyclePath -join " -> "
                        Write-Host "    [!] Circular nesting: $cycleStr" -ForegroundColor Yellow
                        Add-Finding -ObjectDN $startDN `
                            -FindingType "CircularGroupNesting" -Severity "MEDIUM" `
                            -Description "Circular group nesting detected: $cycleStr. Windows resolves circular nesting internally but this is always a configuration defect. Get-ADGroupMember -Recursive will loop; some applications may hang or error. Manual review required to break the cycle." `
                            -NISTControl "AC-3, CM-6" `
                            -Data @{ CyclePath = $cyclePath }
                    }
                } elseif (-not $visited.ContainsKey($childDN)) {
                    $stack.Push([PSCustomObject]@{
                        DN   = $childDN
                        Path = $path + $childDN
                    })
                }
            }
        }
    }

    if ($circularPairs.Count -eq 0) {
        Write-Host "    [OK] No circular group nesting detected" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($circularPairs.Count) circular nesting pair(s) detected" -ForegroundColor Yellow
    }

    # =========================================================================
    # CHECK 6: Large Universal Groups
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [6/8] Large universal security groups..." -ForegroundColor DarkCyan

    $largeUniversals = @($inventoryRows |
        Where-Object {
            $_.Category -eq "Security" -and
            $_.Scope -eq "Universal" -and
            $_.MemberCount -gt $largeGroupThreshold
        })

    if ($largeUniversals.Count -eq 0) {
        Write-Host "    [OK] No universal security groups exceed $largeGroupThreshold members" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($largeUniversals.Count) large universal group(s) (> $largeGroupThreshold members)" `
            -ForegroundColor Yellow
        foreach ($row in $largeUniversals) {
            Write-Host "    Large Universal: $($row.Name) ($($row.MemberCount) members)" -ForegroundColor Yellow
            Add-Finding -ObjectDN $row.DN -FindingType "LargeUniversalGroup" -Severity "LOW" `
                -Description "Universal security group '$($row.Name)' has $($row.MemberCount) members (threshold: $largeGroupThreshold). Universal group membership is replicated to every Global Catalog server in the forest. Consider converting to Global scope if cross-domain access is not required, or splitting into smaller groups." `
                -NISTControl "CM-6, SC-5" `
                -Data @{ MemberCount = $row.MemberCount; Threshold = $largeGroupThreshold }
        }
    }

    # =========================================================================
    # CHECK 7: AdminSDHolder Remnants
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [7/8] AdminSDHolder remnants (AdminCount=1, not in protected groups)..." `
        -ForegroundColor DarkCyan

    # Build set of all accounts currently in any AdminSDHolder-protected group (recursive)
    $protectedDNs = @{}
    foreach ($pgName in $adminSDProtectedGroups) {
        try {
            $pgMembers = @(Get-ADGroupMember -Identity $pgName -Server $Domain -Recursive `
                               -ErrorAction SilentlyContinue)
            foreach ($m in $pgMembers) { $protectedDNs[$m.DistinguishedName] = $true }
        } catch { }
    }

    Write-Host "    $($protectedDNs.Count) account(s) currently in AdminSDHolder-protected groups" `
        -ForegroundColor Gray

    # Find all objects with AdminCount = 1
    $adminSDObjects = @(Get-ADObject -Filter { AdminCount -eq 1 } -Server $Domain `
                            -Properties AdminCount, ObjectClass, SamAccountName, DisplayName `
                            -ErrorAction SilentlyContinue)

    Write-Host "    $($adminSDObjects.Count) object(s) with AdminCount=1" -ForegroundColor Gray

    $remnantItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($obj in $adminSDObjects) {
        if ($protectedDNs.ContainsKey($obj.DistinguishedName)) { continue }
        # This object has AdminCount=1 but is NOT in any protected group -- it's a remnant

        $acctName = if ($null -ne $obj.DisplayName -and $obj.DisplayName -ne "") {
            $obj.DisplayName
        } elseif ($null -ne $obj.SamAccountName) {
            $obj.SamAccountName
        } else {
            $obj.Name
        }

        Write-Host "    Remnant: $acctName ($($obj.ObjectClass))" -ForegroundColor Yellow
        Add-Finding -ObjectDN $obj.DistinguishedName `
            -FindingType "AdminSDHolderRemnant" -Severity "MEDIUM" `
            -Description "Object '$acctName' ($($obj.ObjectClass)) has AdminCount=1 but is not currently a member of any AdminSDHolder-protected group. SDProp previously protected this account and pinned its ACL. Permission inheritance is blocked. The restricted ACL will persist until AdminCount is cleared and inheritance is manually re-enabled. Remediation: set AdminCount=0, then re-enable DACL inheritance via ADSI or dsacls." `
            -CISControl "5" -CISLevel "1" -NISTControl "AC-2, AC-6" `
            -Data @{ ObjectClass = $obj.ObjectClass; AccountName = $acctName }

        $remnantItems.Add([PSCustomObject]@{
            DN          = $obj.DistinguishedName
            AccountName = $acctName
            ObjectClass = $obj.ObjectClass
        })
    }

    if ($remnantItems.Count -eq 0) {
        Write-Host "    [OK] No AdminSDHolder remnants found" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($remnantItems.Count) AdminSDHolder remnant(s) with blocked inheritance" `
            -ForegroundColor Yellow
    }

    # =========================================================================
    # CHECK 8: Mail-enabled Security Groups
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [8/8] Mail-enabled security groups..." -ForegroundColor DarkCyan

    $mailEnabledSec = @($inventoryRows | Where-Object {
        $_.Category -eq "Security" -and $_.MailEnabled
    })

    if ($mailEnabledSec.Count -eq 0) {
        Write-Host "    [OK] No mail-enabled security groups found" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($mailEnabledSec.Count) mail-enabled security group(s)" -ForegroundColor Yellow
        foreach ($row in $mailEnabledSec) {
            Write-Host "    Mail+Security: $($row.Name)" -ForegroundColor Yellow
            Add-Finding -ObjectDN $row.DN -FindingType "MailEnabledSecurityGroup" -Severity "LOW" `
                -Description "Security group '$($row.Name)' is mail-enabled. Email distribution to this alias will reach all members; anyone who can send to the alias can infer its membership. Review whether the security and distribution functions should be split into separate objects, or whether the mail alias should be removed." `
                -NISTControl "AC-3, SI-12" `
                -Data @{ Scope = $row.Scope; MemberCount = $row.MemberCount }
        }
    }

    # =========================================================================
    # Remediation Phase
    # =========================================================================
    if ($Mode -ne "Remediate") {
        $msFindings = @($Global:FindingsList |
            Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
        Write-Host ""
        Write-Host "  M9 complete -- $($msFindings.Count) actionable finding(s)" `
            -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "M9 complete (Discover). Actionable findings: $($msFindings.Count)"
        return
    }

    $totalRemediable = $disabledMemberItems.Count + $remnantItems.Count
    if ($totalRemediable -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No remediable items found." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "M9 Remediate: no remediable items"
        return
    }

    Write-Host ""
    Write-Host "  --- Remediation Phase: $totalRemediable item(s) ---" -ForegroundColor Cyan
    Write-Host "  Checks 2, 4-6, 8 are Discover-only. Processing checks 3 and 7." -ForegroundColor DarkYellow
    Write-Host ""

    try {

        # -- Check 3: Remove disabled accounts from security groups ----------
        if ($disabledMemberItems.Count -gt 0) {
            Write-Host "  --- Disabled Accounts in Security Groups ($($disabledMemberItems.Count) account(s)) ---" `
                -ForegroundColor White

            foreach ($item in $disabledMemberItems) {
                $groupListStr = $item.GroupNames -join ", "

                $approved = Invoke-HumanApproval `
                    -Action    "Remove disabled account from all security groups" `
                    -Target    "$($item.AccountName) ($($item.GroupDNs.Count) group(s))" `
                    -Implications @(
                        "Disabled account '$($item.AccountName)' will be removed from: $groupListStr",
                        "The account is already disabled -- no live authentication impact.",
                        "If the account is ever re-enabled, group memberships will need to be re-added manually.",
                        "This operation cannot be automatically rolled back -- document before proceeding."
                    ) `
                    -RollbackSteps @(
                        "Re-enable the account: Enable-ADAccount -Identity '$($item.AccountDN)'",
                        "Then re-add to required groups: Add-ADGroupMember -Identity <GroupName> -Members '$($item.AccountDN)'"
                    ) `
                    -RiskLevel "MEDIUM" `
                    -Milestone $ms

                if (-not $approved) { continue }

                $successCount = 0
                foreach ($groupDN in $item.GroupDNs) {
                    try {
                        Remove-ADGroupMember -Identity $groupDN -Members $item.AccountDN `
                            -Server $Domain -Confirm:$false -ErrorAction Stop
                        $successCount++
                    } catch {
                        Write-Host "  [!] Failed removing '$($item.AccountName)' from '$groupDN': $($_.Exception.Message)" `
                            -ForegroundColor Red
                        Write-AgentLog -Level WARN -Milestone $ms `
                            -Message "Failed to remove '$($item.AccountName)' from '$groupDN': $($_.Exception.Message)"
                    }
                }

                if ($successCount -gt 0) {
                    Write-Host "  [OK] Removed '$($item.AccountName)' from $successCount group(s)" `
                        -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Removed disabled account '$($item.AccountName)' from $successCount security group(s)"
                }
            }
        }

        # -- Check 7: Clear AdminCount on remnant objects --------------------
        if ($remnantItems.Count -gt 0) {
            Write-Host ""
            Write-Host "  --- AdminSDHolder Remnants ($($remnantItems.Count) object(s)) ---" -ForegroundColor White
            Write-Host "  NOTE: Clearing AdminCount does NOT automatically restore permission inheritance." `
                -ForegroundColor DarkYellow
            Write-Host "  After clearing AdminCount, manually re-enable inheritance with:" -ForegroundColor DarkYellow
            Write-Host "    dsacls ""<ObjectDN>"" /I:T /P:Y  (enable propagation)" -ForegroundColor DarkGray
            Write-Host ""

            foreach ($item in $remnantItems) {
                $approved = Invoke-HumanApproval `
                    -Action    "Clear AdminCount on AdminSDHolder remnant" `
                    -Target    "$($item.AccountName) ($($item.ObjectClass))" `
                    -Implications @(
                        "AdminCount attribute on '$($item.AccountName)' will be set to 0.",
                        "This stops SDProp from re-pinning the ACL on future runs.",
                        "Permission inheritance is still BLOCKED after this change.",
                        "Manual step required: re-enable DACL inheritance via ADSI or dsacls.",
                        "Command: dsacls '$($item.DN)' /I:T /P:Y"
                    ) `
                    -RollbackSteps @(
                        "Set-ADObject -Identity '$($item.DN)' -Replace @{adminCount = 1}"
                    ) `
                    -RiskLevel "MEDIUM" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Set-ADObject -Identity $item.DN -Replace @{ adminCount = 0 } `
                        -Server $Domain -ErrorAction Stop
                    Write-Host "  [OK] Cleared AdminCount on '$($item.AccountName)'" -ForegroundColor Green
                    Write-Host "  [!]  MANUAL: Re-enable inheritance on this object via dsacls or ADSI." `
                        -ForegroundColor DarkYellow
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Cleared AdminCount on AdminSDHolder remnant '$($item.AccountName)' ($($item.DN))"
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "MANUAL FOLLOW-UP: Re-enable DACL inheritance on '$($item.DN)' via dsacls."
                } catch {
                    Write-Host "  [!] Failed on '$($item.AccountName)': $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to clear AdminCount on '$($item.AccountName)': $($_.Exception.Message)"
                }
            }
        }

    } catch {
        if ($_.Exception.Message -eq "MILESTONE_QUIT") {
            Write-Host "  [!] M9 remediation stopped by operator." -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "M9 remediation quit by operator"
        } else {
            throw
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList |
        Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M9 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "M9 complete. Actionable findings: $($msFindings.Count)"
}
