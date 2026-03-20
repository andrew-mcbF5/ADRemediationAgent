#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 3 -- OU Structure Cleanup

    Checks:
      1. OU Inventory  [Always]
         Full OU list with depth, direct GPO link flag, block-inheritance flag,
         user/computer/child-OU counts, protection status, and managed-by.
         CSV export. INFO finding.
         NIST: CM-8

      2. Default Container Usage  [Discover-only]
         User and computer objects found in CN=Computers or CN=Users default
         containers instead of purpose-built OUs. Objects in default containers
         receive only domain-root GPOs and bypass all OU-scoped policy.
         NIST: CM-8, AC-2

      3. Empty OUs  [Discover-only]
         OUs with zero user, computer, and child OU objects. Candidates for
         removal after confirming no ACL delegations, GPO links, or application
         configuration references exist.
         NIST: CM-8

      4. Block Inheritance OUs  [Discover-only]
         OUs with gPOptions bit 0 set (block inheritance). Blocking inheritance
         creates GPO gaps -- security hardening policies linked at the domain
         root or parent OUs will not apply to objects in these OUs.
         NIST: CM-6, CM-3

      5. Policy Gap OUs  [Discover-only]
         Populated OUs (user/computer count > 0) with block inheritance enabled
         AND no directly linked GPOs. These objects may be receiving no Group
         Policy at all. Escalated to HIGH.
         NIST: CM-6

      6. Deep OU Nesting  [Discover-only]
         OUs more than 5 levels deep. Deeply nested OUs make GPO inheritance
         troubleshooting difficult and increase the risk of block-inheritance
         gaps being missed.
         NIST: CM-6, CM-8

      7. Non-Standard OU Delegation  [Discover-only]
         OUs with non-inherited Allow ACEs granting GenericAll, WriteDacl,
         WriteOwner, or GenericWrite to principals other than Domain Admins,
         Enterprise Admins, SYSTEM, Authenticated Users, Account Operators,
         or NT AUTHORITY. These ACEs can be used to create privileged objects
         or modify GPO links within the OU scope.
         NIST: AC-3, AC-6

    All checks are Discover-only. OU restructuring has a high blast radius --
    OU path changes break existing GPO links and membership-by-location
    assumptions. Review findings with the AD team and plan changes via the
    normal change management process before acting.

    CIS Control mapping:
      CIS Control 1 (Inventory and Control of Enterprise Assets)

    NIST Controls:
      CM-8, AC-2, AC-6, CM-6, CM-3, AC-3
#>

function Invoke-M3 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M3"

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

    function Get-ParentDN {
        param([string]$DistinguishedName)
        $idx = $DistinguishedName.IndexOf(",")
        if ($idx -ge 0) { return $DistinguishedName.Substring($idx + 1) }
        return ""
    }

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M3 - OU Structure Cleanup"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M3 : OU Structure Cleanup" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""
    Write-Host "  NOTE: All checks are Discover-only. OU changes carry high blast" -ForegroundColor DarkYellow
    Write-Host "        radius and must be planned with the AD team before acting." -ForegroundColor DarkYellow
    Write-Host ""

    # =========================================================================
    # Domain info
    # =========================================================================
    $domainObj = $null
    $domainDN  = ""
    try {
        $domainObj = Get-ADDomain -Identity $Domain -ErrorAction Stop
        $domainDN  = $domainObj.DistinguishedName
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "DomainQueryFailed" -Severity "CRITICAL" `
            -Description "Get-ADDomain failed: $($_.Exception.Message)"
        Write-Host "  [!] Cannot query domain: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # =========================================================================
    # CHECK 1: OU Inventory
    # =========================================================================
    Write-Host "  -> [1/7] Building OU inventory..." -ForegroundColor DarkCyan

    $allOUs = @()
    try {
        $allOUs = @(Get-ADOrganizationalUnit -Filter * -Server $Domain `
            -Properties Description, ManagedBy, ProtectedFromAccidentalDeletion, GPLink, gPOptions `
            -ErrorAction Stop)
        Write-Host "    Found $($allOUs.Count) OU(s) in domain" -ForegroundColor Gray
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "OUEnumerationFailed" -Severity "CRITICAL" `
            -Description "Get-ADOrganizationalUnit failed: $($_.Exception.Message)"
        Write-Host "  [!] Could not enumerate OUs: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Build depth map: count OU= segments in DN
    $ouDepthMap = @{}
    foreach ($ou in $allOUs) {
        $depth = ([regex]::Matches($ou.DistinguishedName, 'OU=')).Count
        $ouDepthMap[$ou.DistinguishedName] = $depth
    }

    # Build efficient object-count maps via single queries per type
    Write-Host "    Building object-count maps (users, computers, child OUs)..." -ForegroundColor Gray

    $userParentCounts = @{}
    try {
        $allUsers = @(Get-ADUser -Filter * -Server $Domain -Properties DistinguishedName `
            -ErrorAction SilentlyContinue)
        foreach ($u in $allUsers) {
            $pdn = Get-ParentDN $u.DistinguishedName
            if (-not $userParentCounts.ContainsKey($pdn)) { $userParentCounts[$pdn] = 0 }
            $userParentCounts[$pdn]++
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "User enumeration failed: $($_.Exception.Message)"
    }

    $compParentCounts = @{}
    try {
        $allComputers = @(Get-ADComputer -Filter * -Server $Domain -Properties DistinguishedName `
            -ErrorAction SilentlyContinue)
        foreach ($c in $allComputers) {
            $pdn = Get-ParentDN $c.DistinguishedName
            if (-not $compParentCounts.ContainsKey($pdn)) { $compParentCounts[$pdn] = 0 }
            $compParentCounts[$pdn]++
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "Computer enumeration failed: $($_.Exception.Message)"
    }

    $childOUCounts = @{}
    foreach ($ou in $allOUs) {
        $pdn = Get-ParentDN $ou.DistinguishedName
        if (-not $childOUCounts.ContainsKey($pdn)) { $childOUCounts[$pdn] = 0 }
        $childOUCounts[$pdn]++
    }

    # Build inventory rows
    $inventoryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($ou in $allOUs) {
        $dn         = $ou.DistinguishedName
        $depth      = $ouDepthMap[$dn]
        $userCnt    = if ($userParentCounts.ContainsKey($dn))  { $userParentCounts[$dn]  } else { 0 }
        $compCnt    = if ($compParentCounts.ContainsKey($dn))  { $compParentCounts[$dn]  } else { 0 }
        $childCnt   = if ($childOUCounts.ContainsKey($dn))     { $childOUCounts[$dn]     } else { 0 }
        $hasGPLink  = ($null -ne $ou.GPLink -and $ou.GPLink -ne "")
        # gPOptions bit 0 = block inheritance
        $blockInher = ($null -ne $ou.gPOptions -and ($ou.gPOptions -band 1) -ne 0)

        $inventoryRows.Add([PSCustomObject]@{
            Name             = $ou.Name
            DN               = $dn
            Depth            = $depth
            UserCount        = $userCnt
            ComputerCount    = $compCnt
            ChildOUCount     = $childCnt
            HasDirectGPLink  = $hasGPLink
            BlockInheritance = $blockInher
            Protected        = $ou.ProtectedFromAccidentalDeletion
            ManagedBy        = if ($null -ne $ou.ManagedBy)     { $ou.ManagedBy }     else { "" }
            Description      = if ($null -ne $ou.Description)   { $ou.Description }   else { "" }
        })
    }

    $csvPath = "$OutputPath\Reports\M3-OUInventory-$Global:RunTimestamp.csv"
    $inventoryRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "    OU inventory exported: $csvPath" -ForegroundColor Gray

    Add-Finding -ObjectDN $Domain -FindingType "OUInventory" -Severity "INFO" `
        -Description "OU inventory: $($allOUs.Count) OU(s) in domain. Full CSV at $csvPath" `
        -CISControl "1" -NISTControl "CM-8" `
        -Data @{ TotalOUs = $allOUs.Count; CSVPath = $csvPath }

    # =========================================================================
    # CHECK 2: Default Container Usage
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [2/7] Default container usage (CN=Computers, CN=Users)..." -ForegroundColor DarkCyan

    $builtinExclusions = @(
        "krbtgt", "Guest", "Administrator", "DefaultAccount", "WDAGUtilityAccount"
    )

    $totalMisplaced = 0
    foreach ($container in @(
        [PSCustomObject]@{ DN = "CN=Computers,$domainDN"; Label = "CN=Computers" },
        [PSCustomObject]@{ DN = "CN=Users,$domainDN";     Label = "CN=Users" }
    )) {
        $objectsInContainer = @()
        try {
            $objectsInContainer = @(Get-ADObject -SearchBase $container.DN -SearchScope OneLevel `
                -Filter { ObjectClass -eq "user" -or ObjectClass -eq "computer" } `
                -Server $Domain `
                -Properties ObjectClass, SamAccountName, DisplayName, Enabled `
                -ErrorAction SilentlyContinue)
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "Could not query $($container.Label): $($_.Exception.Message)"
            continue
        }

        # Strip built-in accounts that legitimately live here
        $objectsInContainer = @($objectsInContainer | Where-Object {
            $null -ne $_.SamAccountName -and $builtinExclusions -notcontains $_.SamAccountName
        })

        if ($objectsInContainer.Count -eq 0) {
            Write-Host "    [OK] $($container.Label): no user/computer objects" -ForegroundColor Green
        } else {
            $totalMisplaced += $objectsInContainer.Count
            Write-Host "    [!] $($container.Label): $($objectsInContainer.Count) object(s) found" `
                -ForegroundColor Yellow

            foreach ($obj in $objectsInContainer) {
                $displayName = if ($null -ne $obj.DisplayName -and $obj.DisplayName -ne "") {
                    $obj.DisplayName
                } else {
                    $obj.SamAccountName
                }
                Write-Host "    $($obj.ObjectClass): $displayName" -ForegroundColor Yellow

                Add-Finding -ObjectDN $obj.DistinguishedName `
                    -FindingType "ObjectInDefaultContainer" -Severity "MEDIUM" `
                    -Description "$($obj.ObjectClass) '$displayName' is in the $($container.Label) default container. Objects here receive only domain-root GPOs and bypass all OU-scoped policy. Move to a purpose-built OU that applies the appropriate Group Policy." `
                    -CISControl "1" -NISTControl "CM-8, AC-2" `
                    -Data @{ Container = $container.Label; ObjectClass = $obj.ObjectClass; SamAccountName = $obj.SamAccountName }
            }
        }
    }

    if ($totalMisplaced -eq 0) {
        Write-AgentLog -Level INFO -Milestone $ms -Message "Default container check: no misplaced objects"
    }

    # =========================================================================
    # CHECK 3: Empty OUs
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [3/7] Empty OUs (no users, computers, or child OUs)..." -ForegroundColor DarkCyan

    $emptyOUs = @($inventoryRows | Where-Object {
        $_.UserCount -eq 0 -and $_.ComputerCount -eq 0 -and $_.ChildOUCount -eq 0
    })

    if ($emptyOUs.Count -eq 0) {
        Write-Host "    [OK] No empty OUs found" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($emptyOUs.Count) empty OU(s) (no users, computers, or child OUs)" `
            -ForegroundColor Yellow

        foreach ($row in $emptyOUs) {
            Write-Host "    Empty: $($row.Name)  [Depth=$($row.Depth)  Protected=$($row.Protected)  GPLink=$($row.HasDirectGPLink)]" `
                -ForegroundColor Yellow

            Add-Finding -ObjectDN $row.DN -FindingType "EmptyOU" -Severity "LOW" `
                -Description "OU '$($row.Name)' has no user, computer, or child OU objects. If unused, remove after confirming it holds no ACL delegations, GPO links, or application configuration references. Protected=$($row.Protected), HasDirectGPLink=$($row.HasDirectGPLink)." `
                -CISControl "1" -NISTControl "CM-8" `
                -Data @{ Depth = $row.Depth; Protected = $row.Protected; HasDirectGPLink = $row.HasDirectGPLink }
        }
    }

    # =========================================================================
    # CHECK 4: Block Inheritance OUs
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [4/7] Block inheritance OUs..." -ForegroundColor DarkCyan

    $blockOUs = @($inventoryRows | Where-Object { $_.BlockInheritance })

    if ($blockOUs.Count -eq 0) {
        Write-Host "    [OK] No OUs with block inheritance set" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($blockOUs.Count) OU(s) with block inheritance" -ForegroundColor Yellow

        foreach ($row in $blockOUs) {
            Write-Host "    Block-Inheritance: $($row.Name)  [Depth=$($row.Depth)  Users=$($row.UserCount)  Computers=$($row.ComputerCount)  GPLink=$($row.HasDirectGPLink)]" `
                -ForegroundColor Yellow

            Add-Finding -ObjectDN $row.DN -FindingType "OUBlockInheritance" -Severity "MEDIUM" `
                -Description "OU '$($row.Name)' has block inheritance enabled. Security hardening GPOs linked at the domain root or parent OUs will NOT apply here. Verify this is intentional and all required security policies are directly linked to this OU or its children." `
                -CISControl "1" -NISTControl "CM-6, CM-3" `
                -Data @{ Depth = $row.Depth; UserCount = $row.UserCount; ComputerCount = $row.ComputerCount; HasDirectGPLink = $row.HasDirectGPLink }
        }
    }

    # =========================================================================
    # CHECK 5: Policy Gap OUs (block inheritance + no direct GPO link + populated)
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [5/7] Policy gap OUs (block inheritance AND no direct GPO link)..." `
        -ForegroundColor DarkCyan

    $policyGapOUs = @($inventoryRows | Where-Object {
        $_.BlockInheritance -and
        -not $_.HasDirectGPLink -and
        ($_.UserCount -gt 0 -or $_.ComputerCount -gt 0)
    })

    if ($policyGapOUs.Count -eq 0) {
        Write-Host "    [OK] No policy gap OUs detected" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($policyGapOUs.Count) populated OU(s) with block inheritance AND no direct GPO link -- potential policy gap" `
            -ForegroundColor Red

        foreach ($row in $policyGapOUs) {
            Write-Host "    POLICY GAP: $($row.Name)  [Users=$($row.UserCount)  Computers=$($row.ComputerCount)]" `
                -ForegroundColor Red

            Add-Finding -ObjectDN $row.DN -FindingType "OUPolicyGap" -Severity "HIGH" `
                -Description "OU '$($row.Name)' contains $($row.UserCount) user(s) and $($row.ComputerCount) computer(s) with block inheritance enabled AND no directly linked GPOs. Objects in this OU may be receiving no Group Policy at all -- security hardening policies will not apply. Review and link required GPOs immediately." `
                -CISControl "1" -NISTControl "CM-6" `
                -Data @{ UserCount = $row.UserCount; ComputerCount = $row.ComputerCount; Depth = $row.Depth }
        }
    }

    # =========================================================================
    # CHECK 6: Deep OU Nesting (> 5 levels)
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [6/7] Deep OU nesting (depth > 5)..." -ForegroundColor DarkCyan

    $deepOUs = @($inventoryRows | Where-Object { $_.Depth -gt 5 })

    if ($deepOUs.Count -eq 0) {
        Write-Host "    [OK] No OUs deeper than 5 levels" -ForegroundColor Green
    } else {
        $maxDepth = ($deepOUs | Measure-Object -Property Depth -Maximum).Maximum
        Write-Host "    [!] $($deepOUs.Count) OU(s) deeper than 5 levels (max depth: $maxDepth)" `
            -ForegroundColor Yellow

        foreach ($row in ($deepOUs | Sort-Object -Property Depth -Descending)) {
            Write-Host "    Depth $($row.Depth): $($row.Name)" -ForegroundColor Yellow

            Add-Finding -ObjectDN $row.DN -FindingType "DeepOUNesting" -Severity "LOW" `
                -Description "OU '$($row.Name)' is $($row.Depth) levels deep. Deep nesting makes GPO inheritance troubleshooting difficult and increases the chance of block-inheritance gaps being missed during future changes. Review whether the hierarchy can be flattened." `
                -CISControl "1" -NISTControl "CM-6, CM-8" `
                -Data @{ Depth = $row.Depth; UserCount = $row.UserCount; ComputerCount = $row.ComputerCount }
        }
    }

    # =========================================================================
    # CHECK 7: Non-Standard OU Delegation (ACE audit via AD: PSDrive)
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [7/7] Non-standard OU delegation (ACE audit)..." -ForegroundColor DarkCyan

    $adDriveAvailable = $null -ne (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)

    if (-not $adDriveAvailable) {
        Write-Host "    [SKIP] AD: PSDrive not available for ACL enumeration" -ForegroundColor Yellow
        Add-Finding -ObjectDN $Domain -FindingType "ADDriveUnavailable" -Severity "LOW" `
            -Description "The AD: PSDrive is not available -- OU delegation ACE audit (check 7) was skipped. Ensure the ActiveDirectory module is loaded and the AD: drive is accessible." `
            -NISTControl "AC-3, AC-6"
    } else {
        # Standard principals -- any principal matching these patterns is considered expected
        $standardPrincipals = @(
            "Domain Admins", "Enterprise Admins", "SYSTEM",
            "Authenticated Users", "NT AUTHORITY",
            "ENTERPRISE DOMAIN CONTROLLERS", "CREATOR OWNER",
            "Account Operators", "Administrators"
        )

        # Rights that represent meaningful delegation risk
        $dangerousRightsPattern = "GenericAll|WriteDacl|WriteOwner|GenericWrite"

        $delegationFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

        if ($allOUs.Count -gt 200) {
            Write-Host "    [!] $($allOUs.Count) OUs to scan -- ACL audit may take several minutes" `
                -ForegroundColor DarkYellow
        } else {
            Write-Host "    Auditing ACLs on $($allOUs.Count) OU(s)..." -ForegroundColor Gray
        }

        foreach ($ou in $allOUs) {
            try {
                $acl = Get-Acl -Path "AD:\$($ou.DistinguishedName)" -ErrorAction SilentlyContinue
                if ($null -eq $acl) { continue }

                foreach ($ace in $acl.Access) {
                    # Non-inherited, Allow ACEs only
                    if ($ace.IsInherited) { continue }
                    if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

                    $rightsStr = $ace.ActiveDirectoryRights.ToString()
                    if ($rightsStr -notmatch $dangerousRightsPattern) { continue }

                    $principal = $ace.IdentityReference.Value

                    $isStandard = $false
                    foreach ($std in $standardPrincipals) {
                        if ($principal -like "*$std*") { $isStandard = $true; break }
                    }
                    if ($isStandard) { continue }

                    $sev = if ($rightsStr -match "GenericAll|WriteDacl|WriteOwner") { "HIGH" } else { "MEDIUM" }

                    $delegationFindings.Add([PSCustomObject]@{
                        OUName    = $ou.Name
                        OUDN      = $ou.DistinguishedName
                        Principal = $principal
                        Rights    = $rightsStr
                        Severity  = $sev
                    })

                    Add-Finding -ObjectDN $ou.DistinguishedName `
                        -FindingType "NonStandardOUDelegation" -Severity $sev `
                        -Description "OU '$($ou.Name)' has a non-inherited Allow ACE granting '$rightsStr' to '$principal'. This is a non-standard delegation that could be used to create privileged objects, modify GPO links, or take ownership of objects in this OU scope. Verify it is intentional and documented." `
                        -CISControl "1" -NISTControl "AC-3, AC-6" `
                        -Data @{ Principal = $principal; Rights = $rightsStr; Severity = $sev }

                    Write-Host "    [$sev] Non-standard ACE: $($ou.Name) -- $principal ($rightsStr)" `
                        -ForegroundColor $(if ($sev -eq "HIGH") { "Red" } else { "Yellow" })
                }
            } catch {
                # Silently skip OUs where ACL read fails (permission or ADSI error)
            }
        }

        if ($delegationFindings.Count -eq 0) {
            Write-Host "    [OK] No non-standard OU delegation ACEs found" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "OU ACE audit: no non-standard delegation found"
        } else {
            Write-Host "    [!] $($delegationFindings.Count) non-standard delegation ACE(s) found" `
                -ForegroundColor Yellow

            $delCsvPath = "$OutputPath\Reports\M3-OUDelegation-$Global:RunTimestamp.csv"
            $delegationFindings | Export-Csv -Path $delCsvPath -NoTypeInformation -Encoding UTF8
            Write-Host "    Delegation report exported: $delCsvPath" -ForegroundColor Gray
            Write-AgentLog -Level INFO -Milestone $ms `
                -Message "OU ACE audit: $($delegationFindings.Count) non-standard ACE(s). CSV: $delCsvPath"
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })

    Write-Host ""
    if ($Mode -eq "Remediate") {
        Write-Host "  [M3] NOTE: M3 is Discover-only. OU restructuring requires AD team review and" `
            -ForegroundColor DarkYellow
        Write-Host "       change management approval before any objects are moved or deleted." `
            -ForegroundColor DarkYellow
    }
    Write-Host "  M3 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "M3 complete (Discover-only). Actionable findings: $($msFindings.Count)"
}
