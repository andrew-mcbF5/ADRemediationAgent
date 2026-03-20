#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 8 -- GPO Cleanup

    Prerequisite: GroupPolicy PowerShell module (RSAT-Group-Policy or run on a DC).

    Checks:
      1. GPO Inventory  [Always]
         Full GPO list with status, versions, link count, and backup path.
         CSV export. INFO finding. Backup-GPO -All runs at start of Remediate.

      2. Unlinked GPOs  [Remediable: disable all settings]
         GPOs with zero links to any OU, domain root, or site.
         Disabling (not deleting) is the safe first step -- links may be
         in-progress or intentionally held in reserve.
         NIST: CM-6, CM-7

      3. All-Settings-Disabled GPOs  [Remediable: delete]
         GPOs where GpoStatus = AllSettingsDisabled. Already fully disabled;
         safe to remove after backup.
         NIST: CM-6, CM-7

      4. Empty GPOs (version 0/0)  [Remediable: delete]
         GPOs where both Computer.DSVersion and User.DSVersion = 0,
         confirmed by XML report (no ExtensionData). Never configured;
         safe to remove.
         NIST: CM-6

      5. Default Domain Policy and DDCP Modification Check  [Discover-only]
         Flags if DDP or Default Domain Controllers Policy contain
         unexpected settings. CIS guidance: use separate GPOs for custom
         settings to protect defaults from dcgpofix wiping.
         NIST: CM-3, SI-7

      6. SYSVOL Orphan Detection  [Discover-only]
         AD GPO objects with no corresponding SYSVOL folder, and SYSVOL
         GPO folders with no corresponding AD object.
         NIST: SI-7, CM-3

      7. Disabled GPO Links  [Discover-only]
         GPO links where LinkEnabled = $false. Active clutter -- candidate
         for cleanup after owner review.
         NIST: CM-6

      8. GPO Delegation Audit  [Discover-only]
         Non-standard Edit/Modify-Security permissions on GPOs.
         Standard: Domain Admins, Enterprise Admins, SYSTEM (Edit);
         Authenticated Users (Apply Group Policy, read-only).
         NIST: CM-3, AC-6

    Remediation scope:
      - Backup-GPO -All runs before any changes in Remediate mode.
      - Checks 2-4 are remediable with operator approval.
      - Checks 5-8 are Discover-only.
#>

function Invoke-M8 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M8"

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

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M8 - GPO Cleanup"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M8 : GPO Cleanup" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # =========================================================================
    # Prerequisite: GroupPolicy module
    # =========================================================================
    if (-not (Get-Module -Name GroupPolicy -ListAvailable)) {
        Add-Finding -ObjectDN $Domain -FindingType "GroupPolicyModuleMissing" -Severity "HIGH" `
            -Description "The GroupPolicy PowerShell module is not available on this machine. M8 requires RSAT-Group-Policy (workstation) or run from a Domain Controller. Install: Add-WindowsFeature GPMC (server) or install RSAT via Settings > Optional Features." `
            -NISTControl "CM-6"
        Write-Host "  [!] GroupPolicy module not available -- M8 cannot run on this machine." -ForegroundColor Red
        return
    }
    Import-Module GroupPolicy -ErrorAction SilentlyContinue

    # Well-known GPO GUIDs
    $ddpGuid  = "{31B2F340-016D-11D2-945F-00C04FB984F9}"   # Default Domain Policy
    $ddcpGuid = "{6AC1786C-016F-11D2-945F-00C04FB984F9}"   # Default Domain Controllers Policy

    # Remediable item lists
    $unlinkedItems  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $disabledItems  = [System.Collections.Generic.List[PSCustomObject]]::new()
    $emptyItems     = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # CHECK 1: GPO Inventory + build linked-GUID set
    # =========================================================================
    Write-Host "  -> [1/8] Building GPO inventory and scanning links..." -ForegroundColor DarkCyan

    $allGPOs = @()
    try {
        $allGPOs = @(Get-GPO -All -Domain $Domain)
        Write-Host "    Found $($allGPOs.Count) GPO(s) in domain" -ForegroundColor Gray
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "GPOInventoryFailed" -Severity "CRITICAL" `
            -Description "Get-GPO -All failed: $($_.Exception.Message)"
        Write-Host "  [!] Could not enumerate GPOs: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # Build the set of linked GPO GUIDs by scanning all OUs and domain root
    $linkedGuids  = @{}
    $disabledLinks = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $domainObj = Get-ADDomain -Identity $Domain
        $domainDN  = $domainObj.DistinguishedName

        # Domain root
        $domInheritance = Get-GPInheritance -Target $domainDN -Domain $Domain -ErrorAction SilentlyContinue
        if ($domInheritance) {
            foreach ($link in $domInheritance.GpoLinks) {
                $guid = $link.GpoId.ToString().ToUpper()
                if (-not $linkedGuids.ContainsKey($guid)) { $linkedGuids[$guid] = 0 }
                $linkedGuids[$guid]++
                if (-not $link.Enabled) {
                    $disabledLinks.Add([PSCustomObject]@{
                        GPOId    = $guid
                        GPOName  = $link.DisplayName
                        Target   = $domainDN
                    })
                }
            }
        }

        # All OUs
        $allOUs = @(Get-ADOrganizationalUnit -Filter * -Server $Domain)
        Write-Host "    Scanning links across $($allOUs.Count) OU(s)..." -ForegroundColor Gray

        foreach ($ou in $allOUs) {
            try {
                $ouInheritance = Get-GPInheritance -Target $ou.DistinguishedName -Domain $Domain `
                    -ErrorAction SilentlyContinue
                if ($null -eq $ouInheritance) { continue }
                foreach ($link in $ouInheritance.GpoLinks) {
                    $guid = $link.GpoId.ToString().ToUpper()
                    if (-not $linkedGuids.ContainsKey($guid)) { $linkedGuids[$guid] = 0 }
                    $linkedGuids[$guid]++
                    if (-not $link.Enabled) {
                        $disabledLinks.Add([PSCustomObject]@{
                            GPOId    = $guid
                            GPOName  = $link.DisplayName
                            Target   = $ou.DistinguishedName
                        })
                    }
                }
            } catch { }
        }

        Write-Host "    $($linkedGuids.Count) unique GPO GUID(s) have at least one link" -ForegroundColor Gray

    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "Link scan failed: $($_.Exception.Message)"
    }

    # Build inventory rows
    $inventoryRows = [System.Collections.Generic.List[PSCustomObject]]::new()
    foreach ($gpo in $allGPOs) {
        $guid      = $gpo.Id.ToString().ToUpper()
        $linkCount = if ($linkedGuids.ContainsKey($guid)) { $linkedGuids[$guid] } else { 0 }
        $inventoryRows.Add([PSCustomObject]@{
            Name            = $gpo.DisplayName
            GUID            = $guid
            Status          = $gpo.GpoStatus.ToString()
            LinkCount       = $linkCount
            UserDSVersion   = $gpo.User.DSVersion
            ComputerDSVersion = $gpo.Computer.DSVersion
            CreationTime    = $gpo.CreationTime
            ModificationTime = $gpo.ModificationTime
            IsDefaultDDP    = ($guid -eq $ddpGuid.Trim('{}'))
            IsDefaultDDCP   = ($guid -eq $ddcpGuid.Trim('{}'))
        })
    }

    $csvPath = "$OutputPath\Reports\M8-GPOInventory-$Global:RunTimestamp.csv"
    $inventoryRows | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
    Write-Host "    GPO inventory exported: $csvPath" -ForegroundColor Gray

    Add-Finding -ObjectDN $Domain -FindingType "GPOInventory" -Severity "INFO" `
        -Description "GPO inventory: $($allGPOs.Count) GPO(s), $($linkedGuids.Count) linked. Full CSV at $csvPath" `
        -NISTControl "CM-6" `
        -Data @{ TotalGPOs = $allGPOs.Count; LinkedGPOs = $linkedGuids.Count; CSVPath = $csvPath }

    # =========================================================================
    # CHECK 2: Unlinked GPOs
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [2/8] Unlinked GPOs..." -ForegroundColor DarkCyan

    $unlinked = @($inventoryRows | Where-Object { $_.LinkCount -eq 0 })

    if ($unlinked.Count -eq 0) {
        Write-Host "    [OK] No unlinked GPOs found" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($unlinked.Count) unlinked GPO(s)" -ForegroundColor Yellow
        foreach ($row in $unlinked) {
            Write-Host "    Unlinked: $($row.Name) (Status=$($row.Status))" -ForegroundColor Yellow

            Add-Finding -ObjectDN "GPO:$($row.Name)" -FindingType "UnlinkedGPO" -Severity "LOW" `
                -Description "GPO '$($row.Name)' is not linked to any OU, domain root, or site. It is being processed by the Group Policy engine but applying to no objects. Remediation: disable all settings (safe first step) after confirming with the GPO owner." `
                -CISControl "4" -NISTControl "CM-6, CM-7" `
                -Data @{ GUID = $row.GUID; Status = $row.Status; Modified = $row.ModificationTime }

            $unlinkedItems.Add([PSCustomObject]@{
                Name = $row.Name
                GUID = $row.GUID
            })
        }
    }

    # =========================================================================
    # CHECK 3: All-Settings-Disabled GPOs
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [3/8] All-settings-disabled GPOs..." -ForegroundColor DarkCyan

    $allDisabled = @($inventoryRows |
        Where-Object { $_.Status -eq "AllSettingsDisabled" -and $_.LinkCount -eq 0 })

    if ($allDisabled.Count -eq 0) {
        Write-Host "    [OK] No unlinked all-settings-disabled GPOs" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($allDisabled.Count) unlinked, all-settings-disabled GPO(s) -- deletion candidates" `
            -ForegroundColor Yellow
        foreach ($row in $allDisabled) {
            Write-Host "    Disabled+Unlinked: $($row.Name)" -ForegroundColor Yellow

            Add-Finding -ObjectDN "GPO:$($row.Name)" -FindingType "AllSettingsDisabledUnlinked" `
                -Severity "LOW" `
                -Description "GPO '$($row.Name)' has all settings disabled AND is not linked anywhere. It serves no function. Recommended action: delete after backup." `
                -CISControl "4" -NISTControl "CM-6, CM-7" `
                -Data @{ GUID = $row.GUID }

            $disabledItems.Add([PSCustomObject]@{ Name = $row.Name; GUID = $row.GUID })
        }
    }

    # =========================================================================
    # CHECK 4: Empty GPOs (DSVersion 0/0 confirmed by XML)
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [4/8] Empty GPOs (no configured settings)..." -ForegroundColor DarkCyan

    $candidateEmpty = @($inventoryRows |
        Where-Object {
            $_.UserDSVersion -eq 0 -and $_.ComputerDSVersion -eq 0 -and
            $_.Status -ne "AllSettingsDisabled" -and
            $_.GUID -ne $ddpGuid.Trim('{}') -and
            $_.GUID -ne $ddcpGuid.Trim('{}')
        })

    $confirmedEmpty = @()
    foreach ($row in $candidateEmpty) {
        try {
            $xmlStr  = Get-GPOReport -Guid $row.GUID -ReportType Xml -Domain $Domain
            $xmlDoc  = [xml]$xmlStr
            $hasComp = $null -ne $xmlDoc.GPO.Computer.ExtensionData
            $hasUser = $null -ne $xmlDoc.GPO.User.ExtensionData
            if (-not $hasComp -and -not $hasUser) {
                $confirmedEmpty += $row
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "Could not get GPO report for '$($row.Name)': $($_.Exception.Message)"
        }
    }

    if ($confirmedEmpty.Count -eq 0) {
        Write-Host "    [OK] No empty (zero-setting) GPOs found" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($confirmedEmpty.Count) empty GPO(s) confirmed" -ForegroundColor Yellow
        foreach ($row in $confirmedEmpty) {
            Write-Host "    Empty: $($row.Name) (Links=$($row.LinkCount))" -ForegroundColor Yellow

            Add-Finding -ObjectDN "GPO:$($row.Name)" -FindingType "EmptyGPO" -Severity "LOW" `
                -Description "GPO '$($row.Name)' has no configured settings (Computer.DSVersion=0, User.DSVersion=0, confirmed by XML). It contributes to Group Policy processing overhead with no effect. Recommended action: delete." `
                -CISControl "4" -NISTControl "CM-6" `
                -Data @{ GUID = $row.GUID; LinkCount = $row.LinkCount }

            $emptyItems.Add([PSCustomObject]@{
                Name      = $row.Name
                GUID      = $row.GUID
                LinkCount = $row.LinkCount
            })
        }
    }

    # =========================================================================
    # CHECK 5: Default Domain Policy and DDCP Modification
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [5/8] Default Domain Policy and DDCP modification check..." -ForegroundColor DarkCyan

    foreach ($defaultGPO in @(
        @{ GUID = $ddpGuid;  Name = "Default Domain Policy";             UserShouldBeZero = $true },
        @{ GUID = $ddcpGuid; Name = "Default Domain Controllers Policy"; UserShouldBeZero = $false }
    )) {
        try {
            $gpo = Get-GPO -Guid $defaultGPO.GUID -Domain $Domain -ErrorAction Stop

            Write-Host "    $($defaultGPO.Name): UserVersion=$($gpo.User.DSVersion) ComputerVersion=$($gpo.Computer.DSVersion)" `
                -ForegroundColor Gray

            # DDP: user configuration should be zero (no user settings in DDP)
            if ($defaultGPO.UserShouldBeZero -and $gpo.User.DSVersion -gt 0) {
                Add-Finding -ObjectDN "GPO:$($defaultGPO.Name)" `
                    -FindingType "DefaultPolicyUserSettingsModified" -Severity "MEDIUM" `
                    -Description "$($defaultGPO.Name) has User Configuration settings (UserVersion=$($gpo.User.DSVersion)). CIS guidance: custom settings should be in separate GPOs. Applying dcgpofix will wipe all non-default settings. Review and migrate user settings to a dedicated GPO." `
                    -CISControl "4" -NISTControl "CM-3, SI-7"
                Write-Host "    [!] $($defaultGPO.Name) has User Configuration settings -- should be empty" `
                    -ForegroundColor Yellow
            } else {
                Write-Host "    [OK] $($defaultGPO.Name) User Configuration is clean" -ForegroundColor Green
            }

            # Flag if ComputerVersion is higher than typical baseline
            # DDP baseline: 3 (password, lockout, Kerberos). DDCP baseline: ~4 (audit, user rights)
            $baselineVer = if ($defaultGPO.GUID -eq $ddpGuid) { 3 } else { 4 }
            if ($gpo.Computer.DSVersion -gt $baselineVer) {
                Add-Finding -ObjectDN "GPO:$($defaultGPO.Name)" `
                    -FindingType "DefaultPolicyComputerSettingsModified" -Severity "MEDIUM" `
                    -Description "$($defaultGPO.Name) Computer Configuration version is $($gpo.Computer.DSVersion) (baseline is approximately $baselineVer for a default AD install). Custom settings have been added. CIS guidance: use separate GPOs. Run dcgpofix with caution -- it will reset this policy to AD defaults, wiping all custom settings." `
                    -CISControl "4" -NISTControl "CM-3, SI-7"
                Write-Host "    [!] $($defaultGPO.Name) Computer version $($gpo.Computer.DSVersion) > baseline $baselineVer" `
                    -ForegroundColor Yellow
            }

        } catch {
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "Could not check $($defaultGPO.Name): $($_.Exception.Message)"
        }
    }

    # =========================================================================
    # CHECK 6: SYSVOL Orphan Detection
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [6/8] SYSVOL orphan detection..." -ForegroundColor DarkCyan

    $sysvolBase = "\\$Domain\SYSVOL\$Domain\Policies"
    $orphanAD   = @()   # AD GPO with no SYSVOL folder
    $orphanSYS  = @()   # SYSVOL folder with no AD GPO

    try {
        # AD GPOs missing SYSVOL folder
        foreach ($gpo in $allGPOs) {
            $folderPath = "$sysvolBase\{$($gpo.Id.ToString().ToUpper())}"
            if (-not (Test-Path $folderPath)) {
                $orphanAD += $gpo.DisplayName
                Add-Finding -ObjectDN "GPO:$($gpo.DisplayName)" `
                    -FindingType "GPOSYSVOLFolderMissing" -Severity "HIGH" `
                    -Description "GPO '$($gpo.DisplayName)' exists in AD but has no corresponding SYSVOL folder at $folderPath. Group Policy clients cannot apply this GPO -- they will receive error 1058. Likely caused by incomplete replication or manual deletion. Verify DFSR replication health." `
                    -NISTControl "SI-7, CM-3"
                Write-Host "    [!] SYSVOL folder missing for: $($gpo.DisplayName)" -ForegroundColor Red
            }
        }

        # SYSVOL folders with no AD GPO
        if (Test-Path $sysvolBase) {
            $sysvolFolders = @(Get-ChildItem -Path $sysvolBase -Directory -ErrorAction SilentlyContinue |
                Where-Object { $_.Name -match "^\{[0-9A-Fa-f\-]+\}$" })

            $adGuidSet = @{}
            foreach ($gpo in $allGPOs) {
                $adGuidSet["{$($gpo.Id.ToString().ToUpper())}"] = $true
            }

            foreach ($folder in $sysvolFolders) {
                if (-not $adGuidSet.ContainsKey($folder.Name.ToUpper())) {
                    $orphanSYS += $folder.Name
                    Add-Finding -ObjectDN $folder.FullName `
                        -FindingType "GPOSYSVOLOrphanFolder" -Severity "MEDIUM" `
                        -Description "SYSVOL contains GPO folder $($folder.Name) with no corresponding AD object. This is a SYSVOL orphan -- the AD object was deleted but the SYSVOL folder remains. Causes unnecessary replication traffic. Manual cleanup: remove the folder from SYSVOL on all DCs after verifying it is truly orphaned." `
                        -NISTControl "SI-7"
                    Write-Host "    [!] SYSVOL orphan folder: $($folder.Name)" -ForegroundColor Yellow
                }
            }
        }

        if ($orphanAD.Count -eq 0 -and $orphanSYS.Count -eq 0) {
            Write-Host "    [OK] No SYSVOL orphans detected" -ForegroundColor Green
        } else {
            Write-Host "    AD orphans (no SYSVOL): $($orphanAD.Count)" -ForegroundColor Gray
            Write-Host "    SYSVOL orphans (no AD): $($orphanSYS.Count)" -ForegroundColor Gray
        }

    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "SYSVOL orphan check failed: $($_.Exception.Message)"
        Write-Host "    [!] SYSVOL check failed: $($_.Exception.Message)" -ForegroundColor Yellow
    }

    # =========================================================================
    # CHECK 7: Disabled GPO Links
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [7/8] Disabled GPO links..." -ForegroundColor DarkCyan

    if ($disabledLinks.Count -eq 0) {
        Write-Host "    [OK] No disabled GPO links found" -ForegroundColor Green
    } else {
        Write-Host "    [!] $($disabledLinks.Count) disabled link(s) found" -ForegroundColor Yellow
        foreach ($link in $disabledLinks) {
            Write-Host "    Disabled link: '$($link.GPOName)' -> $($link.Target)" -ForegroundColor Yellow
            Add-Finding -ObjectDN "GPO:$($link.GPOName)" -FindingType "DisabledGPOLink" -Severity "LOW" `
                -Description "GPO '$($link.GPOName)' has a disabled link at '$($link.Target)'. The link exists but is not active. If this is intentional (testing/staging), document it. If not, remove the link to reduce namespace clutter." `
                -NISTControl "CM-6" `
                -Data @{ Target = $link.Target; GPOId = $link.GPOId }
        }
    }

    # =========================================================================
    # CHECK 8: GPO Delegation Audit
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [8/8] GPO delegation audit..." -ForegroundColor DarkCyan

    # Standard principals (by identity type pattern)
    $standardPatterns = @(
        "Domain Admins", "Enterprise Admins", "SYSTEM",
        "Authenticated Users", "ENTERPRISE DOMAIN CONTROLLERS",
        "Creator Owner"
    )

    $delegationFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    foreach ($gpo in $allGPOs) {
        try {
            $perms = @(Get-GPPermission -Guid $gpo.Id -All -Domain $Domain -ErrorAction SilentlyContinue)
            foreach ($perm in $perms) {
                $trustee = $perm.Trustee.Name
                $permType = $perm.Permission.ToString()

                # Flag Edit or Modify-Security permissions not held by standard accounts
                $isStandard = $false
                foreach ($pattern in $standardPatterns) {
                    if ($trustee -like "*$pattern*") { $isStandard = $true; break }
                }

                if (-not $isStandard -and $permType -in @("GpoEdit","GpoEditDeleteModifySecurity","GpoCustom")) {
                    $delegationFindings.Add([PSCustomObject]@{
                        GPOName  = $gpo.DisplayName
                        Trustee  = $trustee
                        Permission = $permType
                    })
                }
            }
        } catch { }
    }

    if ($delegationFindings.Count -eq 0) {
        Write-Host "    [OK] No non-standard GPO edit permissions found" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "GPO delegation: no non-standard edit permissions"
    } else {
        Write-Host "    [!] $($delegationFindings.Count) non-standard GPO edit permission(s)" -ForegroundColor Yellow
        foreach ($f in $delegationFindings) {
            Write-Host "    '$($f.GPOName)' -- $($f.Trustee) has $($f.Permission)" -ForegroundColor Yellow
            Add-Finding -ObjectDN "GPO:$($f.GPOName)" -FindingType "NonStandardGPOPermission" `
                -Severity "MEDIUM" `
                -Description "GPO '$($f.GPOName)' grants $($f.Permission) permission to '$($f.Trustee)'. This account is not a standard GPO editor (Domain Admins, Enterprise Admins, SYSTEM). Verify this delegation is intentional and documented." `
                -CISControl "4" -NISTControl "CM-3, AC-6" `
                -Data @{ Trustee = $f.Trustee; Permission = $f.Permission }
        }

        # Export delegation report
        $delCsvPath = "$OutputPath\Reports\M8-GPODelegation-$Global:RunTimestamp.csv"
        $delegationFindings | Export-Csv -Path $delCsvPath -NoTypeInformation -Encoding UTF8
        Write-Host "    Delegation report exported: $delCsvPath" -ForegroundColor Gray
    }

    # =========================================================================
    # Remediation Phase
    # =========================================================================
    if ($Mode -ne "Remediate") {
        $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
        Write-Host ""
        Write-Host "  M8 complete -- $($msFindings.Count) actionable finding(s)" `
            -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "M8 complete (Discover). Actionable findings: $($msFindings.Count)"
        return
    }

    $totalRemediable = $unlinkedItems.Count + $disabledItems.Count + $emptyItems.Count
    if ($totalRemediable -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No remediable items found." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "M8 Remediate: no remediable items"
        return
    }

    # -- Safety backup BEFORE any changes ------------------------------------
    Write-Host ""
    Write-Host "  --- GPO Backup (safety net before any changes) ---" -ForegroundColor Cyan
    $backupPath = "$OutputPath\GPOBackup-$Global:RunTimestamp"
    try {
        New-Item -Path $backupPath -ItemType Directory -Force | Out-Null
        Write-Host "    Backing up all GPOs to $backupPath ..." -ForegroundColor Gray
        $null = Backup-GPO -All -Path $backupPath -Domain $Domain
        Write-Host "    [OK] GPO backup complete: $backupPath" -ForegroundColor Green
        Write-AgentLog -Level ACTION -Milestone $ms -Message "GPO backup created at $backupPath"
    } catch {
        Write-Host "    [!] GPO backup FAILED: $($_.Exception.Message)" -ForegroundColor Red
        Write-Host "    Aborting remediation -- no changes applied without a successful backup." -ForegroundColor Red
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "GPO backup failed -- remediation aborted: $($_.Exception.Message)"
        return
    }

    Write-Host ""
    Write-Host "  --- Remediation Phase: $totalRemediable item(s) ---" -ForegroundColor Cyan
    Write-Host "  Backup location: $backupPath" -ForegroundColor DarkGray
    Write-Host "  Checks 5-8 are Discover-only. Processing checks 2-4." -ForegroundColor DarkYellow
    Write-Host ""

    try {

        # -- 2a: Disable all settings on unlinked GPOs -----------------------
        if ($unlinkedItems.Count -gt 0) {
            Write-Host "  --- Unlinked GPOs ($($unlinkedItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $unlinkedItems) {
                # Skip if it's also in the disabled list (already fully disabled)
                $alreadyDisabled = @($disabledItems | Where-Object { $_.GUID -eq $item.GUID })
                if ($alreadyDisabled.Count -gt 0) { continue }

                $approved = Invoke-HumanApproval `
                    -Action    "Disable all settings on unlinked GPO" `
                    -Target    "$($item.Name) ({$($item.GUID)})" `
                    -Implications @(
                        "GPO '$($item.Name)' will have all settings disabled (GpoStatus = AllSettingsDisabled).",
                        "The GPO object will NOT be deleted -- it can be re-enabled if needed.",
                        "Since the GPO is not linked anywhere, there is no immediate user/computer impact.",
                        "Backup is at: $backupPath"
                    ) `
                    -RollbackSteps @(
                        "Set-GPO -Name '$($item.Name)' -Status AllSettingsEnabled -Domain '$Domain'"
                    ) `
                    -RiskLevel "LOW" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Set-GPO -Name $item.Name -Status AllSettingsDisabled -Domain $Domain -ErrorAction Stop
                    Write-Host "  [OK] Disabled all settings on '$($item.Name)'" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Disabled all settings on unlinked GPO '$($item.Name)' ({$($item.GUID)})"
                } catch {
                    Write-Host "  [!] Failed on '$($item.Name)'`: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to disable GPO '$($item.Name)': $($_.Exception.Message)"
                }
            }
        }

        # -- 3a: Delete unlinked all-settings-disabled GPOs ------------------
        if ($disabledItems.Count -gt 0) {
            Write-Host ""
            Write-Host "  --- Unlinked All-Settings-Disabled GPOs ($($disabledItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $disabledItems) {
                $approved = Invoke-HumanApproval `
                    -Action    "Delete all-settings-disabled unlinked GPO" `
                    -Target    "$($item.Name) ({$($item.GUID)})" `
                    -Implications @(
                        "GPO '$($item.Name)' will be permanently deleted from AD and SYSVOL.",
                        "The GPO is already disabled and unlinked -- no objects are currently affected.",
                        "GPO can be restored from backup if needed: $backupPath",
                        "Deletion is PERMANENT -- the GUID will be released."
                    ) `
                    -RollbackSteps @(
                        "Restore-GPO -BackupGpoName '$($item.Name)' -Path '$backupPath' -Domain '$Domain'"
                    ) `
                    -RiskLevel "MEDIUM" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Remove-GPO -Name $item.Name -Domain $Domain -ErrorAction Stop
                    Write-Host "  [OK] Deleted GPO '$($item.Name)'" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Deleted all-settings-disabled GPO '$($item.Name)' ({$($item.GUID)})"
                } catch {
                    Write-Host "  [!] Failed on '$($item.Name)'`: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to delete GPO '$($item.Name)': $($_.Exception.Message)"
                }
            }
        }

        # -- 4a: Delete empty (never configured) GPOs -----------------------
        if ($emptyItems.Count -gt 0) {
            Write-Host ""
            Write-Host "  --- Empty GPOs ($($emptyItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $emptyItems) {
                $linkNote = if ($item.LinkCount -gt 0) { " NOTE: This GPO has $($item.LinkCount) link(s) -- removing an empty but linked GPO will leave dangling links." } else { "" }

                $approved = Invoke-HumanApproval `
                    -Action    "Delete empty GPO (no settings ever configured)" `
                    -Target    "$($item.Name) ({$($item.GUID)})" `
                    -Implications @(
                        "GPO '$($item.Name)' will be permanently deleted from AD and SYSVOL.",
                        "The GPO has no Computer or User settings (versions 0/0 confirmed by XML report).",
                        "Links: $($item.LinkCount). $linkNote",
                        "GPO can be restored from backup: $backupPath"
                    ) `
                    -RollbackSteps @(
                        "Restore-GPO -BackupGpoName '$($item.Name)' -Path '$backupPath' -Domain '$Domain'"
                    ) `
                    -RiskLevel "LOW" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Remove-GPO -Name $item.Name -Domain $Domain -ErrorAction Stop
                    Write-Host "  [OK] Deleted empty GPO '$($item.Name)'" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Deleted empty GPO '$($item.Name)' ({$($item.GUID)})"
                } catch {
                    Write-Host "  [!] Failed on '$($item.Name)'`: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to delete empty GPO '$($item.Name)': $($_.Exception.Message)"
                }
            }
        }

    } catch {
        if ($_.Exception.Message -eq "MILESTONE_QUIT") {
            Write-Host "  [!] M8 remediation stopped by operator." -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "M8 remediation quit by operator"
        } else {
            throw
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M8 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "M8 complete. Actionable findings: $($msFindings.Count)"
}
