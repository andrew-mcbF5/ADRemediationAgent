#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 1 -- DC Health and Baseline

    Checks:
      - Domain/Forest functional levels
      - DC Inventory: names, IPv4 addresses, OS versions, sites, GC/RODC status
      - FSMO role holders
      - Replication status (repadmin)
      - SYSVOL/DFSR health + replication mode detection (DFSR vs legacy FRS)
      - DNS resolution per DC
      - AD Recycle Bin status
      - Time sync skew (PDC Emulator)
      - DC upgrade readiness flags (pre-2025 OS flagged)
      - IP-bound app warning (if IPBoundAppsPresent = $true in config)
      - krbtgt account password age
      - Accounts with DONT_REQUIRE_PREAUTH (AS-REP roasting risk) [CIS-adjacent, NIST IA-5]
      - Protected Users group membership check for DA members [NIST AC-6]

    Produces a DCInventory finding (Severity INFO, Data = array of DC objects)
    which is consumed by New-RunReport to render the DC OS Progression card.
#>

function Invoke-M1 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    $ms = "M1"

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

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M1 - DC Health and Baseline"

    # Load config if available
    $configPath = Join-Path $PSScriptRoot "..\Config\AgentConfig.psd1"
    $config     = $null
    if (Test-Path $configPath) {
        $config = & ([scriptblock]::Create((Get-Content $configPath -Raw)))
    }
    $ipBoundWarning = $false
    if ($config -and $config.IPBoundAppsPresent) { $ipBoundWarning = $config.IPBoundAppsPresent }

    # =========================================================================
    # 1. Domain and Forest Functional Levels
    # =========================================================================
    Write-Host "  -> Checking domain/forest functional levels..." -ForegroundColor DarkCyan
    try {
        $domainObj = Get-ADDomain -Identity $Domain
        $forestObj = Get-ADForest

        $domFL = $domainObj.DomainMode.ToString()
        $forFL = $forestObj.ForestMode.ToString()

        Write-Host "    Domain FL : $domFL" -ForegroundColor Gray
        Write-Host "    Forest FL : $forFL" -ForegroundColor Gray
        Write-AgentLog -Level INFO -Milestone $ms -Message "Domain FL: $domFL  Forest FL: $forFL"

        $legacyLevels = @(
            "Windows2003Domain","Windows2008Domain","Windows2008R2Domain",
            "Windows2012Domain","Windows2012R2Domain"
        )
        if ($domFL -in $legacyLevels) {
            Add-Finding -ObjectDN $Domain -FindingType "LegacyFunctionalLevel" -Severity "MEDIUM" `
                -Description "Domain functional level is $domFL -- raise after all DCs are on Server 2025." `
                -NISTControl "CM-6"
        }

        Add-Finding -ObjectDN $Domain -FindingType "FunctionalLevel" -Severity "INFO" `
            -Description "Domain: $domFL | Forest: $forFL"

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "FunctionalLevelCheckFailed" `
            -Severity "HIGH" -Description $_.Exception.Message
    }

    # =========================================================================
    # 2. DC Inventory (names, IPs, OS, sites, GC, RODC)
    # =========================================================================
    Write-Host "  -> Enumerating Domain Controllers..." -ForegroundColor DarkCyan

    $dcInventory = @()

    try {
        $dcs = @(Get-ADDomainController -Filter * -Server $Domain)
        $domainObj2 = Get-ADDomain -Identity $Domain
        $forestObj2 = Get-ADForest

        # Build FSMO map to annotate DCs.
        # Built iteratively rather than as a literal to handle single-DC domains
        # where all five roles share the same hostname -- a literal @{} throws
        # "Duplicate keys are not allowed" when the same key appears more than once.
        $fsmoMap = @{}
        @(
            @{ H = $domainObj2.PDCEmulator.ToLower();          R = "PDCEmulator"         }
            @{ H = $domainObj2.RIDMaster.ToLower();            R = "RIDMaster"           }
            @{ H = $domainObj2.InfrastructureMaster.ToLower(); R = "InfrastructureMaster"}
            @{ H = $forestObj2.SchemaMaster.ToLower();         R = "SchemaMaster"        }
            @{ H = $forestObj2.DomainNamingMaster.ToLower();   R = "DomainNamingMaster"  }
        ) | ForEach-Object {
            if ($fsmoMap.ContainsKey($_.H)) {
                $fsmoMap[$_.H] = $fsmoMap[$_.H] + ", " + $_.R
            } else {
                $fsmoMap[$_.H] = $_.R
            }
        }

        Write-Host "    Found $($dcs.Count) DC(s):" -ForegroundColor Gray

        foreach ($dc in $dcs) {
            $osVer  = if ($dc.OperatingSystem) { $dc.OperatingSystem } else { "Unknown" }
            $site   = if ($dc.Site)            { $dc.Site }            else { "Unknown" }
            $ipv4   = if ($dc.IPv4Address)     { $dc.IPv4Address }     else { "Unknown" }
            $isGC   = $dc.IsGlobalCatalog
            $isRODC = $dc.IsReadOnly

            # Check FSMO roles held by this DC
            $dcFqdn    = $dc.HostName.ToLower()
            $dcShort   = $dc.Name.ToLower()
            $fsmoRoles = @()
            foreach ($k in $fsmoMap.Keys) {
                if ($k -eq $dcFqdn -or $k -eq "$($dcShort).$Domain".ToLower() -or $k.StartsWith("$dcShort.")) {
                    $fsmoRoles += $fsmoMap[$k]
                }
            }
            $fsmoStr = if ($fsmoRoles.Count -gt 0) { $fsmoRoles -join ", " } else { "None" }

            # Upgrade readiness
            $onTarget    = $osVer -match "2025"
            $isLegacy    = $osVer -match "2012|2008|2003"
            $upgradeFlag = ""
            if ($onTarget)    { $upgradeFlag = "COMPLETE" }
            elseif ($isLegacy){ $upgradeFlag = "URGENT"   }
            else              { $upgradeFlag = "PENDING"  }

            $dcObj = [PSCustomObject]@{
                Name        = $dc.Name
                HostName    = $dc.HostName
                IPv4        = $ipv4
                OS          = $osVer
                Site        = $site
                IsGC        = $isGC
                IsRODC      = $isRODC
                FSMORoles   = $fsmoStr
                UpgradeFlag = $upgradeFlag
            }
            $dcInventory += $dcObj

            Write-Host "      [$($dc.Name)] IP: $ipv4  OS: $osVer  Site: $site  GC: $isGC  RODC: $isRODC  FSMO: $fsmoStr" -ForegroundColor Gray
            Write-AgentLog -Level INFO -Milestone $ms `
                -Message "DC: $($dc.Name) | IP: $ipv4 | OS: $osVer | Site: $site | GC: $isGC | RODC: $isRODC | FSMO: $fsmoStr"

            # Flag legacy OS
            if (-not $onTarget) {
                $sev = if ($isLegacy) { "HIGH" } else { "MEDIUM" }
                Add-Finding -ObjectDN $dc.HostName -FindingType "LegacyDCOS" -Severity $sev `
                    -Description "DC is running $osVer -- target is Windows Server 2025 (upgrade flag: $upgradeFlag)." `
                    -NISTControl "CM-6, SI-2"
            }

            # DNS check
            try {
                $null = Resolve-DnsName -Name $dc.HostName -ErrorAction Stop
                Write-AgentLog -Level INFO -Milestone $ms -Message "DNS OK for $($dc.HostName)"
            } catch {
                Add-Finding -ObjectDN $dc.HostName -FindingType "DNSResolutionFailed" -Severity "HIGH" `
                    -Description "Cannot resolve DC hostname in DNS: $($_.Exception.Message)" `
                    -NISTControl "SC-22"
            }
        }

        # Store DC inventory as a structured finding for the report
        Add-Finding -ObjectDN $Domain -FindingType "DCInventory" -Severity "INFO" `
            -Description "DC inventory snapshot: $($dcs.Count) controller(s). See Data for detail." `
            -Data $dcInventory

        # IP-bound app warning
        if ($ipBoundWarning) {
            Write-Host ""
            Write-Host "  [WARN] IPBoundAppsPresent = true in config." -ForegroundColor Yellow
            Write-Host "         Legacy apps are bound to DC IP addresses." -ForegroundColor Yellow
            Write-Host "         Review DC IPs above before any DC decommission or IP reassignment." -ForegroundColor Yellow
            Write-Host ""
            Add-Finding -ObjectDN $Domain -FindingType "IPBoundAppsWarning" -Severity "MEDIUM" `
                -Description "Config indicates legacy applications are bound to DC IP addresses. Coordinate IP reassignment during DC upgrade. DNS gap risk during swing migration -- run repadmin /syncall and verify DNS records before cutting over IPs." `
                -NISTControl "CM-8, SC-22"
        }

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "DCEnumerationFailed" `
            -Severity "CRITICAL" -Description $_.Exception.Message
    }

    # =========================================================================
    # 3. FSMO Role Holders (summary finding)
    # =========================================================================
    Write-Host "  -> Checking FSMO roles..." -ForegroundColor DarkCyan
    try {
        $domainObj3 = Get-ADDomain -Identity $Domain
        $forestObj3 = Get-ADForest

        $fsmoDesc = "PDC=$($domainObj3.PDCEmulator) | RID=$($domainObj3.RIDMaster) | Infra=$($domainObj3.InfrastructureMaster) | Schema=$($forestObj3.SchemaMaster) | Naming=$($forestObj3.DomainNamingMaster)"

        Write-Host "    $fsmoDesc" -ForegroundColor Gray
        Write-AgentLog -Level INFO -Milestone $ms -Message "FSMO: $fsmoDesc"

        Add-Finding -ObjectDN $Domain -FindingType "FSMORoles" -Severity "INFO" `
            -Description $fsmoDesc

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "FSMOCheckFailed" `
            -Severity "HIGH" -Description $_.Exception.Message
    }

    # =========================================================================
    # 4. Replication Status
    # =========================================================================
    Write-Host "  -> Checking AD replication (repadmin)..." -ForegroundColor DarkCyan
    try {
        $replOutput = & repadmin /replsummary 2>&1
        $replLines  = @($replOutput | Where-Object { $_ -match "error|fail|warning" -and $_ -notmatch "^$" })

        if ($replLines.Count -eq 0) {
            Write-Host "    [OK] No replication errors detected" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "Replication summary: no errors"
        } else {
            foreach ($line in $replLines) {
                Write-Host "    [!] $line" -ForegroundColor Yellow
                Add-Finding -ObjectDN "replication" -FindingType "ReplicationError" -Severity "HIGH" `
                    -Description $line.ToString().Trim() `
                    -NISTControl "CP-9, SI-7"
            }
        }

        $replLog = "$OutputPath\Reports\M1-ReplicationSummary-$Global:RunTimestamp.txt"
        $replOutput | Out-File $replLog -Encoding UTF8
        Write-AgentLog -Level INFO -Milestone $ms -Message "Replication full output saved to $replLog"

    } catch {
        Add-Finding -ObjectDN "replication" -FindingType "ReplicationCheckFailed" `
            -Severity "HIGH" -Description $_.Exception.Message
    }

    # =========================================================================
    # 5. SYSVOL / DFSR Health + Replication Mode Detection
    # =========================================================================
    Write-Host "  -> Checking SYSVOL/DFSR health and replication mode..." -ForegroundColor DarkCyan

    # Detect replication mode: DFSR (modern) vs FRS (legacy)
    try {
        $domainObj5 = Get-ADDomain -Identity $Domain
        $dfsrDN  = "CN=DFSR-GlobalSettings,CN=System,$($domainObj5.DistinguishedName)"
        $dfsrObj = $null
        try {
            $dfsrObj = Get-ADObject -Identity $dfsrDN -Properties "msDFSR-Flags" -ErrorAction Stop
        } catch {
            $dfsrObj = $null
        }

        if ($dfsrObj) {
            Write-Host "    [OK] SYSVOL is using DFSR (modern replication)" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "SYSVOL replication mode: DFSR"
            Add-Finding -ObjectDN "SYSVOL" -FindingType "SYSVOLReplicationMode" -Severity "INFO" `
                -Description "SYSVOL is using DFSR (modern). No FRS migration required before DC upgrade."
        } else {
            Write-Host "    [WARN] SYSVOL may be using legacy FRS replication" -ForegroundColor Yellow
            Add-Finding -ObjectDN "SYSVOL" -FindingType "SYSVOLLegacyFRS" -Severity "HIGH" `
                -Description "SYSVOL DFSR object not found -- SYSVOL may be using legacy FRS replication. FRS must be migrated to DFSR before upgrading DCs to Windows Server 2025. Run: dfsrmig /getglobalstate to confirm." `
                -NISTControl "SI-2, CM-6"
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "SYSVOL mode check failed: $($_.Exception.Message)"
    }

    # DFSR health check
    try {
        $sysvolCheck  = & dfsrdiag ReplicationState 2>&1
        $sysvolIssues = @($sysvolCheck | Where-Object { $_ -match "Error|Warning" })
        if ($sysvolIssues.Count -eq 0) {
            Write-Host "    [OK] SYSVOL/DFSR appears healthy" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "SYSVOL/DFSR: no issues detected"
        } else {
            foreach ($issue in $sysvolIssues) {
                Add-Finding -ObjectDN "SYSVOL" -FindingType "SYSVOLReplicationIssue" -Severity "HIGH" `
                    -Description $issue.ToString().Trim() -NISTControl "CP-9"
            }
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "dfsrdiag not available: $($_.Exception.Message)"
    }

    # =========================================================================
    # 6. AD Recycle Bin
    # =========================================================================
    Write-Host "  -> Checking AD Recycle Bin status..." -ForegroundColor DarkCyan
    try {
        $recycleBin = @(Get-ADOptionalFeature -Filter { Name -like "Recycle Bin Feature" })
        if ($recycleBin.Count -gt 0 -and $recycleBin[0].EnabledScopes.Count -gt 0) {
            Write-Host "    [OK] AD Recycle Bin is enabled" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "AD Recycle Bin: ENABLED"
        } else {
            Write-Host "    [!] AD Recycle Bin is NOT enabled" -ForegroundColor Yellow
            Add-Finding -ObjectDN $Domain -FindingType "RecycleBinDisabled" -Severity "MEDIUM" `
                -Description "AD Recycle Bin is not enabled. Enable it to allow object recovery without a full restore." `
                -NISTControl "CP-9"
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "Could not check Recycle Bin: $($_.Exception.Message)"
    }

    # =========================================================================
    # 7. Time Sync (PDC Emulator)
    # =========================================================================
    Write-Host "  -> Checking time sync on PDC Emulator..." -ForegroundColor DarkCyan
    try {
        $domainObj7 = Get-ADDomain -Identity $Domain
        $pdcName    = $domainObj7.PDCEmulator
        $w32Status  = & w32tm /query /computer:$pdcName /status 2>&1
        if ($w32Status -match "Error|Unsync") {
            Add-Finding -ObjectDN $pdcName -FindingType "TimeSyncIssue" -Severity "HIGH" `
                -Description "Time sync issue on PDC Emulator $($pdcName): Kerberos tickets will fail if skew exceeds 5 minutes." `
                -NISTControl "AU-8"
        } else {
            Write-Host "    [OK] Time sync OK on $pdcName" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "Time sync OK on PDC $pdcName"
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "w32tm check failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # 8. krbtgt Password Age
    # =========================================================================
    Write-Host "  -> Checking krbtgt account password age..." -ForegroundColor DarkCyan
    try {
        $krbtgt = Get-ADUser -Identity "krbtgt" -Properties PasswordLastSet -Server $Domain
        if ($krbtgt.PasswordLastSet) {
            $krbtgtAge = (New-TimeSpan -Start $krbtgt.PasswordLastSet -End (Get-Date)).Days
            Write-Host "    krbtgt password age: $krbtgtAge days" -ForegroundColor Gray
            Write-AgentLog -Level INFO -Milestone $ms -Message "krbtgt password age: $krbtgtAge days"

            $domainObj8 = Get-ADDomain -Identity $Domain
            $krbtgtDN   = "CN=krbtgt,CN=Users,$($domainObj8.DistinguishedName)"

            if ($krbtgtAge -gt 365) {
                Add-Finding -ObjectDN $krbtgtDN `
                    -FindingType "KrbtgtPasswordStale" -Severity "HIGH" `
                    -Description "krbtgt password is $krbtgtAge days old (>365). Recommend rotating twice (with replication interval between) to invalidate any stolen Kerberos tickets." `
                    -NISTControl "IA-5(1), AC-3"
            } elseif ($krbtgtAge -gt 180) {
                Add-Finding -ObjectDN $krbtgtDN `
                    -FindingType "KrbtgtPasswordAgeing" -Severity "MEDIUM" `
                    -Description "krbtgt password is $krbtgtAge days old (>180). Consider scheduling a rotation." `
                    -NISTControl "IA-5(1)"
            }
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "krbtgt check failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # 9. Accounts with DONT_REQUIRE_PREAUTH (AS-REP Roasting risk)
    #    CIS-adjacent | NIST IA-5(1)
    # =========================================================================
    Write-Host "  -> Checking for accounts with pre-auth disabled (AS-REP roasting risk)..." -ForegroundColor DarkCyan
    try {
        $noPreAuth = @(Get-ADUser -Filter { DoesNotRequirePreAuth -eq $true } `
            -Properties DoesNotRequirePreAuth, Enabled, DistinguishedName -Server $Domain |
            Where-Object { $_.Enabled -eq $true })

        if ($noPreAuth.Count -gt 0) {
            Write-Host "    [!] $($noPreAuth.Count) enabled account(s) with pre-auth disabled" -ForegroundColor Yellow
            foreach ($u in $noPreAuth) {
                Add-Finding -ObjectDN $u.DistinguishedName -FindingType "ASREPRoastable" -Severity "HIGH" `
                    -Description "Account has DONT_REQUIRE_PREAUTH set -- vulnerable to AS-REP roasting (offline hash cracking without domain credentials)." `
                    -CISLevel "L1" -NISTControl "IA-5(1), AC-3"
            }
        } else {
            Write-Host "    [OK] No accounts with pre-auth disabled" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "AS-REP roasting check: no vulnerable accounts"
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "Pre-auth check failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # 10. Protected Users Group - DA members not enrolled
    #     NIST AC-6, IA-2(1)
    # =========================================================================
    Write-Host "  -> Checking Domain Admins enrollment in Protected Users group..." -ForegroundColor DarkCyan
    try {
        $daMembers        = @(Get-ADGroupMember -Identity "Domain Admins" -Recursive -Server $Domain |
            Where-Object { $_.objectClass -eq "user" })
        $protectedMembers = @(Get-ADGroupMember -Identity "Protected Users" -Server $Domain |
            Select-Object -ExpandProperty SamAccountName)

        $daNotProtected = @($daMembers | Where-Object { $protectedMembers -notcontains $_.SamAccountName })

        if ($daNotProtected.Count -gt 0) {
            Write-Host "    [!] $($daNotProtected.Count) Domain Admin(s) not in Protected Users group" -ForegroundColor Yellow
            foreach ($u in $daNotProtected) {
                Add-Finding -ObjectDN $u.distinguishedName -FindingType "DANotInProtectedUsers" -Severity "MEDIUM" `
                    -Description "Domain Admin '$($u.SamAccountName)' is not a member of the Protected Users security group. Protected Users disables NTLM, DES, and RC4 authentication for the account." `
                    -CISLevel "L1" -NISTControl "AC-6, IA-2(1)"
            }
        } else {
            Write-Host "    [OK] All Domain Admins are in Protected Users" -ForegroundColor Green
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "Protected Users check failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # Remediate mode: prompt acknowledgment for CRITICAL/HIGH
    # =========================================================================
    if ($Mode -eq "Remediate") {
        $critFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -in @("CRITICAL","HIGH") })

        if ($critFindings.Count -gt 0) {
            Write-Host ""
            Write-Host "  [!] M1 has $($critFindings.Count) HIGH/CRITICAL health findings." -ForegroundColor Red
            Write-Host "      These require manual investigation -- no auto-remediation is applied." -ForegroundColor Yellow
            Write-Host ""
            foreach ($f in $critFindings) {
                Write-Host "      [$($f.Severity)] $($f.FindingType): $($f.Description)" -ForegroundColor Red
            }
            Write-Host ""
            $ack = Read-Host "  Press ENTER to acknowledge and continue, or type STOP to halt"
            if ($ack.Trim().ToUpper() -eq "STOP") {
                Write-AgentLog -Level WARN -Milestone $ms -Message "Operator halted agent at M1 acknowledgment."
                throw "AGENT_HALTED_BY_OPERATOR"
            }
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M1 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms -Message "M1 complete. Actionable findings: $($msFindings.Count)"
}
