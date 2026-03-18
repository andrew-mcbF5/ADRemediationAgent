<#
.SYNOPSIS
    Milestone 1 -- DC Health & Baseline

    Checks:
      - Replication status (repadmin)
      - DC list and OS versions
      - SYSVOL / DFSR health
      - DNS resolution for each DC
      - FSMO role holders
      - Time sync skew
      - AD Recycle Bin status
      - Functional levels (domain + forest)

    Mode: Discover  -> enumerate and log findings only
    Mode: Remediate -> no auto-remediation (health checks are informational);
                      flags CRITICAL issues and prompts operator to acknowledge
    Mode: Baseline  -> same as Discover, feeds into baseline snapshot
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
        Write-AgentLog -Level FINDING -Milestone $ms -Message "[$Severity] $FindingType -- $ObjectDN : $Description" -Data $Data
    }

    # -- 1. Domain & Forest Functional Levels ---------------------------------
    Write-Host "  -> Checking domain/forest functional levels..." -ForegroundColor DarkCyan
    try {
        $domainObj = Get-ADDomain -Identity $Domain
        $forestObj = Get-ADForest

        $domFL = $domainObj.DomainMode.ToString()
        $forFL = $forestObj.ForestMode.ToString()

        Write-Host "    Domain FL : $domFL" -ForegroundColor Gray
        Write-Host "    Forest FL : $forFL" -ForegroundColor Gray
        Write-AgentLog -Level INFO -Milestone $ms -Message "Domain FL: $domFL  Forest FL: $forFL"

        # Flag if still on pre-2016 levels
        $legacyLevels = @("Windows2003Domain","Windows2008Domain","Windows2008R2Domain","Windows2012Domain","Windows2012R2Domain")
        if ($domFL -in $legacyLevels) {
            Add-Finding -ObjectDN $Domain -FindingType "LegacyFunctionalLevel" -Severity "MEDIUM" `
                -Description "Domain functional level is $domFL -- consider raising after all DCs are on Server 2025."
        }

        # Store as baseline data
        $Global:FindingsList | Where-Object FindingType -eq "FunctionalLevel" | ForEach-Object { $_ }
        # Add informational record
        Add-Finding -ObjectDN $Domain -FindingType "FunctionalLevel" -Severity "INFO" `
            -Description "Domain: $domFL | Forest: $forFL"

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "FunctionalLevelCheckFailed" -Severity "HIGH" -Description $_.Exception.Message
    }

    # -- 2. DC Inventory & OS Versions ----------------------------------------
    Write-Host "  -> Enumerating Domain Controllers..." -ForegroundColor DarkCyan
    try {
        $dcs = Get-ADDomainController -Filter * -Server $Domain

        Write-Host "    Found $($dcs.Count) DC(s):" -ForegroundColor Gray
        foreach ($dc in $dcs) {
            $osVer  = $dc.OperatingSystem
            $site   = $dc.Site
            $isGC   = $dc.IsGlobalCatalog
            $isRODC = $dc.IsReadOnly

            Write-Host "      [$($dc.Name)] OS: $osVer  Site: $site  GC: $isGC  RODC: $isRODC" -ForegroundColor Gray
            Write-AgentLog -Level INFO -Milestone $ms `
                -Message "DC: $($dc.Name) | OS: $osVer | Site: $site | GC: $isGC | RODC: $isRODC"

            # Flag legacy OS
            if ($osVer -and $osVer -notmatch "2022|2025") {
                $sev = if ($osVer -match "2012|2008|2003") { "HIGH" } else { "MEDIUM" }
                Add-Finding -ObjectDN $dc.HostName -FindingType "LegacyDCOS" -Severity $sev `
                    -Description "DC is running $osVer -- target is Windows Server 2025."
            }

            # DNS check
            try {
                $resolved = Resolve-DnsName -Name $dc.HostName -ErrorAction Stop
                Write-AgentLog -Level INFO -Milestone $ms -Message "DNS OK for $($dc.HostName)"
            } catch {
                Add-Finding -ObjectDN $dc.HostName -FindingType "DNSResolutionFailed" -Severity "HIGH" `
                    -Description "Cannot resolve DC hostname in DNS: $($_.Exception.Message)"
            }
        }

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "DCEnumerationFailed" -Severity "CRITICAL" -Description $_.Exception.Message
    }

    # -- 3. FSMO Role Holders --------------------------------------------------
    Write-Host "  -> Checking FSMO roles..." -ForegroundColor DarkCyan
    try {
        $domainObj = Get-ADDomain -Identity $Domain
        $forestObj = Get-ADForest

        $fsmo = @{
            "PDCEmulator"         = $domainObj.PDCEmulator
            "RIDMaster"           = $domainObj.RIDMaster
            "InfrastructureMaster"= $domainObj.InfrastructureMaster
            "SchemaMaster"        = $forestObj.SchemaMaster
            "DomainNamingMaster"  = $forestObj.DomainNamingMaster
        }

        foreach ($role in $fsmo.GetEnumerator()) {
            Write-Host "    $($role.Key): $($role.Value)" -ForegroundColor Gray
            Write-AgentLog -Level INFO -Milestone $ms -Message "FSMO $($role.Key): $($role.Value)"
        }

        Add-Finding -ObjectDN $Domain -FindingType "FSMORoles" -Severity "INFO" `
            -Description "PDC=$($fsmo.PDCEmulator) | RID=$($fsmo.RIDMaster) | Infra=$($fsmo.InfrastructureMaster)"

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "FSMOCheckFailed" -Severity "HIGH" -Description $_.Exception.Message
    }

    # -- 4. Replication Status -------------------------------------------------
    Write-Host "  -> Checking AD replication (repadmin)..." -ForegroundColor DarkCyan
    try {
        $replOutput = & repadmin /replsummary 2>&1
        $replLines  = $replOutput | Where-Object { $_ -match "error|fail|warning" -and $_ -notmatch "^$" }

        if ($replLines.Count -eq 0) {
            Write-Host "    [OK] No replication errors detected" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "Replication summary: no errors"
        } else {
            foreach ($line in $replLines) {
                Write-Host "    [!] $line" -ForegroundColor Yellow
                Add-Finding -ObjectDN "replication" -FindingType "ReplicationError" -Severity "HIGH" `
                    -Description $line.ToString().Trim()
            }
        }

        # Save full output
        $replLog = "$OutputPath\Reports\M1-ReplicationSummary-$Global:RunTimestamp.txt"
        $replOutput | Out-File $replLog -Encoding UTF8
        Write-AgentLog -Level INFO -Milestone $ms -Message "Replication full output saved to $replLog"

    } catch {
        Add-Finding -ObjectDN "replication" -FindingType "ReplicationCheckFailed" -Severity "HIGH" -Description $_.Exception.Message
    }

    # -- 5. SYSVOL / DFSR Health ----------------------------------------------
    Write-Host "  -> Checking SYSVOL/DFSR health..." -ForegroundColor DarkCyan
    try {
        # Check DFSR replication group
        $sysvolCheck = & dfsrdiag ReplicationState 2>&1
        if ($sysvolCheck -match "Error|Warning") {
            Add-Finding -ObjectDN "SYSVOL" -FindingType "SYSVOLReplicationIssue" -Severity "HIGH" `
                -Description ($sysvolCheck | Where-Object { $_ -match "Error|Warning" } | Select-Object -First 3) -join "; "
        } else {
            Write-Host "    [OK] SYSVOL/DFSR appears healthy" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "SYSVOL/DFSR: no issues detected"
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "dfsrdiag not available or failed: $($_.Exception.Message)"
    }

    # -- 6. AD Recycle Bin ----------------------------------------------------
    Write-Host "  -> Checking AD Recycle Bin status..." -ForegroundColor DarkCyan
    try {
        $recycleBin = Get-ADOptionalFeature -Filter { Name -like "Recycle Bin Feature" }
        if ($recycleBin.EnabledScopes.Count -gt 0) {
            Write-Host "    [OK] AD Recycle Bin is enabled" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "AD Recycle Bin: ENABLED"
        } else {
            Write-Host "    [!] AD Recycle Bin is NOT enabled" -ForegroundColor Yellow
            Add-Finding -ObjectDN $Domain -FindingType "RecycleBinDisabled" -Severity "MEDIUM" `
                -Description "AD Recycle Bin is not enabled. Enable it to allow object recovery without restore."
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "Could not check Recycle Bin: $($_.Exception.Message)"
    }

    # -- 7. Time Sync (PDC Emulator) ------------------------------------------
    Write-Host "  -> Checking time sync on PDC Emulator..." -ForegroundColor DarkCyan
    try {
        $domainObj = Get-ADDomain -Identity $Domain
        $pdcName   = $domainObj.PDCEmulator

        $w32Status = & w32tm /query /computer:$pdcName /status 2>&1
        if ($w32Status -match "Error|Unsync") {
            Add-Finding -ObjectDN $pdcName -FindingType "TimeSyncIssue" -Severity "HIGH" `
                -Description "Time sync issue on PDC Emulator $pdcName"
        } else {
            Write-Host "    [OK] Time sync OK on $pdcName" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "Time sync OK on PDC $pdcName"
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms -Message "w32tm check failed: $($_.Exception.Message)"
    }

    # -- Remediate mode: prompt acknowledgment for CRITICAL/HIGH --------------
    if ($Mode -eq "Remediate") {
        $criticalFindings = $Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -in @("CRITICAL","HIGH") }

        if ($criticalFindings.Count -gt 0) {
            Write-Host ""
            Write-Host "  [!]  M1 has $($criticalFindings.Count) HIGH/CRITICAL health findings." -ForegroundColor Red
            Write-Host "     These require manual investigation -- no automated remediation is applied." -ForegroundColor Yellow
            Write-Host ""

            foreach ($f in $criticalFindings) {
                Write-Host "     [$($f.Severity)] $($f.FindingType): $($f.Description)" -ForegroundColor Red
            }

            Write-Host ""
            $ack = Read-Host "  Press ENTER to acknowledge and continue, or type STOP to halt the agent"
            if ($ack.Trim().ToUpper() -eq "STOP") {
                Write-AgentLog -Level WARN -Milestone $ms -Message "Operator halted agent at M1 acknowledgment."
                throw "AGENT_HALTED_BY_OPERATOR"
            }
        }
    }

    # -- Summary ---------------------------------------------------------------
    $msFindings = $Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" }
    Write-Host ""
    Write-Host "  M1 complete -- $($msFindings.Count) actionable finding(s)" -ForegroundColor $(if($msFindings.Count -gt 0){"Yellow"}else{"Green"})
    Write-AgentLog -Level INFO -Milestone $ms -Message "M1 complete. Actionable findings: $($msFindings.Count)"
}
