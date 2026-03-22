#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 7 -- DC Hardening and CIS Level 1 Baseline

    Checks (CIS Microsoft Windows Server 2022/2025 Benchmark, Level 1):
      1.  LDAP Signing Requirement             CIS 2.3.11.8        NIST AC-17, SC-8
      2.  LDAP Channel Binding                 CIS 18.3.3          NIST IA-3
      3.  SMB Signing - Server (require)       CIS 2.3.6.6         NIST SC-8
      4.  SMB Signing - Client (require)       CIS 2.3.6.2         NIST SC-8
      5.  NLA required for RDP                 CIS 18.9.65.3.3.1   NIST IA-2, AC-17
      6.  Print Spooler disabled on DCs        CIS 18.3.6          NIST CM-7
      7.  LSASS Protected Process Light        CIS 18.9.46.2       NIST SI-3
      8.  Guest Account disabled               CIS 2.3.1.2         NIST AC-2
      9.  Anonymous SAM/Share enumeration      CIS 2.3.10.2, 10.3  NIST AC-6
      10. WDigest authentication disabled      CIS 18.3.7          NIST IA-5
      11. Credential Guard enabled             CIS 18.9.46.4       NIST IA-5, SC-28
      12. Advanced Audit Policy                CIS 17.x            NIST AU-2

    Requires WinRM access to each DC.
    Checks 1-11: registry/service state -- remediable with operator approval.
    Check 12 (Audit Policy): Discover-only -- remediate via GPO.

    Reboot notes:
      Check 7  (LSASS PPL):       Registry change takes effect after reboot.
      Check 11 (Credential Guard): Requires compatible hardware + reboot.
#>

function Invoke-M7 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M7"

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

    # Reads a single registry value from a remote DC.
    # Returns [PSCustomObject]@{ Exists=$bool; Value=$val }
    $regReadBlock = {
        param($RegPath, $RegKey)
        $result = [PSCustomObject]@{ Exists = $false; Value = $null }
        try {
            $prop = Get-ItemProperty -Path $RegPath -Name $RegKey -ErrorAction Stop
            $result.Exists = $true
            $result.Value  = $prop.$RegKey
        } catch { }
        return $result
    }

    # =========================================================================
    # Load config
    # =========================================================================
    $configPath = Join-Path $PSScriptRoot "..\Config\AgentConfig.psd1"
    $config     = $null
    if (Test-Path $configPath) {
        $config = & ([scriptblock]::Create((Get-Content $configPath -Raw)))
    }

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M7 - DC Hardening and CIS L1 Baseline"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M7 : DC Hardening and CIS Level 1 Baseline" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # =========================================================================
    # 1. Enumerate DCs
    # =========================================================================
    Write-Host "  -> Enumerating Domain Controllers..." -ForegroundColor DarkCyan
    $dcs = @()
    try {
        $dcs = @(Get-ADDomainController -Filter * -Server $Domain)
        Write-Host "    Found $($dcs.Count) DC(s)" -ForegroundColor Gray
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "DCEnumerationFailed" -Severity "CRITICAL" `
            -Description "Could not enumerate Domain Controllers: $($_.Exception.Message)"
        return
    }

    if ($dcs.Count -eq 0) {
        Write-Host "  [!] No DCs found. Exiting M7." -ForegroundColor Yellow
        return
    }

    # =========================================================================
    # Collection of remediable findings for the Remediate phase
    # Format: [PSCustomObject]@{ DCName; Check; CheckNumber; FindingType; Finding }
    # =========================================================================
    $remediableItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # 2. Per-DC checks
    # =========================================================================
    foreach ($dc in $dcs) {
        $dcName = $dc.HostName
        $dcDN   = "CN=$($dc.Name),OU=Domain Controllers,$((Get-ADDomain -Identity $Domain).DistinguishedName)"
        Write-Host ""
        Write-Host "  --- DC: $dcName ---" -ForegroundColor White

        # -- WinRM prereq check ------------------------------------------------
        Write-Host "  -> Checking WinRM connectivity..." -ForegroundColor DarkCyan
        $winrmOk = $false
        try {
            $null = Test-WSMan -ComputerName $dcName -ErrorAction Stop
            $winrmOk = $true
            Write-Host "    [OK] WinRM reachable on $dcName" -ForegroundColor Green
        } catch {
            Write-Host "    [!] WinRM not reachable on $dcName -- remote checks skipped" -ForegroundColor Yellow
            Add-Finding -ObjectDN $dcName -FindingType "WinRMNotReachable" -Severity "MEDIUM" `
                -Description "WinRM (PS remoting) is not reachable on $dcName. CIS registry checks require WinRM. Enable WinRM and re-run M7 to check this DC." `
                -NISTControl "CM-7"
        }

        if (-not $winrmOk) { continue }

        # =====================================================================
        # CHECK 1: LDAP Signing Requirement
        # CIS 2.3.11.8 -- LDAPServerIntegrity = 2 (Require signing)
        # =====================================================================
        Write-Host "  -> [1/12] LDAP Signing Requirement..." -ForegroundColor DarkCyan
        try {
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LDAPServerIntegrity" `
                -ErrorAction Stop

            $pass = $r.Exists -and ($r.Value -ge 2)
            if ($pass) {
                Write-Host "    [OK] LDAP Signing = $($r.Value) (Require Signing)" -ForegroundColor Green
            } else {
                $current = if ($r.Exists) { $r.Value } else { "Not set" }
                Write-Host "    [!] LDAP Signing = $current (expected >= 2)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "LDAPSigningNotRequired" -Severity "HIGH" `
                    -Description "LDAP Server Integrity is '$current' on $dcName. CIS 2.3.11.8 requires value 2 (Require Signing). Unsigned LDAP binds allow credential relay and MITM attacks." `
                    -CISControl "2.3.11.8" -CISLevel "L1" -NISTControl "AC-17, SC-8"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 1
                    CheckName   = "LDAPSigning"
                    Finding     = "LDAPServerIntegrity=$current"
                    RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                    RegKey      = "LDAPServerIntegrity"
                    RegValue    = 2
                    RegType     = "DWORD"
                    RebootNeeded = $false
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "LDAP signing check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 2: LDAP Channel Binding
        # CIS 18.3.3 -- LdapEnforceChannelBinding >= 1
        # =====================================================================
        Write-Host "  -> [2/12] LDAP Channel Binding..." -ForegroundColor DarkCyan
        try {
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters", "LdapEnforceChannelBinding" `
                -ErrorAction Stop

            $pass = $r.Exists -and ($r.Value -ge 1)
            if ($pass) {
                Write-Host "    [OK] LDAP Channel Binding = $($r.Value)" -ForegroundColor Green
            } else {
                $current = if ($r.Exists) { $r.Value } else { "Not set" }
                Write-Host "    [!] LDAP Channel Binding = $current (expected >= 1)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "LDAPChannelBindingNotConfigured" -Severity "HIGH" `
                    -Description "LdapEnforceChannelBinding is '$current' on $dcName. CIS 18.3.3 requires >= 1. Without channel binding, LDAP over TLS is vulnerable to relay attacks." `
                    -CISControl "18.3.3" -CISLevel "L1" -NISTControl "IA-3"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 2
                    CheckName   = "LDAPChannelBinding"
                    Finding     = "LdapEnforceChannelBinding=$current"
                    RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters"
                    RegKey      = "LdapEnforceChannelBinding"
                    RegValue    = 1
                    RegType     = "DWORD"
                    RebootNeeded = $false
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "LDAP channel binding check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 3: SMB Signing - Server (always require)
        # CIS 2.3.6.6 -- RequireSecuritySignature = 1
        # =====================================================================
        Write-Host "  -> [3/12] SMB Signing (Server - require)..." -ForegroundColor DarkCyan
        try {
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "RequireSecuritySignature" `
                -ErrorAction Stop

            $pass = $r.Exists -and ($r.Value -eq 1)
            if ($pass) {
                Write-Host "    [OK] SMB Server Signing required" -ForegroundColor Green
            } else {
                $current = if ($r.Exists) { $r.Value } else { "Not set" }
                Write-Host "    [!] SMB Server Signing = $current (expected 1)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "SMBServerSigningNotRequired" -Severity "HIGH" `
                    -Description "LanmanServer RequireSecuritySignature is '$current' on $dcName. CIS 2.3.6.6 requires value 1. Without required SMB signing, sessions are vulnerable to relay and MITM attacks." `
                    -CISControl "2.3.6.6" -CISLevel "L1" -NISTControl "SC-8"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 3
                    CheckName   = "SMBServerSigning"
                    Finding     = "RequireSecuritySignature=$current"
                    RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
                    RegKey      = "RequireSecuritySignature"
                    RegValue    = 1
                    RegType     = "DWORD"
                    RebootNeeded = $false
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "SMB server signing check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 4: SMB Signing - Client (always require)
        # CIS 2.3.6.2 -- RequireSecuritySignature = 1
        # =====================================================================
        Write-Host "  -> [4/12] SMB Signing (Client - require)..." -ForegroundColor DarkCyan
        try {
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters", "RequireSecuritySignature" `
                -ErrorAction Stop

            $pass = $r.Exists -and ($r.Value -eq 1)
            if ($pass) {
                Write-Host "    [OK] SMB Client Signing required" -ForegroundColor Green
            } else {
                $current = if ($r.Exists) { $r.Value } else { "Not set" }
                Write-Host "    [!] SMB Client Signing = $current (expected 1)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "SMBClientSigningNotRequired" -Severity "MEDIUM" `
                    -Description "LanmanWorkstation RequireSecuritySignature is '$current' on $dcName. CIS 2.3.6.2 requires value 1." `
                    -CISControl "2.3.6.2" -CISLevel "L1" -NISTControl "SC-8"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 4
                    CheckName   = "SMBClientSigning"
                    Finding     = "RequireSecuritySignature=$current"
                    RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters"
                    RegKey      = "RequireSecuritySignature"
                    RegValue    = 1
                    RegType     = "DWORD"
                    RebootNeeded = $false
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "SMB client signing check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 5: NLA required for RDP
        # CIS 18.9.65.3.3.1 -- UserAuthentication = 1
        # Checks GPO policy path first, falls back to Terminal Server path
        # =====================================================================
        Write-Host "  -> [5/12] NLA required for RDP..." -ForegroundColor DarkCyan
        try {
            $rdpCheckBlock = {
                # Check GPO policy path first (takes precedence)
                $policyPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                $directPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
                $result = [PSCustomObject]@{ Source = "NotConfigured"; Value = $null }

                $policyProp = (Get-ItemProperty -Path $policyPath -Name "UserAuthentication" -ErrorAction SilentlyContinue)
                if ($null -ne $policyProp) {
                    $result.Source = "GPO"
                    $result.Value  = $policyProp.UserAuthentication
                } else {
                    $directProp = (Get-ItemProperty -Path $directPath -Name "UserAuthentication" -ErrorAction SilentlyContinue)
                    if ($null -ne $directProp) {
                        $result.Source = "Direct"
                        $result.Value  = $directProp.UserAuthentication
                    }
                }
                return $result
            }

            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $rdpCheckBlock -ErrorAction Stop

            $pass = ($r.Value -eq 1)
            if ($pass) {
                Write-Host "    [OK] NLA required for RDP (source: $($r.Source))" -ForegroundColor Green
            } else {
                $current = if ($null -ne $r.Value) { $r.Value } else { "Not set" }
                Write-Host "    [!] NLA for RDP = $current via $($r.Source) (expected 1)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "RDPNLANotRequired" -Severity "HIGH" `
                    -Description "NLA (Network Level Authentication) for RDP is not enforced on $dcName (source: $($r.Source), value: '$current'). CIS 18.9.65.3.3.1 requires UserAuthentication=1. Without NLA, RDP is accessible pre-authentication." `
                    -CISControl "18.9.65.3.3.1" -CISLevel "L1" -NISTControl "IA-2, AC-17"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 5
                    CheckName   = "RDPNLA"
                    Finding     = "UserAuthentication=$current"
                    RegPath     = "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services"
                    RegKey      = "UserAuthentication"
                    RegValue    = 1
                    RegType     = "DWORD"
                    RebootNeeded = $false
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "RDP NLA check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 6: Print Spooler disabled on DCs
        # CIS 18.3.6 -- Spooler service StartType = Disabled
        # =====================================================================
        Write-Host "  -> [6/12] Print Spooler service..." -ForegroundColor DarkCyan
        try {
            $spoolerBlock = {
                $svc = Get-Service -Name Spooler -ErrorAction SilentlyContinue
                if ($null -eq $svc) {
                    return [PSCustomObject]@{ Exists = $false; Status = "NotInstalled"; StartType = "N/A" }
                }
                return [PSCustomObject]@{ Exists = $true; Status = $svc.Status.ToString(); StartType = $svc.StartType.ToString() }
            }
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $spoolerBlock -ErrorAction Stop

            if (-not $r.Exists -or $r.StartType -eq "Disabled") {
                Write-Host "    [OK] Print Spooler: $($r.StartType)" -ForegroundColor Green
            } else {
                Write-Host "    [!] Print Spooler StartType=$($r.StartType) Status=$($r.Status)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "PrintSpoolerEnabled" -Severity "HIGH" `
                    -Description "Print Spooler service is not disabled on $dcName (StartType=$($r.StartType), Status=$($r.Status)). CIS 18.3.6 requires Spooler to be disabled on DCs. PrintNightmare (CVE-2021-34527) and related vulnerabilities exploit this service." `
                    -CISControl "18.3.6" -CISLevel "L1" -NISTControl "CM-7"
                $remediableItems.Add([PSCustomObject]@{
                    DCName        = $dcName
                    CheckNumber   = 6
                    CheckName     = "PrintSpooler"
                    Finding       = "Spooler=$($r.StartType)"
                    RegPath       = $null
                    RegKey        = $null
                    RegValue      = $null
                    RegType       = $null
                    RebootNeeded  = $false
                    ServiceAction = "DisableSpooler"
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "Print Spooler check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 7: LSASS Protected Process Light (PPL)
        # CIS 18.9.46.2 -- RunAsPPL = 1 or 2
        # REBOOT REQUIRED for this change to take effect
        # =====================================================================
        Write-Host "  -> [7/12] LSASS Protected Process Light..." -ForegroundColor DarkCyan
        try {
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RunAsPPL" `
                -ErrorAction Stop

            $pass = $r.Exists -and ($r.Value -ge 1)
            if ($pass) {
                Write-Host "    [OK] LSASS PPL = $($r.Value)" -ForegroundColor Green
            } else {
                $current = if ($r.Exists) { $r.Value } else { "Not set" }
                Write-Host "    [!] LSASS PPL = $current (expected >= 1)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "LSSAProtectionDisabled" -Severity "HIGH" `
                    -Description "LSASS is not running as Protected Process Light on $dcName (RunAsPPL=$current). CIS 18.9.46.2 requires RunAsPPL >= 1. Without PPL, tools like Mimikatz can dump credentials from LSASS memory. ** REBOOT REQUIRED after applying this fix. **" `
                    -CISControl "18.9.46.2" -CISLevel "L1" -NISTControl "SI-3"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 7
                    CheckName   = "LSSAPPL"
                    Finding     = "RunAsPPL=$current"
                    RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                    RegKey      = "RunAsPPL"
                    RegValue    = 1
                    RegType     = "DWORD"
                    RebootNeeded = $true
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "LSASS PPL check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 8: Guest Account disabled
        # CIS 2.3.1.2 -- Guest account Enabled = $false
        # =====================================================================
        Write-Host "  -> [8/12] Guest Account status..." -ForegroundColor DarkCyan
        try {
            $guestBlock = {
                $g = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue
                if ($null -eq $g) { return [PSCustomObject]@{ Exists = $false; Enabled = $false } }
                return [PSCustomObject]@{ Exists = $true; Enabled = $g.Enabled }
            }
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $guestBlock -ErrorAction Stop

            if (-not $r.Exists -or -not $r.Enabled) {
                Write-Host "    [OK] Guest account disabled or not present" -ForegroundColor Green
            } else {
                Write-Host "    [!] Guest account is ENABLED on $dcName" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "GuestAccountEnabled" -Severity "HIGH" `
                    -Description "The built-in Guest account is enabled on $dcName. CIS 2.3.1.2 requires it to be disabled. An active Guest account on a DC is a significant attack surface." `
                    -CISControl "2.3.1.2" -CISLevel "L1" -NISTControl "AC-2"
                $remediableItems.Add([PSCustomObject]@{
                    DCName        = $dcName
                    CheckNumber   = 8
                    CheckName     = "GuestAccount"
                    Finding       = "Guest=Enabled"
                    RegPath       = $null
                    RegKey        = $null
                    RegValue      = $null
                    RegType       = $null
                    RebootNeeded  = $false
                    ServiceAction = "DisableGuest"
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "Guest account check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 9: Anonymous SAM and Share Enumeration
        # CIS 2.3.10.2 -- RestrictAnonymousSAM = 1
        # CIS 2.3.10.3 -- RestrictAnonymous = 1
        # =====================================================================
        Write-Host "  -> [9/12] Anonymous SAM/Share enumeration..." -ForegroundColor DarkCyan
        try {
            $r1 = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymousSAM" `
                -ErrorAction Stop
            $r2 = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa", "RestrictAnonymous" `
                -ErrorAction Stop

            $samOk  = $r1.Exists -and ($r1.Value -eq 1)
            $anonOk = $r2.Exists -and ($r2.Value -eq 1)

            if ($samOk -and $anonOk) {
                Write-Host "    [OK] Anonymous enumeration restricted" -ForegroundColor Green
            } else {
                $samVal  = if ($r1.Exists) { $r1.Value } else { "Not set" }
                $anonVal = if ($r2.Exists) { $r2.Value } else { "Not set" }

                if (-not $samOk) {
                    Write-Host "    [!] RestrictAnonymousSAM = $samVal (expected 1)" -ForegroundColor Yellow
                    Add-Finding -ObjectDN $dcName -FindingType "AnonymousSAMEnumerationAllowed" -Severity "MEDIUM" `
                        -Description "RestrictAnonymousSAM is '$samVal' on $dcName. CIS 2.3.10.2 requires value 1. Unauthenticated users can enumerate account names." `
                        -CISControl "2.3.10.2" -CISLevel "L1" -NISTControl "AC-6"
                    $remediableItems.Add([PSCustomObject]@{
                        DCName      = $dcName
                        CheckNumber = 9
                        CheckName   = "RestrictAnonymousSAM"
                        Finding     = "RestrictAnonymousSAM=$samVal"
                        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                        RegKey      = "RestrictAnonymousSAM"
                        RegValue    = 1
                        RegType     = "DWORD"
                        RebootNeeded = $false
                        ServiceAction = $null
                    })
                }
                if (-not $anonOk) {
                    Write-Host "    [!] RestrictAnonymous = $anonVal (expected 1)" -ForegroundColor Yellow
                    Add-Finding -ObjectDN $dcName -FindingType "AnonymousShareEnumerationAllowed" -Severity "MEDIUM" `
                        -Description "RestrictAnonymous is '$anonVal' on $dcName. CIS 2.3.10.3 requires value 1. Anonymous users can enumerate shares." `
                        -CISControl "2.3.10.3" -CISLevel "L1" -NISTControl "AC-6"
                    $remediableItems.Add([PSCustomObject]@{
                        DCName      = $dcName
                        CheckNumber = 9
                        CheckName   = "RestrictAnonymous"
                        Finding     = "RestrictAnonymous=$anonVal"
                        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                        RegKey      = "RestrictAnonymous"
                        RegValue    = 1
                        RegType     = "DWORD"
                        RebootNeeded = $false
                        ServiceAction = $null
                    })
                }
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "Anonymous enumeration check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 10: WDigest Authentication Disabled
        # CIS 18.3.7 -- UseLogonCredential = 0
        # Key may not exist on newer OS (disabled by default) -- still enforce
        # =====================================================================
        Write-Host "  -> [10/12] WDigest authentication..." -ForegroundColor DarkCyan
        try {
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $regReadBlock `
                -ArgumentList "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential" `
                -ErrorAction Stop

            # Not set or set to 0 = compliant (WDigest disabled)
            $pass = (-not $r.Exists) -or ($r.Value -eq 0)
            if ($pass) {
                $state = if ($r.Exists) { "Explicitly 0 (disabled)" } else { "Key absent (OS default: disabled)" }
                Write-Host "    [OK] WDigest: $state" -ForegroundColor Green
            } else {
                Write-Host "    [!] WDigest UseLogonCredential = $($r.Value) (expected 0)" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "WDigestEnabled" -Severity "HIGH" `
                    -Description "WDigest UseLogonCredential is $($r.Value) on $dcName. CIS 18.3.7 requires value 0. WDigest enabled causes Windows to store credentials in cleartext in LSASS memory -- trivially extracted by Mimikatz." `
                    -CISControl "18.3.7" -CISLevel "L1" -NISTControl "IA-5"
                $remediableItems.Add([PSCustomObject]@{
                    DCName      = $dcName
                    CheckNumber = 10
                    CheckName   = "WDigest"
                    Finding     = "UseLogonCredential=$($r.Value)"
                    RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest"
                    RegKey      = "UseLogonCredential"
                    RegValue    = 0
                    RegType     = "DWORD"
                    RebootNeeded = $false
                    ServiceAction = $null
                })
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "WDigest check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 11: Credential Guard
        # CIS 18.9.46.4 -- VBS enabled + LsaCfgFlags >= 1
        # Requires: UEFI + Secure Boot + TPM 2.0 + Server 2016+
        # REBOOT REQUIRED
        # =====================================================================
        Write-Host "  -> [11/12] Credential Guard..." -ForegroundColor DarkCyan
        try {
            $cgBlock = {
                param($ReadBlock)
                $vbs    = & $ReadBlock "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard" "EnableVirtualizationBasedSecurity"
                $lsa    = & $ReadBlock "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" "LsaCfgFlags"
                return [PSCustomObject]@{
                    VBSExists   = $vbs.Exists;  VBSValue   = $vbs.Value
                    LsaExists   = $lsa.Exists;  LsaValue   = $lsa.Value
                }
            }
            $r = Invoke-Command -ComputerName $dcName -ScriptBlock $cgBlock `
                -ArgumentList $regReadBlock -ErrorAction Stop

            $vbsOk = $r.VBSExists -and ($r.VBSValue -ge 1)
            $lsaOk = $r.LsaExists -and ($r.LsaValue -ge 1)

            if ($vbsOk -and $lsaOk) {
                Write-Host "    [OK] Credential Guard: VBS=$($r.VBSValue), LsaCfgFlags=$($r.LsaValue)" -ForegroundColor Green
            } else {
                $vbsVal = if ($r.VBSExists) { $r.VBSValue } else { "Not set" }
                $lsaVal = if ($r.LsaExists) { $r.LsaValue } else { "Not set" }
                Write-Host "    [!] Credential Guard: VBS=$vbsVal, LsaCfgFlags=$lsaVal" -ForegroundColor Yellow
                Add-Finding -ObjectDN $dcName -FindingType "CredentialGuardNotEnabled" -Severity "HIGH" `
                    -Description "Credential Guard is not fully enabled on $dcName (VBS=$vbsVal, LsaCfgFlags=$lsaVal). CIS 18.9.46.4 requires EnableVirtualizationBasedSecurity=1 and LsaCfgFlags>=1. Credential Guard isolates LSASS secrets in a VBS enclave, blocking Mimikatz-style attacks. ** REQUIRES compatible hardware (UEFI, Secure Boot, TPM 2.0) and REBOOT. **" `
                    -CISControl "18.9.46.4" -CISLevel "L1" -NISTControl "IA-5, SC-28"

                if (-not $vbsOk) {
                    $remediableItems.Add([PSCustomObject]@{
                        DCName      = $dcName
                        CheckNumber = 11
                        CheckName   = "CredentialGuard_VBS"
                        Finding     = "EnableVirtualizationBasedSecurity=$vbsVal"
                        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard"
                        RegKey      = "EnableVirtualizationBasedSecurity"
                        RegValue    = 1
                        RegType     = "DWORD"
                        RebootNeeded = $true
                        ServiceAction = $null
                    })
                }
                if (-not $lsaOk) {
                    $remediableItems.Add([PSCustomObject]@{
                        DCName      = $dcName
                        CheckNumber = 11
                        CheckName   = "CredentialGuard_Lsa"
                        Finding     = "LsaCfgFlags=$lsaVal"
                        RegPath     = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
                        RegKey      = "LsaCfgFlags"
                        RegValue    = 1
                        RegType     = "DWORD"
                        RebootNeeded = $true
                        ServiceAction = $null
                    })
                }
            }
        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "Credential Guard check failed on $dcName`: $($_.Exception.Message)"
        }

        # =====================================================================
        # CHECK 12: Advanced Audit Policy (CIS 17.x -- Discover only)
        # =====================================================================
        Write-Host "  -> [12/12] Advanced Audit Policy (CIS 17.x)..." -ForegroundColor DarkCyan

        # Define required subcategory => minimum setting
        # Setting values: "No Auditing", "Success", "Failure", "Success and Failure"
        $auditRequirements = @{
            "Credential Validation"          = "Success and Failure"
            "Security Group Management"      = "Success"
            "Directory Service Changes"      = "Success"
            "Logon"                          = "Success and Failure"
            "Logoff"                         = "Success"
            "Special Logon"                  = "Success"
            "SAM"                            = "Success"
            "Audit Policy Change"            = "Success"
            "Sensitive Privilege Use"        = "Success and Failure"
            "Security System Extension"      = "Success"
        }

        try {
            $auditBlock = {
                param($Requirements)
                $output  = & auditpol /get /category:* 2>&1
                $results = @{}
                foreach ($line in $output) {
                    $line = $line.ToString().Trim()
                    if ($line -eq "" -or $line -match "^Category" -or $line -match "^--") { continue }
                    foreach ($key in $Requirements.Keys) {
                        if ($line -match [regex]::Escape($key)) {
                            # auditpol line format: "  Subcategory Name                    Setting"
                            # Split on 2+ spaces
                            $parts = $line -split "\s{2,}"
                            $setting = if ($parts.Count -ge 2) { $parts[-1].Trim() } else { "Unknown" }
                            $results[$key] = $setting
                        }
                    }
                }
                return $results
            }

            $auditResults = Invoke-Command -ComputerName $dcName -ScriptBlock $auditBlock `
                -ArgumentList $auditRequirements -ErrorAction Stop

            $auditFailures = @()
            foreach ($subcategory in $auditRequirements.Keys) {
                $required = $auditRequirements[$subcategory]
                $actual   = if ($auditResults.ContainsKey($subcategory)) { $auditResults[$subcategory] } else { "Not found" }

                $compliant = $false
                if ($required -eq "Success and Failure") {
                    $compliant = ($actual -eq "Success and Failure")
                } elseif ($required -eq "Success") {
                    $compliant = ($actual -eq "Success" -or $actual -eq "Success and Failure")
                } elseif ($required -eq "Failure") {
                    $compliant = ($actual -eq "Failure" -or $actual -eq "Success and Failure")
                }

                if (-not $compliant) {
                    $auditFailures += "$subcategory`: actual='$actual', required='$required'"
                    Write-Host "    [!] $subcategory`: $actual (need: $required)" -ForegroundColor Yellow
                } else {
                    Write-Host "    [OK] $subcategory`: $actual" -ForegroundColor Green
                }
            }

            if ($auditFailures.Count -eq 0) {
                Write-Host "    [OK] All required audit subcategories are configured" -ForegroundColor Green
                Write-AgentLog -Level INFO -Milestone $ms -Message "Audit policy: all required subcategories compliant on $dcName"
            } else {
                $desc = "Audit policy gaps on $dcName ($($auditFailures.Count) subcategory/ies non-compliant -- see Data). " +
                        "Remediate via GPO: Computer Configuration > Windows Settings > Security Settings > Advanced Audit Policy Configuration. " +
                        "Note: this check is Discover-only and does not auto-remediate."
                Add-Finding -ObjectDN $dcName -FindingType "AuditPolicyGaps" -Severity "MEDIUM" `
                    -Description $desc `
                    -CISControl "17.x" -CISLevel "L1" -NISTControl "AU-2" `
                    -Data $auditFailures
            }

        } catch {
            Write-AgentLog -Level WARN -Milestone $ms -Message "Audit policy check failed on $dcName`: $($_.Exception.Message)"
            Add-Finding -ObjectDN $dcName -FindingType "AuditPolicyCheckFailed" -Severity "LOW" `
                -Description "Could not run auditpol on $dcName`: $($_.Exception.Message). Run manually: auditpol /get /category:*" `
                -CISControl "17.x" -CISLevel "L1" -NISTControl "AU-2"
        }

    } # end foreach DC

    # =========================================================================
    # 3. Remediation Phase
    # =========================================================================
    if ($Mode -ne "Remediate") {
        # Summary and return
        $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
        Write-Host ""
        Write-Host "  M7 complete -- $($msFindings.Count) actionable finding(s)" `
            -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-AgentLog -Level INFO -Milestone $ms -Message "M7 complete. Actionable findings: $($msFindings.Count)"
        return
    }

    if ($remediableItems.Count -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No remediable findings -- all CIS L1 checks passed." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "M7 Remediate: no items to remediate."
        return
    }

    Write-Host ""
    Write-Host "  --- Remediation Phase: $($remediableItems.Count) item(s) to review ---" -ForegroundColor Cyan
    Write-Host ""

    $rebootRequired = [System.Collections.Generic.List[string]]::new()

    try {
        foreach ($item in $remediableItems) {

            # Build approval gate context
            $riskLevel   = "HIGH"
            $implications = @()
            $rollback     = @()

            switch ($item.CheckName) {
                "LDAPSigning" {
                    $implications = @(
                        "LDAPServerIntegrity will be set to 2 (Require Signing) on $($item.DCName).",
                        "LDAP clients that do not support signing will be refused. Verify all LDAP clients support signing before approving.",
                        "Impact zone: any application performing unsigned LDAP binds to this DC."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LDAPServerIntegrity -Value 1"
                    )
                }
                "LDAPChannelBinding" {
                    $implications = @(
                        "LdapEnforceChannelBinding will be set to 1 on $($item.DCName).",
                        "LDAP over TLS connections without valid channel binding tokens will be rejected.",
                        "Impact zone: applications using LDAPS that do not support channel binding (older .NET, Java LDAP libs)."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' -Name LdapEnforceChannelBinding -Value 0"
                    )
                }
                "SMBServerSigning" {
                    $implications = @(
                        "LanmanServer RequireSecuritySignature will be set to 1 on $($item.DCName).",
                        "SMB clients that do not support signing will be unable to connect to this DC.",
                        "Impact zone: legacy clients (Windows XP/2003 without SMB signing enabled)."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters' -Name RequireSecuritySignature -Value 0"
                    )
                    $riskLevel = "MEDIUM"
                }
                "SMBClientSigning" {
                    $implications = @(
                        "LanmanWorkstation RequireSecuritySignature will be set to 1 on $($item.DCName).",
                        "The DC will require signing when acting as an SMB client connecting to other servers."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters' -Name RequireSecuritySignature -Value 0"
                    )
                    $riskLevel = "MEDIUM"
                }
                "RDPNLA" {
                    $implications = @(
                        "RDP UserAuthentication will be set to 1 (NLA required) on $($item.DCName).",
                        "RDP clients that do not support NLA will be unable to connect.",
                        "Active RDP sessions to this DC are NOT affected -- only new connections after the change.",
                        "Impact zone: any admin tool that initiates RDP without NLA support."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services' -Name UserAuthentication -Value 0"
                    )
                }
                "PrintSpooler" {
                    $implications = @(
                        "Print Spooler service will be STOPPED and set to DISABLED on $($item.DCName).",
                        "Any print jobs routed through this DC will fail immediately.",
                        "DCs should not be running Print Spooler -- printing via DC is a misconfiguration."
                    )
                    $rollback = @(
                        "Set-Service Spooler -StartupType Automatic",
                        "Start-Service Spooler"
                    )
                }
                "LSSAPPL" {
                    $implications = @(
                        "RunAsPPL will be set to 1 on $($item.DCName). LSASS will run as a Protected Process after next reboot.",
                        "This blocks credential dumping tools (Mimikatz, procdump LSASS) from reading LSASS memory.",
                        "REBOOT REQUIRED on $($item.DCName) for this to take effect.",
                        "If using kernel-mode security tools that hook LSASS, they may be affected -- verify vendor compatibility."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name RunAsPPL -Value 0",
                        "Reboot the DC"
                    )
                }
                "GuestAccount" {
                    $implications = @(
                        "Guest account will be disabled on $($item.DCName) via Disable-LocalUser Guest.",
                        "No authenticated sessions use the Guest account on a DC -- impact should be zero."
                    )
                    $rollback = @(
                        "Enable-LocalUser -Name Guest"
                    )
                    $riskLevel = "MEDIUM"
                }
                { $_ -in @("RestrictAnonymousSAM", "RestrictAnonymous") } {
                    $implications = @(
                        "$($item.RegKey) will be set to 1 on $($item.DCName).",
                        "Anonymous (unauthenticated) enumeration of SAM accounts or shares will be blocked.",
                        "Impact zone: legacy applications that rely on anonymous LDAP or NetBIOS enumeration."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name $($item.RegKey) -Value 0"
                    )
                    $riskLevel = "MEDIUM"
                }
                "WDigest" {
                    $implications = @(
                        "WDigest UseLogonCredential will be set to 0 on $($item.DCName).",
                        "Windows will stop caching credentials in cleartext in LSASS memory.",
                        "Active users will need to log off and back on for the change to apply to their session.",
                        "Impact zone: legacy applications that use WDigest HTTP authentication (rare on DCs)."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' -Name UseLogonCredential -Value 1"
                    )
                }
                { $_ -in @("CredentialGuard_VBS", "CredentialGuard_Lsa") } {
                    $implications = @(
                        "$($item.RegKey) will be set to 1 on $($item.DCName).",
                        "REBOOT REQUIRED. Credential Guard will be enabled after reboot.",
                        "HARDWARE CHECK: Ensure $($item.DCName) has UEFI firmware, Secure Boot enabled, and TPM 2.0.",
                        "If hardware is incompatible, the DC will boot but Credential Guard will silently fail to activate.",
                        "Review Event ID 14 in CAPI2 log post-reboot to confirm Credential Guard is active."
                    )
                    $rollback = @(
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\DeviceGuard' -Name EnableVirtualizationBasedSecurity -Value 0",
                        "Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name LsaCfgFlags -Value 0",
                        "Reboot the DC"
                    )
                }
                default {
                    $implications = @("Registry key $($item.RegKey) will be set to $($item.RegValue) on $($item.DCName).")
                    $rollback = @("Revert $($item.RegKey) to previous value")
                }
            }

            # Invoke approval gate
            $approved = Invoke-HumanApproval `
                -Action   "Apply CIS L1 fix: $($item.CheckName) on $($item.DCName)" `
                -Target   "$($item.DCName) ($($item.Finding))" `
                -Implications $implications `
                -RollbackSteps $rollback `
                -RiskLevel $riskLevel `
                -Milestone $ms

            if (-not $approved) { continue }

            # --- Apply the fix ---
            try {
                if ($item.ServiceAction -eq "DisableSpooler") {
                    Invoke-Command -ComputerName $item.DCName -ScriptBlock {
                        Stop-Service  -Name Spooler -Force -ErrorAction SilentlyContinue
                        Set-Service   -Name Spooler -StartupType Disabled
                    } -ErrorAction Stop
                    Write-Host "  [OK] Print Spooler stopped and disabled on $($item.DCName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Disabled Print Spooler on $($item.DCName)"

                } elseif ($item.ServiceAction -eq "DisableGuest") {
                    Invoke-Command -ComputerName $item.DCName -ScriptBlock {
                        Disable-LocalUser -Name "Guest" -ErrorAction Stop
                    } -ErrorAction Stop
                    Write-Host "  [OK] Guest account disabled on $($item.DCName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Disabled Guest account on $($item.DCName)"

                } elseif ($null -ne $item.RegPath) {
                    # Ensure the registry key path exists (needed for e.g. WDigest, RDP policy)
                    Invoke-Command -ComputerName $item.DCName -ScriptBlock {
                        param($Path, $Key, $Value, $Type)
                        if (-not (Test-Path $Path)) {
                            New-Item -Path $Path -Force | Out-Null
                        }
                        Set-ItemProperty -Path $Path -Name $Key -Value $Value -Type $Type -Force
                    } -ArgumentList $item.RegPath, $item.RegKey, $item.RegValue, $item.RegType `
                      -ErrorAction Stop

                    Write-Host "  [OK] Set $($item.RegKey) = $($item.RegValue) on $($item.DCName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Set $($item.RegPath)\$($item.RegKey) = $($item.RegValue) on $($item.DCName)"

                    if ($item.RebootNeeded -and $rebootRequired -notcontains $item.DCName) {
                        $rebootRequired.Add($item.DCName)
                    }
                }

            } catch {
                Write-Host "  [!] Failed to apply fix on $($item.DCName)`: $($_.Exception.Message)" -ForegroundColor Red
                Write-AgentLog -Level WARN -Milestone $ms `
                    -Message "Remediation failed for $($item.CheckName) on $($item.DCName)`: $($_.Exception.Message)"
            }
        }

    } catch {
        if ($_.Exception.Message -eq "MILESTONE_QUIT") {
            Write-Host "  [!] M7 remediation stopped by operator." -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "M7 remediation quit by operator"
        } else {
            throw
        }
    }

    # -- Reboot warnings -------------------------------------------------------
    if ($rebootRequired.Count -gt 0) {
        Write-Host ""
        Write-Host "  +---------------------------------------------------------+" -ForegroundColor Red
        Write-Host "     REBOOT REQUIRED on the following DC(s):" -ForegroundColor Red
        foreach ($dcr in $rebootRequired) {
            Write-Host "       * $dcr" -ForegroundColor Red
        }
        Write-Host "     Changes to LSASS PPL and Credential Guard are NOT active" -ForegroundColor Red
        Write-Host "     until the DC is rebooted. Plan maintenance windows." -ForegroundColor Red
        Write-Host "  +---------------------------------------------------------+" -ForegroundColor Red
        Write-Host ""
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "Reboot required on: $($rebootRequired -join ', ') for LSASS PPL / Credential Guard changes"
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M7 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms -Message "M7 complete. Actionable findings: $($msFindings.Count)"
}
