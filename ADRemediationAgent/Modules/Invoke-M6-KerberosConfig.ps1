#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 6 -- Kerberos Configuration Review

    Checks:
      1. Kerberos Ticket Policy  [Discover-only]
         Reads Default Domain Policy GptTmpl.inf from SYSVOL.
         Validates MaxTicketAge (<= 10h), MaxRenewAge (<= 7d),
         MaxClockSkew (<= 5m), MaxServiceAge (<= 600m).
         NIST: AU-8, SC-8

      2. RC4-only Account Encryption Audit  [Remediable]
         All ENABLED user accounts with no AES support in
         msDS-SupportedEncryptionTypes (value 0/unset, or
         only DES/RC4 bits set). Broader than M5 (which covers
         SPN holders only) -- any RC4-only account can be
         downgrade-attacked or targeted for pass-the-ticket.
         NIST: IA-5, IA-5(1), SC-28

      3. Protected Users Extended Analysis  [Remediable]
         M1 checks Domain Admins vs Protected Users.
         M6 extends to all PrivilegedGroups config members
         and also flags service accounts erroneously IN
         Protected Users (which disables delegation/NTLM).
         NIST: AC-6, IA-2(1)

      4. WHfB Kerberos Hybrid Trust Prerequisites  [Discover-only]
         Validates the Azure AD Kerberos server computer object
         (CN=AzureADKerberos,OU=Domain Controllers,<DomainDN>),
         domain functional level >= 2016 (WHfB requirement),
         and msDS-KeyCredentialLink presence on a user sample.
         NIST: IA-2(1), SC-8

      5. Authentication Policy and Silo Inventory  [Discover-only]
         Lists all Authentication Policy and Silo objects.
         Flags Tier 0 accounts not assigned to a silo.
         NIST: AC-2, AC-6

    Note: AS-REP roasting (DONT_REQUIRE_PREAUTH) is covered in M1.
          Kerberoastable SPN accounts are covered in M5.
          M6 does not duplicate those checks.

    Kerberos encryption type bit flags (msDS-SupportedEncryptionTypes):
      0x01 = DES-CBC-CRC       0x02 = DES-CBC-MD5
      0x04 = RC4-HMAC          0x08 = AES128-CTS-HMAC-SHA1
      0x10 = AES256-CTS-HMAC-SHA1
      AES supported: ($value -band 0x18) -gt 0
      Value 0 (unset): domain default -- RC4 on pre-2016 functional levels
#>

function Invoke-M6 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M6"

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

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M6 - Kerberos Configuration Review"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M6 : Kerberos Configuration Review" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # =========================================================================
    # Shared data loaded once
    # =========================================================================

    $domainObj = $null
    try {
        $domainObj = Get-ADDomain -Identity $Domain
    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "DomainQueryFailed" -Severity "CRITICAL" `
            -Description "Cannot query domain object: $($_.Exception.Message)"
        return
    }
    $domainDN = $domainObj.DistinguishedName

    # Load PrivilegedGroups from config
    $configPath      = Join-Path $PSScriptRoot "..\Config\AgentConfig.psd1"
    $config          = $null
    $privilegedGroups = @("Domain Admins","Enterprise Admins","Schema Admins")
    if (Test-Path $configPath) {
        $config = & ([scriptblock]::Create((Get-Content $configPath -Raw)))
        if ($config.PrivilegedGroups) {
            $privilegedGroups = @($config.PrivilegedGroups)
        }
    }

    # Build Tier 0 account set from all configured privileged groups
    $tier0Accounts = @()
    foreach ($grp in $privilegedGroups) {
        try {
            $members = @(Get-ADGroupMember -Identity $grp -Recursive -Server $Domain |
                Where-Object { $_.objectClass -eq "user" })
            $tier0Accounts += $members
        } catch { }
    }
    $tier0Accounts = @($tier0Accounts | Sort-Object -Property DistinguishedName -Unique)
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "Tier 0 account set: $($tier0Accounts.Count) unique accounts across $($privilegedGroups.Count) privileged groups"

    # Remediable items
    $rc4Items            = [System.Collections.Generic.List[PSCustomObject]]::new()
    $notProtectedItems   = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # CHECK 1: Kerberos Ticket Policy (Default Domain Policy SYSVOL)
    # =========================================================================
    Write-Host "  -> [1/5] Kerberos Ticket Policy (Default Domain Policy)..." -ForegroundColor DarkCyan

    $ddpGuid  = "{31B2F340-016D-11D2-945F-00C04FB984F9}"
    $gptPath  = "\\$Domain\SYSVOL\$Domain\Policies\$ddpGuid\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"

    try {
        if (-not (Test-Path $gptPath)) {
            throw "GptTmpl.inf not found at $gptPath"
        }

        $gptContent = Get-Content -Path $gptPath -Encoding Unicode -ErrorAction Stop
        $kerbSettings = @{}
        $inSection    = $false

        foreach ($line in $gptContent) {
            $trimmed = $line.Trim()
            if ($trimmed -eq "[Kerberos Policy]") { $inSection = $true; continue }
            if ($trimmed -match "^\[" -and $inSection)  { $inSection = $false; continue }
            if ($inSection -and $trimmed -match "^(\w+)\s*=\s*(.+)$") {
                $kerbSettings[$Matches[1]] = $Matches[2].Trim()
            }
        }

        if ($kerbSettings.Count -eq 0) {
            Write-Host "    [!] No Kerberos Policy section found in Default Domain Policy" -ForegroundColor Yellow
            Add-Finding -ObjectDN $Domain -FindingType "KerberosPolicyNotConfigured" -Severity "MEDIUM" `
                -Description "No [Kerberos Policy] section found in Default Domain Policy GptTmpl.inf. Domain is using built-in defaults -- explicitly configure ticket lifetimes via GPO to meet baseline requirements." `
                -NISTControl "AU-8, SC-8"
        } else {
            Write-Host "    Kerberos Policy values:" -ForegroundColor Gray
            foreach ($k in $kerbSettings.Keys) {
                Write-Host "      $k = $($kerbSettings[$k])" -ForegroundColor Gray
            }

            # MaxTicketAge: max Kerberos TGT lifetime in hours (should be <= 10)
            if ($kerbSettings.ContainsKey("MaxTicketAge")) {
                $val = [int]$kerbSettings["MaxTicketAge"]
                if ($val -gt 10) {
                    Add-Finding -ObjectDN $Domain -FindingType "KerberosTicketLifetimeTooLong" -Severity "MEDIUM" `
                        -Description "MaxTicketAge is $val hours (recommended <= 10). Long-lived TGTs increase the window of opportunity for stolen ticket abuse (pass-the-ticket)." `
                        -NISTControl "AU-8, SC-8"
                    Write-Host "    [!] MaxTicketAge = $val hours (recommended <= 10)" -ForegroundColor Yellow
                } else {
                    Write-Host "    [OK] MaxTicketAge = $val hours" -ForegroundColor Green
                }
            }

            # MaxRenewAge: max TGT renewal period in days (should be <= 7)
            if ($kerbSettings.ContainsKey("MaxRenewAge")) {
                $val = [int]$kerbSettings["MaxRenewAge"]
                if ($val -gt 7) {
                    Add-Finding -ObjectDN $Domain -FindingType "KerberosRenewalPeriodTooLong" -Severity "LOW" `
                        -Description "MaxRenewAge is $val days (recommended <= 7). Extended renewal windows allow compromised tickets to remain valid longer." `
                        -NISTControl "SC-8"
                    Write-Host "    [!] MaxRenewAge = $val days (recommended <= 7)" -ForegroundColor Yellow
                } else {
                    Write-Host "    [OK] MaxRenewAge = $val days" -ForegroundColor Green
                }
            }

            # MaxClockSkew: max allowed clock skew in minutes (must be <= 5)
            if ($kerbSettings.ContainsKey("MaxClockSkew")) {
                $val = [int]$kerbSettings["MaxClockSkew"]
                if ($val -gt 5) {
                    Add-Finding -ObjectDN $Domain -FindingType "KerberosClockSkewTooPermissive" -Severity "HIGH" `
                        -Description "MaxClockSkew is $val minutes (must be <= 5). A permissive clock skew policy weakens replay protection. Kerberos requires all participants to be within 5 minutes of each other." `
                        -NISTControl "AU-8"
                    Write-Host "    [!] MaxClockSkew = $val minutes (must be <= 5)" -ForegroundColor Yellow
                } else {
                    Write-Host "    [OK] MaxClockSkew = $val minutes" -ForegroundColor Green
                }
            }

            # MaxServiceAge: service ticket lifetime in minutes (should be <= 600)
            if ($kerbSettings.ContainsKey("MaxServiceAge")) {
                $val = [int]$kerbSettings["MaxServiceAge"]
                if ($val -gt 600) {
                    Add-Finding -ObjectDN $Domain -FindingType "KerberosServiceTicketLifetimeTooLong" -Severity "LOW" `
                        -Description "MaxServiceAge is $val minutes (recommended <= 600). Long-lived service tickets extend the pass-the-ticket window for compromised sessions." `
                        -NISTControl "SC-8"
                    Write-Host "    [!] MaxServiceAge = $val minutes (recommended <= 600)" -ForegroundColor Yellow
                } else {
                    Write-Host "    [OK] MaxServiceAge = $val minutes" -ForegroundColor Green
                }
            }

            Add-Finding -ObjectDN $Domain -FindingType "KerberosPolicySnapshot" -Severity "INFO" `
                -Description "Kerberos ticket policy read from Default Domain Policy." `
                -NISTControl "AU-8, SC-8" -Data $kerbSettings
        }

    } catch {
        Write-Host "    [!] Could not read Default Domain Policy: $($_.Exception.Message)" -ForegroundColor Yellow
        Add-Finding -ObjectDN $Domain -FindingType "KerberosPolicyReadFailed" -Severity "MEDIUM" `
            -Description "Could not read Kerberos policy from SYSVOL ($gptPath): $($_.Exception.Message). Verify SYSVOL health and DFSR replication." `
            -NISTControl "AU-8, SC-8"
    }

    # =========================================================================
    # CHECK 2: RC4-only Account Encryption Audit
    # All ENABLED user accounts with no AES in msDS-SupportedEncryptionTypes
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [2/5] RC4-only account encryption audit..." -ForegroundColor DarkCyan

    try {
        $adProps    = @("msDS-SupportedEncryptionTypes", "Enabled", "SamAccountName",
                        "ServicePrincipalName", "DistinguishedName", "PasswordLastSet", "Description")
        $allUsers   = @(Get-ADUser -Filter { Enabled -eq $true } -Properties $adProps -Server $Domain)

        $rc4Only = @(
            $allUsers | Where-Object {
                $enc = $_."msDS-SupportedEncryptionTypes"
                # Flag: value is null/0 (domain default, typically RC4) OR
                #        explicitly set to only DES/RC4 bits (no 0x8 or 0x10)
                ($null -eq $enc -or $enc -eq 0) -or (($enc -band 0x18) -eq 0)
            }
        )

        Write-Host "    Scanned $($allUsers.Count) enabled user account(s)" -ForegroundColor Gray

        if ($rc4Only.Count -eq 0) {
            Write-Host "    [OK] All enabled accounts have AES encryption support" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "RC4 audit: all accounts have AES support"
        } else {
            Write-Host "    [!] $($rc4Only.Count) account(s) with no AES encryption support" -ForegroundColor Yellow

            foreach ($u in $rc4Only) {
                $enc      = $u."msDS-SupportedEncryptionTypes"
                $encStr   = if ($null -eq $enc -or $enc -eq 0) { "Not set (RC4 default)" } else { "0x$($enc.ToString('X')) ($enc)" }
                $hasSpn   = ($u.ServicePrincipalName.Count -gt 0)
                $isTier0  = ($tier0Accounts | Where-Object { $_.SamAccountName -eq $u.SamAccountName }).Count -gt 0
                $pwdAge   = if ($u.PasswordLastSet) {
                    (New-TimeSpan -Start $u.PasswordLastSet -End (Get-Date)).Days
                } else { -1 }

                $severity = if ($isTier0) { "CRITICAL" } elseif ($hasSpn) { "HIGH" } else { "MEDIUM" }
                $tier0Tag = if ($isTier0) { " [TIER 0]" } else { "" }
                $spnTag   = if ($hasSpn)  { " [HAS SPN -- also Kerberoastable]" } else { "" }

                Write-Host "    $($u.SamAccountName)$tier0Tag$spnTag -- EncTypes: $encStr" `
                    -ForegroundColor $(if ($severity -eq "CRITICAL") { "Magenta" } elseif ($severity -eq "HIGH") { "Red" } else { "Yellow" })

                Add-Finding -ObjectDN $u.DistinguishedName -FindingType "RC4OnlyEncryption" -Severity $severity `
                    -Description "Account '$($u.SamAccountName)'$tier0Tag$spnTag has no AES encryption support (msDS-SupportedEncryptionTypes=$encStr). RC4-only accounts are vulnerable to encryption downgrade and pass-the-ticket attacks. Password age: $pwdAge days. Remediation: enable AES128+AES256, then reset the account password." `
                    -NISTControl "IA-5, IA-5(1), SC-28" `
                    -Data @{ EncTypes = $encStr; HasSPN = $hasSpn; IsTier0 = $isTier0; PwdAgeDays = $pwdAge }

                $rc4Items.Add([PSCustomObject]@{
                    ObjectDN   = $u.DistinguishedName
                    ObjectName = $u.SamAccountName
                    EncTypes   = $encStr
                    PwdAgeDays = $pwdAge
                    IsTier0    = $isTier0
                    Severity   = $severity
                })
            }
        }

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "RC4AuditFailed" -Severity "HIGH" `
            -Description "RC4 encryption audit failed: $($_.Exception.Message)" `
            -NISTControl "IA-5"
        Write-Host "    [!] RC4 audit failed: $($_.Exception.Message)" -ForegroundColor Red
    }

    # =========================================================================
    # CHECK 3: Protected Users Extended Analysis
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [3/5] Protected Users extended analysis..." -ForegroundColor DarkCyan

    try {
        $protectedUsersDN      = "CN=Protected Users,CN=Users,$domainDN"
        $protectedUsersMembers = @(Get-ADGroupMember -Identity $protectedUsersDN -Server $Domain |
            Select-Object -ExpandProperty SamAccountName)

        Write-Host "    Protected Users has $($protectedUsersMembers.Count) member(s)" -ForegroundColor Gray

        # 3a: Privileged accounts NOT in Protected Users
        foreach ($acct in $tier0Accounts) {
            if ($protectedUsersMembers -notcontains $acct.SamAccountName) {
                $groupMembership = ($privilegedGroups | Where-Object {
                    try {
                        $members = @(Get-ADGroupMember -Identity $_ -Recursive -Server $Domain |
                            Where-Object { $_.SamAccountName -eq $acct.SamAccountName })
                        $members.Count -gt 0
                    } catch { $false }
                }) -join ", "

                Write-Host "    [!] Privileged account not in Protected Users: $($acct.SamAccountName) ($groupMembership)" `
                    -ForegroundColor Yellow

                Add-Finding -ObjectDN $acct.DistinguishedName -FindingType "PrivilegedNotInProtectedUsers" `
                    -Severity "MEDIUM" `
                    -Description "Account '$($acct.SamAccountName)' is a member of privileged group(s) [$groupMembership] but is NOT in the Protected Users security group. Protected Users prevents NTLM, DES, and RC4 authentication for the account, protecting against credential relay attacks. Note: Protected Users also disables Kerberos delegation and cached credentials -- verify before adding service accounts." `
                    -NISTControl "AC-6, IA-2(1)"

                $notProtectedItems.Add([PSCustomObject]@{
                    ObjectDN   = $acct.DistinguishedName
                    ObjectName = $acct.SamAccountName
                    Groups     = $groupMembership
                })
            }
        }

        if ($notProtectedItems.Count -eq 0) {
            Write-Host "    [OK] All configured privileged accounts are in Protected Users" -ForegroundColor Green
        }

        # 3b: Service accounts (with SPN) inside Protected Users -- flag as potential misconfiguration
        $serviceAccountsInPU = @()
        foreach ($sam in $protectedUsersMembers) {
            try {
                $user = Get-ADUser -Identity $sam -Properties ServicePrincipalName, Enabled `
                    -Server $Domain -ErrorAction SilentlyContinue
                if ($null -ne $user -and $user.Enabled -and $user.ServicePrincipalName.Count -gt 0) {
                    $serviceAccountsInPU += $user
                }
            } catch { }
        }

        if ($serviceAccountsInPU.Count -gt 0) {
            Write-Host "    [!] $($serviceAccountsInPU.Count) service account(s) with SPNs found IN Protected Users" `
                -ForegroundColor Yellow
            foreach ($svc in $serviceAccountsInPU) {
                Add-Finding -ObjectDN $svc.DistinguishedName `
                    -FindingType "ServiceAccountInProtectedUsers" -Severity "MEDIUM" `
                    -Description "Service account '$($svc.SamAccountName)' has SPN(s) registered and is a member of Protected Users. Protected Users disables Kerberos delegation and NTLM -- services using this account for authentication may fail. Review whether this account should be in Protected Users." `
                    -NISTControl "AC-6"
                Write-Host "    Service account in Protected Users: $($svc.SamAccountName)" -ForegroundColor Yellow
            }
        } else {
            Write-Host "    [OK] No service accounts with SPNs found inside Protected Users" -ForegroundColor Green
        }

    } catch {
        Write-Host "    [!] Protected Users check failed: $($_.Exception.Message)" -ForegroundColor Yellow
        Add-Finding -ObjectDN $Domain -FindingType "ProtectedUsersCheckFailed" -Severity "MEDIUM" `
            -Description "Protected Users analysis failed: $($_.Exception.Message)" `
            -NISTControl "AC-6"
    }

    # =========================================================================
    # CHECK 4: WHfB Kerberos Hybrid Trust Prerequisites
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [4/5] Windows Hello for Business Kerberos hybrid trust..." -ForegroundColor DarkCyan

    # 4a: Domain functional level (WHfB requires >= 2016)
    try {
        $domMode   = $domainObj.DomainMode.ToString()
        $forestObj = Get-ADForest
        $forMode   = $forestObj.ForestMode.ToString()

        $legacyModes = @(
            "Windows2003Domain","Windows2008Domain","Windows2008R2Domain",
            "Windows2012Domain","Windows2012R2Domain"
        )
        if ($domMode -in $legacyModes) {
            Add-Finding -ObjectDN $Domain -FindingType "WHfBFunctionalLevelTooLow" -Severity "HIGH" `
                -Description "Domain functional level is $domMode. Windows Hello for Business Kerberos hybrid trust requires Windows Server 2016 domain functional level or higher. WHfB will not function correctly in this environment until the DFL is raised." `
                -NISTControl "IA-2(1)"
            Write-Host "    [!] Domain FL ($domMode) is too low for WHfB hybrid trust (need >= 2016)" -ForegroundColor Yellow
        } else {
            Write-Host "    [OK] Domain FL ($domMode) supports WHfB" -ForegroundColor Green
        }

    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "Could not check functional level for WHfB: $($_.Exception.Message)"
    }

    # 4b: Azure AD Kerberos server object
    $azureKerbDN = "CN=AzureADKerberos,OU=Domain Controllers,$domainDN"
    try {
        $azureKerbObj = Get-ADObject -Identity $azureKerbDN -Properties * -Server $Domain -ErrorAction Stop

        Write-Host "    [OK] Azure AD Kerberos server object found: $azureKerbDN" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "WHfB: Azure AD Kerberos server object present"

        # Check msDS-KeyCredentialLink -- should be set on the AzureADKerberos object
        $kcl = $azureKerbObj."msDS-KeyCredentialLink"
        if ($null -eq $kcl -or $kcl.Count -eq 0) {
            Add-Finding -ObjectDN $azureKerbDN -FindingType "WHfBKeyCredentialLinkMissing" -Severity "HIGH" `
                -Description "Azure AD Kerberos server object exists but has no msDS-KeyCredentialLink attribute. This may indicate the AzureADKerberos server was not properly initialised. Re-run: Set-AzureADKerberosServer in the AzureAD PowerShell module to re-initialise." `
                -NISTControl "IA-2(1), SC-8"
            Write-Host "    [!] AzureADKerberos msDS-KeyCredentialLink is empty" -ForegroundColor Yellow
        } else {
            Write-Host "    [OK] AzureADKerberos msDS-KeyCredentialLink is populated ($($kcl.Count) entry/ies)" -ForegroundColor Green
        }

        Add-Finding -ObjectDN $azureKerbDN -FindingType "WHfBServerObjectPresent" -Severity "INFO" `
            -Description "Azure AD Kerberos server object is present and initialised. WHfB Kerberos hybrid trust infrastructure is in place." `
            -NISTControl "IA-2(1)"

    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "Cannot find an object with identity") {
            Add-Finding -ObjectDN $azureKerbDN -FindingType "WHfBServerObjectMissing" -Severity "HIGH" `
                -Description "Azure AD Kerberos server object (CN=AzureADKerberos) not found in Domain Controllers OU. WHfB Kerberos hybrid trust will not function. If WHfB is deployed, run: Set-AzureADKerberosServer -Domain '$Domain' -UserPrincipalName <GAAAccount> to create it." `
                -NISTControl "IA-2(1)"
            Write-Host "    [!] Azure AD Kerberos server object NOT found -- WHfB hybrid trust not configured" -ForegroundColor Yellow
        } else {
            Write-AgentLog -Level WARN -Milestone $ms -Message "WHfB object check failed: $errMsg"
            Write-Host "    [!] WHfB object check failed: $errMsg" -ForegroundColor Yellow
        }
    }

    # 4c: Sample msDS-KeyCredentialLink on user objects (WHfB device trust registration)
    try {
        $whfbUsers = @(Get-ADUser -Filter * -Properties "msDS-KeyCredentialLink" -Server $Domain `
            -ResultSetSize 500 |
            Where-Object { $_."msDS-KeyCredentialLink".Count -gt 0 })

        $totalUsers = @(Get-ADUser -Filter * -Server $Domain -ResultSetSize 500).Count

        Write-Host "    WHfB device registrations: $($whfbUsers.Count) of $totalUsers sampled users have msDS-KeyCredentialLink set" `
            -ForegroundColor Gray
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "WHfB: $($whfbUsers.Count) users with msDS-KeyCredentialLink (sample of $totalUsers)"

        Add-Finding -ObjectDN $Domain -FindingType "WHfBDeviceRegistrationSample" -Severity "INFO" `
            -Description "WHfB device registration sample: $($whfbUsers.Count) of $totalUsers sampled users have msDS-KeyCredentialLink populated (indicates active WHfB enrollment)." `
            -NISTControl "IA-2(1)"

    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "WHfB user sample check failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # CHECK 5: Authentication Policy and Silo Inventory
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [5/5] Authentication Policy and Silo inventory..." -ForegroundColor DarkCyan

    # 5a: Authentication Policies
    try {
        $authPolicies = @(Get-ADAuthenticationPolicy -Filter * -Server $Domain)
        if ($authPolicies.Count -eq 0) {
            Write-Host "    No Authentication Policies configured" -ForegroundColor Gray
            Add-Finding -ObjectDN $Domain -FindingType "NoAuthenticationPolicies" -Severity "LOW" `
                -Description "No Authentication Policies are configured. Authentication Policies can restrict which accounts can authenticate to specific services and enforce TGT lifetime controls for Tier 0 accounts. Consider implementing a policy for Domain Admins (e.g. TGT lifetime of 4 hours)." `
                -NISTControl "AC-2, AC-6"
        } else {
            Write-Host "    Found $($authPolicies.Count) Authentication Policy/ies:" -ForegroundColor Gray
            foreach ($pol in $authPolicies) {
                Write-Host "      $($pol.Name) -- UserTGTLifetimeMins=$($pol.UserTGTLifetimeMins)" -ForegroundColor Gray
            }
            Add-Finding -ObjectDN $Domain -FindingType "AuthenticationPolicyInventory" -Severity "INFO" `
                -Description "Authentication Policies in use: $($authPolicies.Count). See Data for details." `
                -NISTControl "AC-2, AC-6" `
                -Data ($authPolicies | Select-Object Name, UserTGTLifetimeMins, Description)
        }

    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "not recognized" -or $errMsg -match "not available" -or $errMsg -match "module") {
            Write-Host "    Get-ADAuthenticationPolicy not available (check RSAT/functional level)" -ForegroundColor DarkYellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "Get-ADAuthenticationPolicy not available: $errMsg"
        } else {
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "Authentication policy query failed: $errMsg"
        }
    }

    # 5b: Authentication Policy Silos
    try {
        $authSilos = @(Get-ADAuthenticationPolicySilo -Filter * -Server $Domain)
        if ($authSilos.Count -eq 0) {
            Write-Host "    No Authentication Policy Silos configured" -ForegroundColor Gray
            Add-Finding -ObjectDN $Domain -FindingType "NoAuthenticationPolicySilos" -Severity "LOW" `
                -Description "No Authentication Policy Silos are configured. Silos allow you to scope Authentication Policies to specific groups of accounts (e.g. Tier 0 admins, service accounts). Implementing a Tier 0 silo with a restrictive Authentication Policy significantly reduces lateral movement risk." `
                -NISTControl "AC-2, AC-6"
        } else {
            Write-Host "    Found $($authSilos.Count) Authentication Policy Silo(s):" -ForegroundColor Gray
            foreach ($silo in $authSilos) {
                $siloMembers = @()
                try {
                    $siloMembers = @($silo.Members)
                } catch { }
                Write-Host "      $($silo.Name) -- $($siloMembers.Count) member(s)" -ForegroundColor Gray
            }

            # Tier 0 accounts not assigned to any silo
            $allSiloMembers = @()
            foreach ($silo in $authSilos) {
                if ($silo.Members.Count -gt 0) {
                    $allSiloMembers += @($silo.Members | ForEach-Object { $_.ToString().ToLower() })
                }
            }

            $tier0NotInSilo = @($tier0Accounts | Where-Object {
                $dn = $_.DistinguishedName.ToLower()
                $allSiloMembers -notcontains $dn
            })

            if ($tier0NotInSilo.Count -gt 0) {
                Write-Host "    [!] $($tier0NotInSilo.Count) Tier 0 account(s) not assigned to any Authentication Policy Silo" `
                    -ForegroundColor Yellow
                foreach ($acct in $tier0NotInSilo) {
                    Add-Finding -ObjectDN $acct.DistinguishedName -FindingType "Tier0NotInAuthSilo" -Severity "MEDIUM" `
                        -Description "Tier 0 account '$($acct.SamAccountName)' is not assigned to an Authentication Policy Silo. Silos exist but this account falls outside their scope -- its TGT lifetime and service access are not restricted by a policy." `
                        -NISTControl "AC-2, AC-6"
                }
            } else {
                Write-Host "    [OK] All Tier 0 accounts are covered by an Authentication Policy Silo" -ForegroundColor Green
            }

            Add-Finding -ObjectDN $Domain -FindingType "AuthenticationSiloInventory" -Severity "INFO" `
                -Description "Authentication Policy Silos in use: $($authSilos.Count)." `
                -NISTControl "AC-2, AC-6" `
                -Data ($authSilos | Select-Object Name, Description)
        }

    } catch {
        $errMsg = $_.Exception.Message
        if ($errMsg -match "not recognized" -or $errMsg -match "not available" -or $errMsg -match "module") {
            Write-Host "    Get-ADAuthenticationPolicySilo not available (check RSAT/functional level)" -ForegroundColor DarkYellow
        } else {
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "Authentication silo query failed: $errMsg"
        }
    }

    # =========================================================================
    # Remediation Phase
    # =========================================================================
    if ($Mode -ne "Remediate") {
        $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
        Write-Host ""
        Write-Host "  M6 complete -- $($msFindings.Count) actionable finding(s)" `
            -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "M6 complete (Discover). Actionable findings: $($msFindings.Count)"
        return
    }

    $totalRemediable = $rc4Items.Count + $notProtectedItems.Count
    if ($totalRemediable -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No remediable items. Kerberos policy and WHfB checks are Discover-only." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "M6 Remediate: no remediable items"
        return
    }

    Write-Host ""
    Write-Host "  --- Remediation Phase ---" -ForegroundColor Cyan
    Write-Host "  Checks 1 (Ticket Policy), 4 (WHfB), 5 (Auth Policies) are Discover-only." -ForegroundColor DarkYellow
    Write-Host "  Remediable items: $totalRemediable" -ForegroundColor Cyan
    Write-Host ""

    try {

        # -- 2a: Enable AES on RC4-only accounts -------------------------------
        if ($rc4Items.Count -gt 0) {
            Write-Host "  --- RC4-only Accounts ($($rc4Items.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $rc4Items) {
                $riskLevel = if ($item.IsTier0) { "CRITICAL" } else { "HIGH" }

                $approved = Invoke-HumanApproval `
                    -Action    "Enable AES encryption on RC4-only account" `
                    -Target    "$($item.ObjectName) ($($item.ObjectDN))" `
                    -Implications @(
                        "msDS-SupportedEncryptionTypes will be set to AES128 + AES256 on '$($item.ObjectName)'.",
                        "RC4 will no longer be offered for this account's Kerberos authentication.",
                        "PASSWORD RESET REQUIRED after this change to generate new AES Kerberos keys.",
                        "Until the password is reset, the account continues using RC4 keys from the last set.",
                        "Coordinate with account owners and any services running under this identity.",
                        "Password age is $($item.PwdAgeDays) days -- include reset in this change window."
                    ) `
                    -RollbackSteps @(
                        "Set-ADUser -Identity '$($item.ObjectName)' -KerberosEncryptionType RC4",
                        "Reset the account password to restore original Kerberos session keys"
                    ) `
                    -RiskLevel $riskLevel `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Set-ADUser -Identity $item.ObjectDN `
                        -KerberosEncryptionType AES128, AES256 `
                        -Server $Domain -ErrorAction Stop

                    Write-Host "  [OK] AES128+AES256 enabled on $($item.ObjectName)" -ForegroundColor Green
                    Write-Host "  [!] PASSWORD RESET REQUIRED on $($item.ObjectName)" -ForegroundColor Yellow
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Enabled AES128+AES256 on '$($item.ObjectName)'. PASSWORD RESET REQUIRED."

                    Add-Finding -ObjectDN $item.ObjectDN `
                        -FindingType "PendingPasswordReset" -Severity "MEDIUM" `
                        -Description "AES encryption was enabled on '$($item.ObjectName)' in this run. A password reset is required to generate new AES Kerberos keys -- account remains RC4-capable until reset." `
                        -NISTControl "IA-5(1)"

                } catch {
                    Write-Host "  [!] Failed on $($item.ObjectName)`: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "AES update failed for '$($item.ObjectName)': $($_.Exception.Message)"
                }
            }
        }

        # -- 3a: Add privileged accounts to Protected Users -------------------
        if ($notProtectedItems.Count -gt 0) {
            Write-Host ""
            Write-Host "  --- Add to Protected Users ($($notProtectedItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $notProtectedItems) {
                $approved = Invoke-HumanApproval `
                    -Action    "Add privileged account to Protected Users group" `
                    -Target    "$($item.ObjectName) ($($item.ObjectDN))" `
                    -Implications @(
                        "'$($item.ObjectName)' will be added to the Protected Users security group.",
                        "Effect: NTLM authentication disabled for this account (Kerberos only).",
                        "Effect: DES and RC4 Kerberos encryption disabled (AES only).",
                        "Effect: Kerberos unconstrained and constrained delegation disabled.",
                        "Effect: Kerberos TGT lifetime capped at 4 hours (not renewable).",
                        "Effect: Cached domain credentials disabled for this account.",
                        "DO NOT add service accounts that use Kerberos delegation -- they will break.",
                        "Account is in: $($item.Groups)"
                    ) `
                    -RollbackSteps @(
                        "Remove-ADGroupMember -Identity 'Protected Users' -Members '$($item.ObjectName)' -Confirm:`$false"
                    ) `
                    -RiskLevel "MEDIUM" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Add-ADGroupMember -Identity "Protected Users" `
                        -Members $item.ObjectDN `
                        -Server $Domain -ErrorAction Stop

                    Write-Host "  [OK] Added '$($item.ObjectName)' to Protected Users" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Added '$($item.ObjectName)' to Protected Users group"
                } catch {
                    Write-Host "  [!] Failed on $($item.ObjectName)`: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to add '$($item.ObjectName)' to Protected Users: $($_.Exception.Message)"
                }
            }
        }

    } catch {
        if ($_.Exception.Message -eq "MILESTONE_QUIT") {
            Write-Host "  [!] M6 remediation stopped by operator." -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "M6 remediation quit by operator"
        } else {
            throw
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M6 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "M6 complete. Actionable findings: $($msFindings.Count)"
}
