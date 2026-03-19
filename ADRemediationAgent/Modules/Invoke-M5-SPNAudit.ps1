#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 5 -- SPN Audit

    Checks:
      1. SPN Inventory
         Full domain SPN export to CSV. Always runs. INFO finding.

      2. Duplicate SPN Detection  [Discover-only]
         Pure PowerShell domain-wide scan + setspn -X -F cross-check.
         Duplicate SPNs cause Kerberos TGS failures -- the wrong account
         receives the service ticket. Application owners must decide which
         registration to remove before auto-remediation is safe.
         NIST: IA-5, SC-8

      3. SPNs on Disabled Accounts  [Remediable]
         Orphaned SPNs on disabled users and computer accounts.
         Safe to remove -- the service is not running.
         CIS Control 5 (Account Management)
         NIST: AC-2, IA-5

      4. Kerberoastable Accounts  [Remediable -- update encryption types]
         User accounts (not computers) with SPNs and no AES encryption support
         (msDS-SupportedEncryptionTypes lacks 0x8/0x10 flags, or is 0/unset).
         These accounts produce RC4-encrypted TGS tickets crackable offline.
         Remediation: update KerberosEncryptionType to AES128+AES256.
         NOTE: password reset is required after to generate new AES keys.
         CIS Control 5, CIS-adjacent
         NIST: IA-5, IA-5(1), SC-28

      5. SPNs on High-Privilege Accounts  [Remediable -- remove SPN, CRITICAL]
         SPNs on members of Domain Admins, Enterprise Admins, Schema Admins.
         A Kerberoastable Domain Admin is a single-step domain compromise.
         Service accounts should never hold Tier 0 group membership.
         NIST: AC-2, AC-6, IA-5

    Remediation scope:
      - Checks 3 and 5: remove the SPN from the object (Set-ADObject)
      - Check 4: update msDS-SupportedEncryptionTypes (Set-ADUser)
      - Check 2: Discover-only (application owners must validate before removal)

    msDS-SupportedEncryptionTypes bit flags:
      0x01 = DES-CBC-CRC   0x02 = DES-CBC-MD5
      0x04 = RC4-HMAC      0x08 = AES128-CTS-HMAC-SHA1
      0x10 = AES256-CTS-HMAC-SHA1
      AES supported = ($value -band 0x18) -gt 0
      Value 0 (unset) = domain default (RC4 on pre-2025 functional levels)
#>

function Invoke-M5 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M5"

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

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M5 - SPN Audit"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M5 : SPN Audit" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # =========================================================================
    # Load privileged group membership for cross-reference (Check 5)
    # =========================================================================
    $tier0Accounts = @()
    try {
        $tier0Groups = @("Domain Admins", "Enterprise Admins", "Schema Admins")
        foreach ($grp in $tier0Groups) {
            $members = @()
            try {
                $members = @(Get-ADGroupMember -Identity $grp -Recursive -Server $Domain |
                    Where-Object { $_.objectClass -eq "user" })
            } catch { }
            $tier0Accounts += $members | Select-Object -ExpandProperty SamAccountName
        }
        $tier0Accounts = @($tier0Accounts | Sort-Object -Unique)
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "Tier 0 account list built: $($tier0Accounts.Count) accounts across Domain/Enterprise/Schema Admins"
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "Could not build Tier 0 account list: $($_.Exception.Message)"
    }

    # =========================================================================
    # CHECK 1: SPN Inventory -- full domain scan
    # =========================================================================
    Write-Host "  -> [1/5] Building SPN inventory..." -ForegroundColor DarkCyan

    $allSpnObjects  = @()
    $spnInventory   = [System.Collections.Generic.List[PSCustomObject]]::new()
    # Keyed by normalised SPN string -> list of object DNs (for duplicate detection)
    $spnMap         = @{}

    try {
        # Query users, computers, and managed service accounts
        $adProperties = @(
            "ServicePrincipalName",
            "Enabled",
            "SamAccountName",
            "DistinguishedName",
            "msDS-SupportedEncryptionTypes",
            "PasswordLastSet",
            "ObjectClass"
        )

        $allSpnObjects = @(
            Get-ADObject -Filter { ServicePrincipalName -like "*" } `
                -Properties $adProperties -Server $Domain |
            Where-Object { $_.ServicePrincipalName.Count -gt 0 }
        )

        Write-Host "    Found $($allSpnObjects.Count) object(s) with SPNs registered" -ForegroundColor Gray
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "SPN scan: $($allSpnObjects.Count) objects with SPNs found in domain"

        foreach ($obj in $allSpnObjects) {
            $encTypes   = $obj."msDS-SupportedEncryptionTypes"
            $hasAES     = ($null -ne $encTypes) -and (($encTypes -band 0x18) -gt 0)
            $encDisplay = if ($null -eq $encTypes -or $encTypes -eq 0) {
                "Not set (domain default RC4)"
            } elseif ($hasAES -and ($encTypes -band 0x04)) {
                "RC4 + AES ($encTypes)"
            } elseif ($hasAES) {
                "AES only ($encTypes)"
            } else {
                "RC4/DES only ($encTypes)"
            }

            $isTier0 = $tier0Accounts -contains $obj.SamAccountName
            $pwdAge  = if ($obj.PasswordLastSet) {
                (New-TimeSpan -Start $obj.PasswordLastSet -End (Get-Date)).Days
            } else {
                -1
            }

            foreach ($spn in $obj.ServicePrincipalName) {
                $spnRow = [PSCustomObject]@{
                    SPN             = $spn
                    ObjectName      = $obj.SamAccountName
                    ObjectClass     = $obj.ObjectClass
                    DN              = $obj.DistinguishedName
                    Enabled         = $obj.Enabled
                    EncTypes        = $encDisplay
                    HasAES          = $hasAES
                    IsTier0         = $isTier0
                    PasswordAgeDays = $pwdAge
                }
                $spnInventory.Add($spnRow)

                # Populate the duplicate-detection map
                $key = $spn.ToLower()
                if (-not $spnMap.ContainsKey($key)) {
                    $spnMap[$key] = [System.Collections.Generic.List[PSCustomObject]]::new()
                }
                $spnMap[$key].Add([PSCustomObject]@{
                    ObjectDN   = $obj.DistinguishedName
                    ObjectName = $obj.SamAccountName
                    Enabled    = $obj.Enabled
                })
            }
        }

        # Export inventory CSV
        $csvPath = "$OutputPath\Reports\M5-SPNInventory-$Global:RunTimestamp.csv"
        $spnInventory | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "    SPN inventory exported: $csvPath" -ForegroundColor Gray
        Write-AgentLog -Level INFO -Milestone $ms -Message "SPN inventory CSV: $csvPath"

        Add-Finding -ObjectDN $Domain -FindingType "SPNInventory" -Severity "INFO" `
            -Description "SPN inventory: $($spnInventory.Count) SPN registration(s) across $($allSpnObjects.Count) object(s). Full CSV at $csvPath" `
            -NISTControl "IA-5" `
            -Data @{ TotalSPNs = $spnInventory.Count; TotalObjects = $allSpnObjects.Count; CSVPath = $csvPath }

    } catch {
        Add-Finding -ObjectDN $Domain -FindingType "SPNInventoryFailed" -Severity "HIGH" `
            -Description "SPN inventory query failed: $($_.Exception.Message)" `
            -NISTControl "IA-5"
        Write-Host "    [!] SPN inventory failed: $($_.Exception.Message)" -ForegroundColor Red
        return
    }

    # =========================================================================
    # CHECK 2: Duplicate SPN Detection -- Discover-only
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [2/5] Duplicate SPN detection..." -ForegroundColor DarkCyan

    $duplicateGroups = @(
        $spnMap.GetEnumerator() | Where-Object { $_.Value.Count -gt 1 }
    )

    if ($duplicateGroups.Count -eq 0) {
        Write-Host "    [OK] No duplicate SPNs detected" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "Duplicate SPN scan: no duplicates found"
    } else {
        Write-Host "    [!] $($duplicateGroups.Count) duplicate SPN(s) detected" -ForegroundColor Yellow

        foreach ($dup in $duplicateGroups) {
            $spnVal   = $dup.Key
            $owners   = @($dup.Value)
            $ownerStr = ($owners | ForEach-Object { $_.ObjectName }) -join " | "

            Write-Host "    Duplicate: $spnVal" -ForegroundColor Red
            foreach ($owner in $owners) {
                Write-Host "      -> $($owner.ObjectName) ($($owner.ObjectDN))" -ForegroundColor Gray
            }

            Add-Finding -ObjectDN $spnVal -FindingType "DuplicateSPN" -Severity "HIGH" `
                -Description "SPN '$spnVal' is registered on $($owners.Count) objects: $ownerStr. Duplicate SPNs cause Kerberos TGS failures -- clients receive a KRB_ERR_S_PRINCIPAL_UNKNOWN or are issued a ticket for the wrong account. Application owners must confirm which registration is correct before removal." `
                -CISControl "5" -CISLevel "L1" -NISTControl "IA-5, SC-8" `
                -Data $owners
        }

        Write-Host ""
        Write-Host "    [NOTE] Duplicate SPN remediation is Discover-only." -ForegroundColor DarkYellow
        Write-Host "           Engage application owners to confirm the correct owner" -ForegroundColor DarkYellow
        Write-Host "           then remove the incorrect registration with:" -ForegroundColor DarkYellow
        Write-Host "           setspn -D <SPN> <AccountName>" -ForegroundColor DarkCyan
        Write-Host ""
    }

    # Cross-check with setspn -X -F (forest-wide, independent validation)
    Write-Host "  -> Running setspn -X -F cross-check..." -ForegroundColor DarkCyan
    try {
        $setspnOutput = @(& setspn -X -F 2>&1)
        $setspnFound  = @($setspnOutput | Where-Object { $_ -match "SPN Found!" })

        if ($setspnFound.Count -gt 0) {
            Write-Host "    [!] setspn -X -F confirms $($setspnFound.Count) duplicate group(s)" -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms `
                -Message "setspn -X -F found $($setspnFound.Count) duplicate SPN group(s)"
        } else {
            Write-Host "    [OK] setspn -X -F confirms no forest-wide duplicates" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms -Message "setspn -X -F: no duplicates confirmed"
        }

        # Save raw setspn output
        $setspnLog = "$OutputPath\Reports\M5-setspn-XF-$Global:RunTimestamp.txt"
        $setspnOutput | Out-File -FilePath $setspnLog -Encoding UTF8
        Write-AgentLog -Level INFO -Milestone $ms -Message "setspn -X -F output saved: $setspnLog"

    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "setspn not available or failed: $($_.Exception.Message)"
        Write-Host "    [!] setspn not in PATH or failed -- PowerShell scan only" -ForegroundColor Yellow
    }

    # =========================================================================
    # Remediable finding collections
    # =========================================================================
    $disabledSpnItems   = [System.Collections.Generic.List[PSCustomObject]]::new()
    $kerberoastItems    = [System.Collections.Generic.List[PSCustomObject]]::new()
    $tier0SpnItems      = [System.Collections.Generic.List[PSCustomObject]]::new()

    # =========================================================================
    # CHECK 3: SPNs on Disabled Accounts
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [3/5] SPNs on disabled accounts..." -ForegroundColor DarkCyan

    $disabledWithSpn = @($allSpnObjects | Where-Object { $_.Enabled -eq $false })

    if ($disabledWithSpn.Count -eq 0) {
        Write-Host "    [OK] No disabled accounts have SPNs registered" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "Disabled account SPN check: clean"
    } else {
        Write-Host "    [!] $($disabledWithSpn.Count) disabled account(s) have SPN(s) registered" -ForegroundColor Yellow

        foreach ($obj in $disabledWithSpn) {
            $spnList = @($obj.ServicePrincipalName)
            Write-Host "    Disabled: $($obj.SamAccountName) -- $($spnList.Count) SPN(s)" -ForegroundColor Yellow
            foreach ($spn in $spnList) {
                Write-Host "      SPN: $spn" -ForegroundColor Gray
            }

            Add-Finding -ObjectDN $obj.DistinguishedName -FindingType "SPNOnDisabledAccount" -Severity "MEDIUM" `
                -Description "Disabled account '$($obj.SamAccountName)' has $($spnList.Count) SPN(s) registered. Orphaned SPNs on disabled accounts pollute the SPN namespace and can cause duplicate conflicts when the service is re-registered. Safe to remove." `
                -CISControl "5" -CISLevel "L1" -NISTControl "AC-2, IA-5" `
                -Data $spnList

            foreach ($spn in $spnList) {
                $disabledSpnItems.Add([PSCustomObject]@{
                    ObjectDN   = $obj.DistinguishedName
                    ObjectName = $obj.SamAccountName
                    SPN        = $spn
                })
            }
        }
    }

    # =========================================================================
    # CHECK 4: Kerberoastable Accounts (user accounts with SPNs, no AES)
    # Computers are excluded -- machine account tickets use AES by default
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [4/5] Kerberoastable accounts (SPN + no AES encryption)..." -ForegroundColor DarkCyan

    $kerberoastable = @(
        $allSpnObjects |
        Where-Object {
            $_.ObjectClass -eq "user" -and
            $_.Enabled -eq $true
        } |
        Where-Object {
            $encVal = $_."msDS-SupportedEncryptionTypes"
            ($null -eq $encVal) -or ($encVal -eq 0) -or (($encVal -band 0x18) -eq 0)
        }
    )

    if ($kerberoastable.Count -eq 0) {
        Write-Host "    [OK] No Kerberoastable user accounts detected" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "Kerberoastable check: no vulnerable accounts"
    } else {
        Write-Host "    [!] $($kerberoastable.Count) Kerberoastable account(s) found" -ForegroundColor Yellow

        foreach ($obj in $kerberoastable) {
            $encVal    = $obj."msDS-SupportedEncryptionTypes"
            $encStr    = if ($null -eq $encVal -or $encVal -eq 0) { "Not set (RC4 default)" } else { $encVal.ToString() }
            $pwdAge    = if ($obj.PasswordLastSet) {
                (New-TimeSpan -Start $obj.PasswordLastSet -End (Get-Date)).Days
            } else { -1 }
            $tier0Flag = if ($tier0Accounts -contains $obj.SamAccountName) { " [TIER 0 ACCOUNT]" } else { "" }
            $spnList   = @($obj.ServicePrincipalName)

            $severity = if ($tier0Accounts -contains $obj.SamAccountName) { "CRITICAL" } else { "HIGH" }

            Write-Host "    Kerberoastable: $($obj.SamAccountName)$tier0Flag" -ForegroundColor $(if ($severity -eq "CRITICAL") { "Magenta" } else { "Yellow" })
            Write-Host "      EncTypes   : $encStr" -ForegroundColor Gray
            Write-Host "      PwdAge     : $pwdAge days" -ForegroundColor Gray
            Write-Host "      SPN count  : $($spnList.Count)" -ForegroundColor Gray

            Add-Finding -ObjectDN $obj.DistinguishedName -FindingType "KerberoastableAccount" `
                -Severity $severity `
                -Description "Account '$($obj.SamAccountName)'$tier0Flag has SPN(s) registered with no AES encryption support (msDS-SupportedEncryptionTypes=$encStr). Any TGS ticket for this account will be RC4-encrypted and crackable offline without domain credentials. Password age: $pwdAge days." `
                -CISControl "5" -CISLevel "L1" -NISTControl "IA-5, IA-5(1), SC-28" `
                -Data @{ EncTypes = $encStr; PasswordAgeDays = $pwdAge; SPNs = $spnList }

            $kerberoastItems.Add([PSCustomObject]@{
                ObjectDN    = $obj.DistinguishedName
                ObjectName  = $obj.SamAccountName
                EncTypes    = $encStr
                PwdAgeDays  = $pwdAge
                IsTier0     = ($tier0Accounts -contains $obj.SamAccountName)
                Severity    = $severity
            })
        }
    }

    # =========================================================================
    # CHECK 5: SPNs on High-Privilege (Tier 0) Accounts
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [5/5] SPNs on Tier 0 privileged accounts..." -ForegroundColor DarkCyan

    $tier0WithSpn = @(
        $allSpnObjects |
        Where-Object {
            $_.ObjectClass -eq "user" -and
            ($tier0Accounts -contains $_.SamAccountName)
        }
    )

    if ($tier0WithSpn.Count -eq 0) {
        Write-Host "    [OK] No Tier 0 privileged accounts have SPNs registered" -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "Tier 0 SPN check: clean"
    } else {
        Write-Host "    [!] $($tier0WithSpn.Count) Tier 0 account(s) have SPN(s) -- CRITICAL Kerberoasting risk" `
            -ForegroundColor Magenta

        foreach ($obj in $tier0WithSpn) {
            $spnList = @($obj.ServicePrincipalName)
            Write-Host "    CRITICAL: $($obj.SamAccountName) is Tier 0 and has $($spnList.Count) SPN(s)" -ForegroundColor Magenta
            foreach ($spn in $spnList) {
                Write-Host "      SPN: $spn" -ForegroundColor Gray
            }

            Add-Finding -ObjectDN $obj.DistinguishedName -FindingType "Tier0AccountHasSPN" -Severity "CRITICAL" `
                -Description "Tier 0 account '$($obj.SamAccountName)' has SPN(s) registered: $($spnList -join '; '). A Kerberoastable Domain/Enterprise/Schema Admin is a single offline crack away from full domain compromise. Service accounts must never hold Tier 0 group membership. Remediation: remove the SPN, or remove the account from the privileged group." `
                -CISControl "5" -CISLevel "L1" -NISTControl "AC-2, AC-6, IA-5" `
                -Data $spnList

            foreach ($spn in $spnList) {
                $tier0SpnItems.Add([PSCustomObject]@{
                    ObjectDN   = $obj.DistinguishedName
                    ObjectName = $obj.SamAccountName
                    SPN        = $spn
                })
            }
        }
    }

    # =========================================================================
    # Remediation Phase
    # =========================================================================
    if ($Mode -ne "Remediate") {
        $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
        Write-Host ""
        Write-Host "  M5 complete -- $($msFindings.Count) actionable finding(s)" `
            -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "M5 complete (Discover). Actionable findings: $($msFindings.Count)"
        return
    }

    $totalRemediable = $disabledSpnItems.Count + $kerberoastItems.Count + $tier0SpnItems.Count

    if ($totalRemediable -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No remediable items (duplicates are Discover-only)." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "M5 Remediate: no remediable items"
        return
    }

    Write-Host ""
    Write-Host "  --- Remediation Phase ---" -ForegroundColor Cyan
    Write-Host "  Duplicate SPNs (Check 2) require manual application owner review -- skipped." -ForegroundColor DarkYellow
    Write-Host "  Remediable items: $totalRemediable" -ForegroundColor Cyan
    Write-Host ""

    try {

        # -- 3a: Remove SPNs from disabled accounts ----------------------------
        if ($disabledSpnItems.Count -gt 0) {
            Write-Host "  --- Disabled Account SPNs ($($disabledSpnItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $disabledSpnItems) {
                $approved = Invoke-HumanApproval `
                    -Action    "Remove SPN from disabled account" `
                    -Target    "$($item.ObjectName) ($($item.ObjectDN))" `
                    -Implications @(
                        "SPN '$($item.SPN)' will be removed from disabled account '$($item.ObjectName)'.",
                        "The account is already disabled -- no running service uses this SPN.",
                        "If the account is later re-enabled and the service restarted, the SPN must be re-registered."
                    ) `
                    -RollbackSteps @(
                        "setspn -S '$($item.SPN)' '$($item.ObjectName)'"
                    ) `
                    -RiskLevel "LOW" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Set-ADObject -Identity $item.ObjectDN `
                        -Remove @{ servicePrincipalName = $item.SPN } `
                        -Server $Domain -ErrorAction Stop
                    Write-Host "  [OK] Removed SPN '$($item.SPN)' from $($item.ObjectName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Removed SPN '$($item.SPN)' from disabled account '$($item.ObjectName)' ($($item.ObjectDN))"
                } catch {
                    Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to remove SPN '$($item.SPN)' from '$($item.ObjectName)': $($_.Exception.Message)"
                }
            }
        }

        # -- 4a: Update encryption types on Kerberoastable accounts -----------
        if ($kerberoastItems.Count -gt 0) {
            Write-Host ""
            Write-Host "  --- Kerberoastable Accounts ($($kerberoastItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $kerberoastItems) {
                $riskLevel = if ($item.IsTier0) { "CRITICAL" } else { "HIGH" }

                $approved = Invoke-HumanApproval `
                    -Action    "Enable AES encryption on Kerberoastable account" `
                    -Target    "$($item.ObjectName) ($($item.ObjectDN))" `
                    -Implications @(
                        "msDS-SupportedEncryptionTypes will be set to AES128 + AES256 on '$($item.ObjectName)'.",
                        "RC4 will be disabled for this account -- TGS tickets will be AES-encrypted.",
                        "The account password MUST be reset after this change for new AES keys to be generated.",
                        "Coordinate with the service owner -- if the service runs as this account, it will need its stored credential updated.",
                        "Password age is $($item.PwdAgeDays) days -- plan the reset as part of this change."
                    ) `
                    -RollbackSteps @(
                        "Set-ADUser -Identity '$($item.ObjectName)' -KerberosEncryptionType RC4",
                        "Reset the service account password to restore original Kerberos keys"
                    ) `
                    -RiskLevel $riskLevel `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Set-ADUser -Identity $item.ObjectDN `
                        -KerberosEncryptionType AES128, AES256 `
                        -Server $Domain -ErrorAction Stop

                    Write-Host "  [OK] AES encryption enabled on $($item.ObjectName)" -ForegroundColor Green
                    Write-Host "  [!] PASSWORD RESET REQUIRED on $($item.ObjectName) to activate AES keys" `
                        -ForegroundColor Yellow
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Enabled AES128+AES256 on '$($item.ObjectName)'. PASSWORD RESET REQUIRED."

                    # Add a follow-up finding to track the pending password reset
                    Add-Finding -ObjectDN $item.ObjectDN `
                        -FindingType "PendingPasswordReset" -Severity "MEDIUM" `
                        -Description "AES encryption was enabled on '$($item.ObjectName)' in this run. A password reset is required to generate AES Kerberos keys -- until reset, the account remains Kerberoastable with RC4." `
                        -NISTControl "IA-5(1)"

                } catch {
                    Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to update encryption types on '$($item.ObjectName)': $($_.Exception.Message)"
                }
            }
        }

        # -- 5a: Remove SPNs from Tier 0 accounts (CRITICAL) ------------------
        if ($tier0SpnItems.Count -gt 0) {
            Write-Host ""
            Write-Host "  --- Tier 0 Account SPNs ($($tier0SpnItems.Count) item(s)) ---" -ForegroundColor White

            foreach ($item in $tier0SpnItems) {
                $approved = Invoke-HumanApproval `
                    -Action    "Remove SPN from Tier 0 privileged account" `
                    -Target    "$($item.ObjectName) ($($item.ObjectDN))" `
                    -Implications @(
                        "SPN '$($item.SPN)' will be removed from Tier 0 account '$($item.ObjectName)'.",
                        "Any service configured to run as '$($item.ObjectName)' and relying on Kerberos SPN authentication WILL BREAK.",
                        "The correct fix is to run the service under a dedicated non-privileged service account.",
                        "Removing the SPN does not remove '$($item.ObjectName)' from Domain Admins or other privileged groups."
                    ) `
                    -RollbackSteps @(
                        "setspn -S '$($item.SPN)' '$($item.ObjectName)'"
                    ) `
                    -RiskLevel "CRITICAL" `
                    -Milestone $ms

                if (-not $approved) { continue }

                try {
                    Set-ADObject -Identity $item.ObjectDN `
                        -Remove @{ servicePrincipalName = $item.SPN } `
                        -Server $Domain -ErrorAction Stop
                    Write-Host "  [OK] Removed SPN '$($item.SPN)' from Tier 0 account $($item.ObjectName)" -ForegroundColor Green
                    Write-AgentLog -Level ACTION -Milestone $ms `
                        -Message "Removed SPN '$($item.SPN)' from Tier 0 account '$($item.ObjectName)' ($($item.ObjectDN))"
                } catch {
                    Write-Host "  [!] Failed: $($_.Exception.Message)" -ForegroundColor Red
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "Failed to remove SPN from Tier 0 account '$($item.ObjectName)': $($_.Exception.Message)"
                }
            }
        }

    } catch {
        if ($_.Exception.Message -eq "MILESTONE_QUIT") {
            Write-Host "  [!] M5 remediation stopped by operator." -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "M5 remediation quit by operator"
        } else {
            throw
        }
    }

    # =========================================================================
    # Summary
    # =========================================================================
    $msFindings = @($Global:FindingsList | Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M5 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "M5 complete. Actionable findings: $($msFindings.Count)"
}
