#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 10 -- Delegated Permissions Review

    Checks:
      1. DCSync Rights Audit  [Discover-only, CRITICAL]
         Enumerates all principals with DS-Replication-Get-Changes-All or
         DS-Replication-Get-Changes extended rights on the domain root NC.
         Any principal that is not a Domain Controller, Domain Admins,
         Enterprise Admins, or Administrators is flagged CRITICAL.
         A DCSync-capable account can extract all password hashes from AD.
         NIST: AC-3, AC-6, IA-2

      2. Domain Root High-Risk ACE Audit  [Discover-only, CRITICAL]
         Enumerates non-inherited Allow ACEs on the domain root NC granting
         GenericAll, WriteDacl, or WriteOwner to non-standard principals.
         These rights allow full domain compromise: DACL manipulation,
         object ownership takeover, and arbitrary attribute writes.
         NIST: AC-3, AC-6, AU-9

      3. AdminSDHolder ACE Audit  [Discover-only, HIGH]
         Enumerates non-standard write/full-control ACEs on
         CN=AdminSDHolder,CN=System,<DomainDN>. SDProp runs every 60 minutes
         and stamps the AdminSDHolder ACL onto all protected group members.
         A backdoor ACE on AdminSDHolder persists across membership changes.
         NIST: AC-2, AC-3, AC-6

      4. DC OU Non-Standard Delegation  [Remediable -- per-ACE approval, CRITICAL]
         Enumerates non-inherited Allow ACEs on OU=Domain Controllers granting
         GenericAll, WriteDacl, WriteOwner, or GenericWrite to non-standard
         principals. Control of the DC OU can be used to push malicious GPOs
         to all Domain Controllers.
         Per-ACE approval with typed confirmation (CRITICAL).
         Rollback: re-add the ACE via Set-Acl if removal was in error.
         NIST: AC-3, AC-6, CM-3

      5. DNS Permissions Audit  [Discover-only, HIGH]
         a) Enumerates members of the DnsAdmins group. DnsAdmins can load
            arbitrary DLLs into the DNS service running on DCs -- full DC
            compromise. Membership should be near-zero.
         b) Enumerates non-standard write ACEs on the MicrosoftDNS container
            in the System partition (CN=MicrosoftDNS,CN=System,<DomainDN>).
            ADIDNS write access can be used for DNS poisoning attacks.
         NIST: AC-3, AC-6, SC-22

      6. DC Computer Object Delegation  [Discover-only, HIGH]
         Enumerates Domain Controller computer objects with constrained or
         unconstrained delegation configured. M4 excludes DCs from its
         unconstrained delegation remediation -- this check surfaces them
         explicitly. Constrained delegation on a DC indicates a non-default
         configuration that should be reviewed.
         NIST: AC-3, IA-2

    Remediation scope:
      Check 4 is remediable (per-ACE approval, CRITICAL risk, typed confirmation).
      All other checks are Discover-only due to blast radius of ACL changes.

    Tooling note:
      ACL enumeration uses Get-Acl via the AD: PSDrive (ActiveDirectory module).
      Requires ActiveDirectory module loaded and AD: PSDrive available.

    CIS Control mapping:
      CIS Control 6 (Access Control Management)

    NIST Controls:
      AC-2, AC-3, AC-6, AU-9, IA-2, SC-22, CM-3
#>

function Invoke-M10 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    Set-StrictMode -Version Latest
    $ms = "M10"

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

    Write-AgentLog -Level INFO -Milestone $ms -Message "Starting milestone M10 - Delegated Permissions Review"
    Write-Host ""
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host "     M10 : Delegated Permissions Review" -ForegroundColor Cyan
    Write-Host "  +---------------------------------------------------------+" -ForegroundColor DarkCyan
    Write-Host ""

    # =========================================================================
    # Domain info + prereq check
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

    $adDriveAvailable = $null -ne (Get-PSDrive -Name AD -ErrorAction SilentlyContinue)
    if (-not $adDriveAvailable) {
        Add-Finding -ObjectDN $Domain -FindingType "ADDriveUnavailable" -Severity "CRITICAL" `
            -Description "The AD: PSDrive is not available. M10 requires the ActiveDirectory module to be loaded and the AD: PSDrive to be accessible for ACL enumeration. All checks that depend on Get-Acl will be skipped." `
            -NISTControl "AC-3, AC-6"
        Write-Host "  [!] AD: PSDrive not available -- ACL-based checks cannot run." -ForegroundColor Red
        Write-Host "  [!] Ensure the ActiveDirectory module is loaded before running M10." -ForegroundColor Red
        return
    }

    # Standard admin principals -- these are expected to hold elevated rights
    $standardAdminPatterns = @(
        "Domain Admins", "Enterprise Admins", "Administrators",
        "NT AUTHORITY", "SYSTEM", "ENTERPRISE DOMAIN CONTROLLERS",
        "BUILTIN\Administrators", "CREATOR OWNER"
    )

    function Test-IsStandardPrincipal {
        param([string]$Principal)
        foreach ($pattern in $standardAdminPatterns) {
            if ($Principal -like "*$pattern*") { return $true }
        }
        return $false
    }

    # DCSync extended right GUIDs (from Microsoft schema)
    $dcSyncGuids = @(
        [System.Guid]"1131f6aa-9c07-11d1-f79f-00c04fc2dcd2",   # DS-Replication-Get-Changes
        [System.Guid]"1131f6ad-9c07-11d1-f79f-00c04fc2dcd2",   # DS-Replication-Get-Changes-All
        [System.Guid]"89e95b76-444d-4c62-991a-0facbeda640c"    # DS-Replication-Get-Changes-In-Filtered-Set
    )

    $dcSyncGuidNames = @{
        "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes"
        "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" = "DS-Replication-Get-Changes-All"
        "89e95b76-444d-4c62-991a-0facbeda640c" = "DS-Replication-Get-Changes-In-Filtered-Set"
    }

    # =========================================================================
    # CHECK 1: DCSync Rights Audit (domain root extended rights)
    # =========================================================================
    Write-Host "  -> [1/6] DCSync rights audit (domain root extended rights)..." -ForegroundColor DarkCyan

    $domainRootACL = $null
    try {
        $domainRootACL = Get-Acl -Path "AD:\$domainDN" -ErrorAction Stop
    } catch {
        Add-Finding -ObjectDN $domainDN -FindingType "DomainRootACLReadFailed" -Severity "HIGH" `
            -Description "Could not read domain root ACL: $($_.Exception.Message). DCSync and domain root checks cannot run." `
            -NISTControl "AC-3"
        Write-Host "  [!] Could not read domain root ACL: $($_.Exception.Message)" -ForegroundColor Red
    }

    $dcSyncFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($null -ne $domainRootACL) {
        foreach ($ace in $domainRootACL.Access) {
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            $rightsStr = $ace.ActiveDirectoryRights.ToString()
            if ($rightsStr -notmatch "ExtendedRight") { continue }

            $aceGuid = $ace.ObjectType.ToString().ToLower()
            $matchedGuid = $null
            foreach ($g in $dcSyncGuids) {
                if ($g.ToString().ToLower() -eq $aceGuid) { $matchedGuid = $g; break }
            }
            if ($null -eq $matchedGuid) { continue }

            $principal  = $ace.IdentityReference.Value
            $rightName  = if ($dcSyncGuidNames.ContainsKey($aceGuid)) { $dcSyncGuidNames[$aceGuid] } else { $aceGuid }
            $isStandard = Test-IsStandardPrincipal $principal

            $sev = if ($rightName -eq "DS-Replication-Get-Changes-All" -and -not $isStandard) {
                "CRITICAL"
            } elseif (-not $isStandard) {
                "HIGH"
            } else {
                "INFO"
            }

            $dcSyncFindings.Add([PSCustomObject]@{
                Principal   = $principal
                Right       = $rightName
                IsStandard  = $isStandard
                Severity    = $sev
            })

            if (-not $isStandard) {
                Add-Finding -ObjectDN $domainDN -FindingType "DCsyncRightNonStandardPrincipal" -Severity $sev `
                    -Description "Non-standard principal '$principal' has '$rightName' on the domain root. This grants DCSync capability -- the account can extract all password hashes from Active Directory. Verify this is a legitimate service account (e.g. Azure AD Connect) and document it. If unexpected, investigate immediately." `
                    -CISControl "6" -CISLevel "1" -NISTControl "AC-3, AC-6, IA-2" `
                    -Data @{ Principal = $principal; Right = $rightName }
                Write-Host "    [$sev] DCSync right: $principal -> $rightName" `
                    -ForegroundColor $(if ($sev -eq "CRITICAL") { "Magenta" } else { "Red" })
            }
        }

        $nonStandardDCSync = @($dcSyncFindings | Where-Object { -not $_.IsStandard })
        if ($nonStandardDCSync.Count -eq 0) {
            Write-Host "    [OK] No non-standard DCSync rights found" -ForegroundColor Green
            Write-AgentLog -Level INFO -Milestone $ms `
                -Message "DCSync audit: $($dcSyncFindings.Count) ACE(s) found, all standard principals"
        } else {
            Write-Host "    [!] $($nonStandardDCSync.Count) non-standard DCSync right(s) found" `
                -ForegroundColor Red
        }

        # Export all DCSync holders (standard and non-standard) for inventory
        if ($dcSyncFindings.Count -gt 0) {
            $dcSyncCsv = "$OutputPath\Reports\M10-DCsyncRights-$Global:RunTimestamp.csv"
            $dcSyncFindings | Export-Csv -Path $dcSyncCsv -NoTypeInformation -Encoding UTF8
            Write-Host "    DCSync rights inventory exported: $dcSyncCsv" -ForegroundColor Gray
        }
    }

    # =========================================================================
    # CHECK 2: Domain Root High-Risk ACE Audit
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [2/6] Domain root high-risk ACE audit (GenericAll, WriteDacl, WriteOwner)..." `
        -ForegroundColor DarkCyan

    $domainRootRiskyACEs = [System.Collections.Generic.List[PSCustomObject]]::new()

    if ($null -ne $domainRootACL) {
        foreach ($ace in $domainRootACL.Access) {
            if ($ace.IsInherited) { continue }
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            $rightsStr = $ace.ActiveDirectoryRights.ToString()
            if ($rightsStr -notmatch "GenericAll|WriteDacl|WriteOwner") { continue }

            $principal  = $ace.IdentityReference.Value
            $isStandard = Test-IsStandardPrincipal $principal
            if ($isStandard) { continue }

            $domainRootRiskyACEs.Add([PSCustomObject]@{
                Principal = $principal
                Rights    = $rightsStr
            })

            Add-Finding -ObjectDN $domainDN -FindingType "DomainRootHighRiskACE" -Severity "CRITICAL" `
                -Description "Non-standard principal '$principal' has '$rightsStr' on the domain root NC. These rights can be used to elevate to Domain Admin: WriteDacl allows granting any right including DCSync; GenericAll provides full control; WriteOwner allows taking ownership. This is an immediate privilege escalation path." `
                -CISControl "6" -CISLevel "1" -NISTControl "AC-3, AC-6, AU-9" `
                -Data @{ Principal = $principal; Rights = $rightsStr }

            Write-Host "    [CRITICAL] Domain root: $principal has $rightsStr" -ForegroundColor Magenta
        }

        if ($domainRootRiskyACEs.Count -eq 0) {
            Write-Host "    [OK] No non-standard high-risk ACEs on domain root" -ForegroundColor Green
        } else {
            Write-Host "    [!] $($domainRootRiskyACEs.Count) high-risk non-standard ACE(s) on domain root" `
                -ForegroundColor Red
        }
    }

    # =========================================================================
    # CHECK 3: AdminSDHolder ACE Audit
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [3/6] AdminSDHolder ACE audit..." -ForegroundColor DarkCyan

    $adminSDHolderDN = "CN=AdminSDHolder,CN=System,$domainDN"
    $adminSDFindings = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $adminSDACL = Get-Acl -Path "AD:\$adminSDHolderDN" -ErrorAction Stop

        foreach ($ace in $adminSDACL.Access) {
            if ($ace.IsInherited) { continue }
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            $rightsStr = $ace.ActiveDirectoryRights.ToString()
            if ($rightsStr -notmatch "GenericAll|WriteDacl|WriteOwner|GenericWrite|WriteProperty") { continue }

            $principal  = $ace.IdentityReference.Value
            $isStandard = Test-IsStandardPrincipal $principal
            if ($isStandard) { continue }

            $sev = if ($rightsStr -match "GenericAll|WriteDacl|WriteOwner") { "CRITICAL" } else { "HIGH" }

            $adminSDFindings.Add([PSCustomObject]@{
                Principal = $principal
                Rights    = $rightsStr
                Severity  = $sev
            })

            Add-Finding -ObjectDN $adminSDHolderDN -FindingType "AdminSDHolderBackdoorACE" -Severity $sev `
                -Description "Non-standard principal '$principal' has '$rightsStr' on CN=AdminSDHolder. SDProp runs every 60 minutes and stamps this ACL onto all protected group members (Domain Admins, etc). This ACE will re-appear on every protected account every hour -- it is effectively a persistent backdoor granting ongoing access to all privileged accounts." `
                -CISControl "6" -CISLevel "1" -NISTControl "AC-2, AC-3, AC-6" `
                -Data @{ Principal = $principal; Rights = $rightsStr }

            Write-Host "    [$sev] AdminSDHolder backdoor ACE: $principal ($rightsStr)" `
                -ForegroundColor $(if ($sev -eq "CRITICAL") { "Magenta" } else { "Red" })
        }

        if ($adminSDFindings.Count -eq 0) {
            Write-Host "    [OK] No non-standard ACEs on AdminSDHolder" -ForegroundColor Green
        } else {
            Write-Host "    [!] $($adminSDFindings.Count) non-standard ACE(s) on AdminSDHolder" `
                -ForegroundColor Red
        }

    } catch {
        Write-Host "    [!] Could not read AdminSDHolder ACL: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "AdminSDHolder ACL read failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # CHECK 4: DC OU Non-Standard Delegation (Remediable)
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [4/6] DC OU non-standard delegation (OU=Domain Controllers)..." -ForegroundColor DarkCyan

    $dcOUDN = "OU=Domain Controllers,$domainDN"
    $dcOUACEItems = [System.Collections.Generic.List[PSCustomObject]]::new()

    try {
        $dcOUACL = Get-Acl -Path "AD:\$dcOUDN" -ErrorAction Stop

        foreach ($ace in $dcOUACL.Access) {
            if ($ace.IsInherited) { continue }
            if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

            $rightsStr  = $ace.ActiveDirectoryRights.ToString()
            if ($rightsStr -notmatch "GenericAll|WriteDacl|WriteOwner|GenericWrite") { continue }

            $principal  = $ace.IdentityReference.Value
            $isStandard = Test-IsStandardPrincipal $principal
            if ($isStandard) { continue }

            $dcOUACEItems.Add([PSCustomObject]@{
                DN        = $dcOUDN
                OUName    = "Domain Controllers"
                Principal = $principal
                Rights    = $rightsStr
            })

            Add-Finding -ObjectDN $dcOUDN -FindingType "DCOUNonStandardDelegation" -Severity "CRITICAL" `
                -Description "Non-standard principal '$principal' has '$rightsStr' on OU=Domain Controllers. Control over the DC OU allows pushing malicious GPOs to all Domain Controllers -- this is a full domain compromise path. This ACE should be removed unless explicitly authorised and documented." `
                -CISControl "6" -CISLevel "1" -NISTControl "AC-3, AC-6, CM-3" `
                -Data @{ Principal = $principal; Rights = $rightsStr }

            Write-Host "    [CRITICAL] DC OU delegation: $principal has $rightsStr" -ForegroundColor Magenta
        }

        if ($dcOUACEItems.Count -eq 0) {
            Write-Host "    [OK] No non-standard ACEs on DC OU" -ForegroundColor Green
        } else {
            Write-Host "    [!] $($dcOUACEItems.Count) non-standard ACE(s) on DC OU" -ForegroundColor Red
        }

    } catch {
        Write-Host "    [!] Could not read DC OU ACL: $($_.Exception.Message)" -ForegroundColor Yellow
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "DC OU ACL read failed: $($_.Exception.Message)"
    }

    # =========================================================================
    # CHECK 5: DNS Permissions Audit
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [5/6] DNS permissions audit (DnsAdmins membership + MicrosoftDNS ACL)..." `
        -ForegroundColor DarkCyan

    # 5a: DnsAdmins membership
    $dnsAdminsMembers = @()
    try {
        $dnsAdminsGroup = Get-ADGroup -Identity "DnsAdmins" -Server $Domain -ErrorAction SilentlyContinue
        if ($null -ne $dnsAdminsGroup) {
            $dnsAdminsMembers = @(Get-ADGroupMember -Identity "DnsAdmins" -Server $Domain `
                -Recursive -ErrorAction SilentlyContinue)

            Write-Host "    DnsAdmins has $($dnsAdminsMembers.Count) member(s)" -ForegroundColor Gray

            foreach ($m in $dnsAdminsMembers) {
                $sev = if ($m.objectClass -eq "user") { "HIGH" } else { "CRITICAL" }
                Add-Finding -ObjectDN $m.distinguishedName -FindingType "DnsAdminsMember" -Severity $sev `
                    -Description "Account '$($m.SamAccountName)' ($($m.objectClass)) is a member of DnsAdmins. DnsAdmins members can instruct the DNS service (running on DCs) to load an arbitrary DLL via dnscmd -- this is a well-known path to full DC compromise. Membership should be near-zero for normal operations." `
                    -CISControl "6" -CISLevel "1" -NISTControl "AC-3, AC-6, SC-22" `
                    -Data @{ SamAccountName = $m.SamAccountName; ObjectClass = $m.objectClass }
                Write-Host "    [$sev] DnsAdmins member: $($m.SamAccountName) ($($m.objectClass))" `
                    -ForegroundColor $(if ($sev -eq "CRITICAL") { "Magenta" } else { "Yellow" })
            }

            if ($dnsAdminsMembers.Count -eq 0) {
                Write-Host "    [OK] DnsAdmins has no members" -ForegroundColor Green
            }
        } else {
            Write-Host "    DnsAdmins group not found (may not exist in this domain)" -ForegroundColor DarkGray
        }
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "DnsAdmins enumeration failed: $($_.Exception.Message)"
    }

    # 5b: MicrosoftDNS container ACL
    $dnsMicrosoftDN = "CN=MicrosoftDNS,CN=System,$domainDN"
    try {
        $dnsContainerACL = Get-Acl -Path "AD:\$dnsMicrosoftDN" -ErrorAction SilentlyContinue

        if ($null -ne $dnsContainerACL) {
            foreach ($ace in $dnsContainerACL.Access) {
                if ($ace.IsInherited) { continue }
                if ($ace.AccessControlType -ne [System.Security.AccessControl.AccessControlType]::Allow) { continue }

                $rightsStr  = $ace.ActiveDirectoryRights.ToString()
                if ($rightsStr -notmatch "GenericAll|WriteDacl|WriteOwner|GenericWrite|CreateChild") { continue }

                $principal  = $ace.IdentityReference.Value
                $isStandard = Test-IsStandardPrincipal $principal
                if ($isStandard) { continue }

                Add-Finding -ObjectDN $dnsMicrosoftDN -FindingType "DNSContainerNonStandardACE" -Severity "HIGH" `
                    -Description "Non-standard principal '$principal' has '$rightsStr' on the MicrosoftDNS container (CN=MicrosoftDNS,CN=System). Write access to AD-integrated DNS zones enables ADIDNS poisoning -- attackers can create DNS records that redirect traffic or enable NTLM relay attacks." `
                    -CISControl "6" -CISLevel "1" -NISTControl "AC-3, AC-6, SC-22" `
                    -Data @{ Principal = $principal; Rights = $rightsStr }
                Write-Host "    [HIGH] MicrosoftDNS non-standard ACE: $principal ($rightsStr)" -ForegroundColor Red
            }
        }
    } catch {
        # MicrosoftDNS container may not exist in all configurations
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "MicrosoftDNS ACL check failed (container may not exist): $($_.Exception.Message)"
    }

    # =========================================================================
    # CHECK 6: DC Computer Object Delegation
    # =========================================================================
    Write-Host ""
    Write-Host "  -> [6/6] DC computer object delegation audit..." -ForegroundColor DarkCyan

    $domainControllers = @()
    try {
        $domainControllers = @(Get-ADDomainController -Filter * -Server $Domain -ErrorAction SilentlyContinue |
            ForEach-Object {
                Get-ADComputer -Identity $_.ComputerObjectDN -Server $Domain `
                    -Properties TrustedForDelegation, TrustedToAuthForDelegation,
                                msDS-AllowedToDelegateTo, msDS-AllowedToActOnBehalfOfOtherIdentity `
                    -ErrorAction SilentlyContinue
            })
    } catch {
        Write-AgentLog -Level WARN -Milestone $ms `
            -Message "DC enumeration failed: $($_.Exception.Message)"
    }

    Write-Host "    $($domainControllers.Count) Domain Controller object(s) found" -ForegroundColor Gray

    foreach ($dc in $domainControllers) {
        if ($null -eq $dc) { continue }

        # Unconstrained delegation on a DC (TrustedForDelegation should be $true by default
        # for DCs -- this is expected and required for Kerberos. Flag only if the DC is NOT
        # in the DC OU, which would be unusual)
        $inDCOU = $dc.DistinguishedName -like "*,$dcOUDN"

        if ($dc.TrustedForDelegation -and -not $inDCOU) {
            Add-Finding -ObjectDN $dc.DistinguishedName `
                -FindingType "DCUnconstrained_OutsideDCOU" -Severity "HIGH" `
                -Description "DC '$($dc.Name)' has TrustedForDelegation=True but is NOT in OU=Domain Controllers. DCs outside the DC OU may not receive DC-specific GPOs and their delegation configuration should be reviewed." `
                -CISControl "6" -CISLevel "1" -NISTControl "AC-3, IA-2" `
                -Data @{ DCName = $dc.Name; TrustedForDelegation = $dc.TrustedForDelegation }
            Write-Host "    [HIGH] DC '$($dc.Name)' has unconstrained delegation but is outside DC OU" -ForegroundColor Red
        }

        # Constrained delegation on a DC (non-default, high risk)
        $constrainedSPNs = @()
        if ($null -ne $dc."msDS-AllowedToDelegateTo") {
            $constrainedSPNs = @($dc."msDS-AllowedToDelegateTo")
        }

        if ($constrainedSPNs.Count -gt 0) {
            $spnList = $constrainedSPNs -join ", "
            Add-Finding -ObjectDN $dc.DistinguishedName `
                -FindingType "DCConstrainedDelegationConfigured" -Severity "HIGH" `
                -Description "DC '$($dc.Name)' has constrained delegation configured for: $spnList. Constrained delegation on a DC is not a default configuration. If an attacker compromises a service that the DC is trusted to delegate to, they can move laterally using the DC's identity. Review whether this delegation is required." `
                -CISControl "6" -CISLevel "1" -NISTControl "AC-3, IA-2" `
                -Data @{ DCName = $dc.Name; AllowedToDelegateTo = $constrainedSPNs }
            Write-Host "    [HIGH] DC '$($dc.Name)' has constrained delegation: $spnList" -ForegroundColor Red
        }

        # Protocol transition (TrustedToAuthForDelegation) on a DC -- very unusual
        if ($dc.TrustedToAuthForDelegation) {
            Add-Finding -ObjectDN $dc.DistinguishedName `
                -FindingType "DCProtocolTransitionDelegation" -Severity "CRITICAL" `
                -Description "DC '$($dc.Name)' has TrustedToAuthForDelegation=True (protocol transition / constrained delegation with any-auth). This allows impersonating any user to any service the DC is allowed to delegate to, without requiring Kerberos pre-authentication. This is an extremely high-risk configuration on a Domain Controller." `
                -CISControl "6" -CISLevel "1" -NISTControl "AC-3, IA-2" `
                -Data @{ DCName = $dc.Name }
            Write-Host "    [CRITICAL] DC '$($dc.Name)' has protocol-transition delegation (TrustedToAuthForDelegation)" `
                -ForegroundColor Magenta
        }
    }

    $dcDelegationIssues = @($Global:FindingsList | Where-Object {
        $_.Milestone -eq $ms -and
        $_.FindingType -in @("DCUnconstrained_OutsideDCOU","DCConstrainedDelegationConfigured","DCProtocolTransitionDelegation")
    })

    if ($dcDelegationIssues.Count -eq 0) {
        Write-Host "    [OK] No unexpected delegation configurations on DC objects" -ForegroundColor Green
    }

    # =========================================================================
    # Summary / Discover-only exit
    # =========================================================================
    if ($Mode -ne "Remediate") {
        $msFindings = @($Global:FindingsList |
            Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
        Write-Host ""
        Write-Host "  M10 complete -- $($msFindings.Count) actionable finding(s)" `
            -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
        Write-AgentLog -Level INFO -Milestone $ms `
            -Message "M10 complete (Discover). Actionable findings: $($msFindings.Count)"
        return
    }

    # =========================================================================
    # Remediation Phase -- Check 4: DC OU Non-Standard Delegation (per-ACE)
    # =========================================================================
    if ($dcOUACEItems.Count -eq 0) {
        Write-Host ""
        Write-Host "  [OK] No remediable items found (no non-standard DC OU ACEs)." -ForegroundColor Green
        Write-AgentLog -Level INFO -Milestone $ms -Message "M10 Remediate: no remediable DC OU ACEs"
        return
    }

    Write-Host ""
    Write-Host "  --- Remediation Phase: DC OU ACE Removal ($($dcOUACEItems.Count) ACE(s)) ---" -ForegroundColor Cyan
    Write-Host "  Checks 1, 2, 3, 5, 6 are Discover-only due to blast radius." -ForegroundColor DarkYellow
    Write-Host "  Processing check 4: DC OU non-standard delegation ACE removal." -ForegroundColor DarkYellow
    Write-Host ""
    Write-Host "  NOTE: Checks 1, 2, 3 findings require manual ACL review with a domain admin." -ForegroundColor DarkYellow
    Write-Host "        Use ADSI Edit or dsacls for those changes under a separate change request." -ForegroundColor DarkYellow
    Write-Host ""

    try {
        foreach ($item in $dcOUACEItems) {
            $approved = Invoke-HumanApproval `
                -Action    "Remove non-standard ACE from OU=Domain Controllers" `
                -Target    "$($item.Principal) ($($item.Rights))" `
                -Milestone $ms `
                -RiskLevel "CRITICAL" `
                -Implications @(
                    "The Allow ACE granting '$($item.Rights)' to '$($item.Principal)' will be removed from $dcOUDN.",
                    "If '$($item.Principal)' has legitimate operational need for this access, that access will be lost.",
                    "DCs will continue to function -- this change only affects the ability to manage the DC OU.",
                    "The domain root, AdminSDHolder, and DCSync rights are NOT changed by this action.",
                    "ACL changes on AD objects are not automatically logged to Windows Event Log -- this agent log is the audit record."
                ) `
                -RollbackSteps @(
                    "To restore: load the AD: PSDrive, then run:",
                    "  `$acl = Get-Acl 'AD:\$dcOUDN'",
                    "  `$ace = New-Object System.DirectoryServices.ActiveDirectoryAccessRule(",
                    "      [System.Security.Principal.NTAccount]'$($item.Principal)',",
                    "      [System.DirectoryServices.ActiveDirectoryRights]'$($item.Rights)',",
                    "      [System.Security.AccessControl.AccessControlType]::Allow)",
                    "  `$acl.AddAccessRule(`$ace)",
                    "  Set-Acl -Path 'AD:\$dcOUDN' -AclObject `$acl"
                )

            if (-not $approved) { continue }

            try {
                $currentACL = Get-Acl -Path "AD:\$($item.DN)" -ErrorAction Stop

                $aceToRemove = $null
                foreach ($ace in $currentACL.Access) {
                    if ($ace.IsInherited) { continue }
                    if ($ace.IdentityReference.Value -eq $item.Principal -and
                        $ace.ActiveDirectoryRights.ToString() -eq $item.Rights -and
                        $ace.AccessControlType -eq [System.Security.AccessControl.AccessControlType]::Allow) {
                        $aceToRemove = $ace
                        break
                    }
                }

                if ($null -eq $aceToRemove) {
                    Write-Host "  [!] ACE no longer present on '$($item.OUName)' -- may have already been removed." `
                        -ForegroundColor Yellow
                    Write-AgentLog -Level WARN -Milestone $ms `
                        -Message "ACE not found for removal: $($item.Principal) on $($item.DN)"
                    continue
                }

                $null = $currentACL.RemoveAccessRule($aceToRemove)
                Set-Acl -Path "AD:\$($item.DN)" -AclObject $currentACL -ErrorAction Stop

                Write-Host "  [OK] Removed ACE: '$($item.Principal)' ($($item.Rights)) from $($item.OUName)" `
                    -ForegroundColor Green
                Write-AgentLog -Level ACTION -Milestone $ms `
                    -Message "Removed DC OU ACE: '$($item.Principal)' ($($item.Rights)) from $($item.DN)"

            } catch {
                Write-Host "  [!] Failed to remove ACE: $($_.Exception.Message)" -ForegroundColor Red
                Write-AgentLog -Level WARN -Milestone $ms `
                    -Message "ACE removal failed for '$($item.Principal)' on $($item.DN): $($_.Exception.Message)"
            }
        }

    } catch {
        if ($_.Exception.Message -eq "MILESTONE_QUIT") {
            Write-Host "  [!] M10 remediation stopped by operator." -ForegroundColor Yellow
            Write-AgentLog -Level WARN -Milestone $ms -Message "M10 remediation quit by operator"
        } else {
            throw
        }
    }

    # =========================================================================
    # Final summary
    # =========================================================================
    $msFindings = @($Global:FindingsList |
        Where-Object { $_.Milestone -eq $ms -and $_.Severity -ne "INFO" })
    Write-Host ""
    Write-Host "  M10 complete -- $($msFindings.Count) actionable finding(s)" `
        -ForegroundColor $(if ($msFindings.Count -gt 0) { "Yellow" } else { "Green" })
    Write-AgentLog -Level INFO -Milestone $ms `
        -Message "M10 complete. Actionable findings: $($msFindings.Count)"
}
