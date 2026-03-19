#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 6 -- Kerberos Configuration Review [STUB - planned for future release]

    Planned checks:
      - msDS-SupportedEncryptionTypes audit:
          Flag accounts that support only RC4 (0x4) with no AES (0x8, 0x10).
          RC4-only accounts are trivially Kerberoastable.
          Target: all accounts should support AES128 (0x8) and AES256 (0x10).

      - Default domain Kerberos policy settings (via Default Domain Policy GPO):
          - Maximum ticket lifetime (recommended: 10 hours, CIS: <= 10 hours)
          - Maximum ticket renewal (recommended: 7 days)
          - Maximum clock skew (must be <= 5 minutes for Kerberos to function)
          Note: check via Get-ADDefaultDomainPasswordPolicy and GPO audit

      - Protected Users group membership analysis:
          NOTE: Basic DA membership check is already performed in M1.
          M6 will extend this to all tier-0 and tier-1 accounts,
          and flag any service accounts incorrectly placed in Protected Users
          (Protected Users disables delegation which breaks some service accounts).

      - Windows Hello for Business (WHfB) Kerberos hybrid trust prerequisites:
          - msDS-KeyCredentialLink populated on user objects (WHfB cloud trust)
          - Azure AD Kerberos server object present in domain
            (CN=AzureADKerberos,OU=Domain Controllers,<DomainDN>)
          - Entra ID tenant ID registered in AD

      - Authentication policies and silos inventory:
          - List all Authentication Policy objects
          - List all Authentication Policy Silos
          - Flag tier-0 accounts not assigned to a silo

      - Accounts with DONT_REQUIRE_PREAUTH:
          NOTE: This check is already implemented in M1 (AS-REP roasting).
          M6 will not duplicate it but will reference M1 findings.

    Planned CIS Controls:
      - CIS-adjacent (Kerberos settings not explicitly in CIS L1 benchmarks
        for Server 2025, but align with CIS Control 4 -- Secure Configuration)

    Planned NIST Controls:
      - IA-5   (Authenticator Management)
      - IA-5(1)(Password-Based Authentication -- encryption type enforcement)
      - IA-2(1)(Multi-Factor Authentication)
      - SC-8   (Transmission Confidentiality and Integrity)
      - SC-28  (Protection of Information at Rest)
      - AU-8   (Time Stamps -- clock skew)
#>

function Invoke-M6 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    $ms = "M6"

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

    Write-Host "  [M6] Kerberos Configuration Review -- planned, not yet implemented." -ForegroundColor DarkYellow
    Write-AgentLog -Level INFO -Milestone $ms -Message "M6 stub invoked -- not yet implemented"

    Add-Finding -ObjectDN $Domain -FindingType "MilestonePlanned" -Severity "INFO" `
        -Description "M6 (Kerberos Configuration Review) is planned for a future release. No checks were performed. AS-REP roasting check is available in M1." `
        -NISTControl "IA-5, IA-5(1), IA-2(1), SC-8, SC-28, AU-8"
}
