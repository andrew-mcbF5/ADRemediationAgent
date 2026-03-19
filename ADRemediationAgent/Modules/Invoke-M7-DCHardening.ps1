#Requires -Version 5.1
<#
.SYNOPSIS
    Milestone 7 -- DC Hardening and CIS L1 Baseline [STUB - planned for future release]

    Planned CIS L1 checks (per CIS Microsoft Windows Server 2025 Benchmark):

      1. LDAP Signing Requirement
         CIS: 2.3.11.8  "Network security: LDAP client signing requirements = Require signing"
         NIST: AC-17, SC-8
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LDAPServerIntegrity = 2

      2. LDAP Channel Binding
         CIS: 18.3.3  "Ensure LDAP channel binding is configured"
         NIST: IA-3
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Services\NTDS\Parameters\LdapEnforceChannelBinding >= 1

      3. SMB Signing - Server (require)
         CIS: 2.3.6.6  "Microsoft network server: Digitally sign communications (always) = Enabled"
         NIST: SC-8
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters\RequireSecuritySignature = 1

      4. SMB Signing - Client (require)
         CIS: 2.3.6.2  "Microsoft network client: Digitally sign communications (always) = Enabled"
         NIST: SC-8
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters\RequireSecuritySignature = 1

      5. NLA for RDP
         CIS: 18.9.65.3.3.1  "Require use of specific security layer for RDP = SSL"
         Also: "Require NLA = Enabled"
         NIST: IA-2, AC-17
         Check: Registry HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services\UserAuthentication = 1

      6. Print Spooler Disabled on DCs
         CIS: 18.3.6  "Ensure Print Spooler service is disabled or not installed on DCs"
         NIST: CM-7
         Check: Get-Service -Name Spooler | Where StartType -ne 'Disabled'

      7. LSASS Protection (PPL - Protected Process Light)
         CIS: 18.9.46.2  "Configure LSASS to run as a protected process"
         NIST: SI-3
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RunAsPPL = 1

      8. Guest Account Disabled
         CIS: 2.3.1.2  "Accounts: Guest account status = Disabled"
         NIST: AC-2
         Check: Get-LocalUser -Name Guest | Where Enabled -eq $true

      9. Anonymous Enumeration of SAM Accounts and Shares
         CIS: 2.3.10.2  "Network access: Do not allow anonymous enumeration of SAM accounts = Enabled"
         NIST: AC-6
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymousSAM = 1
         Check: Registry HKLM\SYSTEM\CurrentControlSet\Control\Lsa\RestrictAnonymous = 1

      10. WDigest Authentication Disabled
          CIS: 18.3.7  "WDigest Authentication = Disabled"
          NIST: IA-5
          Check: Registry HKLM\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential = 0

      11. Credential Guard Enabled
          CIS: 18.9.46.4  "Turn On Virtualization Based Security -- Credential Guard Configuration = Enabled with UEFI lock"
          NIST: IA-5, SC-28
          Check: Registry HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\EnableVirtualizationBasedSecurity = 1
          Check: Registry HKLM\SYSTEM\CurrentControlSet\Control\DeviceGuard\RequirePlatformSecurityFeatures >= 1
          Note: Credential Guard requires UEFI + Secure Boot + TPM 2.0 + Windows Server 2016+ / Server 2025

      12. Advanced Audit Policy Configuration
          CIS: 17.x  (multiple subcategories)
          NIST: AU-2
          Key subcategories to verify:
            - Account Logon: Audit Credential Validation = Success, Failure
            - Account Management: Audit Security Group Management = Success
            - DS Access: Audit Directory Service Changes = Success
            - Logon/Logoff: Audit Logon = Success, Failure
            - Object Access: Audit SAM = Success  (for DCSync detection)
            - Policy Change: Audit Audit Policy Change = Success
            - Privilege Use: Audit Sensitive Privilege Use = Success, Failure
            - System: Audit Security System Extension = Success

    Implementation note:
      Each check will query the registry/service state on each DC via Invoke-Command
      (requires WinRM enabled on all DCs -- prereq check will be included).
      Remediate mode will apply GPO/registry fixes with human approval.
#>

function Invoke-M7 {
    [CmdletBinding()]
    param(
        [string] $Mode,
        [string] $Domain,
        [string] $OutputPath
    )

    $ms = "M7"

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

    Write-Host "  [M7] DC Hardening and CIS L1 Baseline -- planned, not yet implemented." -ForegroundColor DarkYellow
    Write-AgentLog -Level INFO -Milestone $ms -Message "M7 stub invoked -- not yet implemented"

    Add-Finding -ObjectDN $Domain -FindingType "MilestonePlanned" -Severity "INFO" `
        -Description "M7 (DC Hardening and CIS L1 Baseline) is planned for a future release. Planned checks include LDAP signing, SMB signing, NLA, Print Spooler, LSASS PPL, WDigest, Credential Guard, and advanced audit policy. No checks were performed." `
        -CISControl "2.3.11.8, 18.3.3, 2.3.6.6, 2.3.6.2, 18.9.65.3.3.1, 18.3.6, 18.9.46.2, 2.3.1.2, 2.3.10.2, 18.3.7, 18.9.46.4, 17.x" `
        -CISLevel "L1" `
        -NISTControl "AC-17, SC-8, IA-3, IA-2, CM-7, SI-3, AC-2, AC-6, IA-5, SC-28, AU-2"
}
