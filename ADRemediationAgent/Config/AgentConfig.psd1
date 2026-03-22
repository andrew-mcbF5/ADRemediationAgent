# ADRemediationAgent - Configuration File
# Edit this file to customise thresholds and behaviour for your environment.
# This file is loaded automatically if present at Config\AgentConfig.psd1

@{
    # -- General ----------------------------------------------------------------
    AgentVersion        = "2.2"
    DefaultDomain       = $env:USERDNSDOMAIN

    # -- Compliance Framework ---------------------------------------------------
    # CIS_L1_NIST800-53: CIS Benchmark L1 checks with NIST SP 800-53 control mapping
    # CIS_L1_ONLY: CIS L1 checks only, no NIST mapping in reports
    # NONE: No compliance framework, health checks only
    ComplianceFramework = "CIS_L1_NIST800-53"

    # -- DC Upgrade Gate --------------------------------------------------------
    # When $true, agent will warn (Discover) or block (Remediate) M3-M12
    # if any DC is not yet running TargetDCOS.
    # Set to $false after all DCs have been upgraded.
    DCUpgradeGateEnabled = $true
    TargetDCOS           = "2025"   # Matches against OperatingSystem string

    # -- M11: Stale Account Thresholds -----------------------------------------
    StaleUserDays       = 90
    StaleComputerDays   = 90
    StalePrivDays       = 60

    # -- M11: Quarantine OU ----------------------------------------------------
    QuarantineOU        = ""

    # -- M11: Protected Account Patterns (never quarantine) --------------------
    ProtectedPatterns   = @(
        "krbtgt",
        "Guest",
        "Administrator",
        "DefaultAccount",
        "SUPPORT_388945a0"
    )

    # -- M12: Privileged Groups to audit ---------------------------------------
    PrivilegedGroups    = @(
        "Domain Admins",
        "Enterprise Admins",
        "Schema Admins",
        "Backup Operators",
        "Account Operators",
        "Print Operators",
        "Server Operators",
        "Group Policy Creator Owners"
    )

    # -- Reporting -------------------------------------------------------------
    LogRetentionCount   = 90
    AutoOpenReport      = $false

    # -- Hybrid Azure AD -------------------------------------------------------
    # $true: DCs are Azure VMs in hybrid AAD join environment.
    # LastLogonDate reflects on-prem logons only -- cross-reference Entra ID
    # sign-in logs before quarantining accounts.
    HybridAAD           = $true

    # -- IP-Bound App Warning --------------------------------------------------
    # Set $true if legacy apps are bound to DC IP addresses.
    # M1 will include a warning in reporting and the DC upgrade checklist
    # will flag the IP reassignment risk.
    IPBoundAppsPresent  = $true
}
