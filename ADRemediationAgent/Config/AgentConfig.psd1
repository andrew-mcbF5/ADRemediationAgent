# ADRemediationAgent - Configuration File
# Edit this file to customise thresholds and behaviour for your environment.
# This file is loaded automatically if present at Config\AgentConfig.psd1

@{
    # ── General ───────────────────────────────────────────────────────────────
    AgentVersion        = "1.0"
    DefaultDomain       = $env:USERDNSDOMAIN

    # ── M11: Stale Account Thresholds ─────────────────────────────────────────
    StaleUserDays       = 90       # Days without logon to flag a user as stale
    StaleComputerDays   = 90       # Days without logon to flag a computer as stale
    StalePrivDays       = 60       # Days without logon to flag a privileged account

    # ── M11: Quarantine OU ────────────────────────────────────────────────────
    # Leave empty to auto-construct from domain DN
    # Example: "OU=Quarantine-Disabled,DC=corp,DC=contoso,DC=com"
    QuarantineOU        = ""

    # ── M11: Protected Account Patterns (never quarantine) ───────────────────
    ProtectedPatterns   = @(
        "krbtgt",
        "Guest",
        "Administrator",
        "DefaultAccount",
        "SUPPORT_388945a0"
    )

    # ── M12: Privileged Groups to audit ───────────────────────────────────────
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

    # ── Reporting ─────────────────────────────────────────────────────────────
    # Max log files to retain in the Logs directory
    LogRetentionCount   = 90

    # Open HTML report in browser after run (requires a GUI session)
    AutoOpenReport      = $false

    # ── Hybrid AAD notes ──────────────────────────────────────────────────────
    # If running in a Hybrid Azure AD environment:
    # - LastLogonDate from Get-ADUser reflects on-prem logons only.
    # - Cloud-only logons via Entra ID will NOT update LastLogonDate.
    # - For hybrid environments, consider cross-referencing with Entra ID sign-in
    #   logs (Get-MgAuditLogSignIn) before quarantining accounts.
    # - Set HybridAAD = $true below to enable a warning reminder at M11 startup.
    HybridAAD           = $false
}
