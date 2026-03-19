# AD Remediation Agent

> A PowerShell-based Active Directory remediation agent with human-in-the-loop approval gates, CIS Level 1 compliance checking, NIST SP 800-53 control mapping, structured audit logging, baseline drift tracking, and HTML reporting.

Designed for environments upgrading Domain Controllers to Windows Server 2025 and Hybrid Azure AD deployments.

---

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Directory Structure](#directory-structure)
- [Compliance Framework](#compliance-framework)
- [Operating Modes](#operating-modes)
- [Quick Start](#quick-start)
- [DC Upgrade Workflow](#dc-upgrade-workflow)
- [DC Upgrade Gate](#dc-upgrade-gate)
- [Milestone Reference](#milestone-reference)
- [Approval Gate Behaviour](#approval-gate-behaviour)
- [Baseline and Drift Tracking](#baseline-and-drift-tracking)
- [Hybrid Azure AD Notes](#hybrid-azure-ad-notes)
- [Output Files](#output-files)
- [Configuration](#configuration)
- [Security Notes](#security-notes)
- [Extending the Agent](#extending-the-agent)

---

## Overview

The AD Remediation Agent automates discovery and remediation across all 12 Active Directory security and hygiene milestones, while enforcing human approval before any change is made. Built for use from a domain-joined machine or Privileged Access Workstation (PAW) by a Domain Admin or delegated equivalent.

**Core principles:**

- **Discover before you change** -- all modes produce findings reports; non-Remediate modes have zero side effects
- **Human in the loop, always** -- no change is made without explicit operator approval at the CLI, with full blast-radius warnings
- **Compliance-mapped findings** -- every finding is tagged with the CIS Benchmark Level 1 control and NIST SP 800-53 control ID
- **Baseline everything** -- snapshot AD state after a known-good build; all subsequent runs diff against it
- **Full audit trail** -- every run, finding, approval, and denial is logged to a structured CSV and an HTML report
- **Safe-by-default** -- no objects are ever deleted; stale accounts are quarantined (disabled + moved), not removed
- **Upgrade-gated** -- the agent blocks or warns when M3-M12 remediation is attempted before DCs are on the target OS

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later |
| Module | `ActiveDirectory` (RSAT on a workstation, or run from a DC / member server) |
| Tools in PATH | `repadmin`, `dcdiag`, `w32tm`, `dfsrdiag`, `setspn` |
| Permissions | Domain Admin, or delegated read (Discover) / write (Remediate) access |
| Platform | Windows 10/11 or Windows Server 2016+ domain-joined machine |

---

## Directory Structure

```
ADRemediationAgent/
+-- Start-ADRemediationAgent.ps1          Entry point
+-- README.md
+-- Config/
|   +-- AgentConfig.psd1                  Thresholds, compliance framework, environment settings
+-- Core/
|   +-- Write-AgentLog.ps1                Structured CSV logging engine
|   +-- Invoke-HumanApproval.ps1          CLI approval gate (single-item and bulk)
|   +-- Save-Baseline.ps1                 Baseline snapshot engine
|   +-- Compare-Baseline.ps1              Baseline comparison wrapper
|   +-- New-RunReport.ps1                 Per-run HTML report generator
+-- Modules/
|   +-- Invoke-M1-DCHealthBaseline.ps1    M1:  DC Health, inventory, AS-REP, krbtgt, upgrade readiness
|   +-- Invoke-M3-OUStructure.ps1         M3:  OU Structure Cleanup          [stub - planned]
|   +-- Invoke-M4-UnconstrainedDelegation.ps1  M4:  Unconstrained Delegation
|   +-- Invoke-M5-SPNAudit.ps1            M5:  SPN Duplicate Detection        [stub - planned]
|   +-- Invoke-M6-KerberosConfig.ps1      M6:  Kerberos Configuration Review  [stub - planned]
|   +-- Invoke-M7-DCHardening.ps1         M7:  DC Hardening and CIS L1 Baseline [stub - planned]
|   +-- Invoke-M8-GPOCleanup.ps1          M8:  GPO Cleanup                    [stub - planned]
|   +-- Invoke-M9-SecurityGroups.ps1      M9:  Security Group Cleanup         [stub - planned]
|   +-- Invoke-M10-DelegatedPermissions.ps1 M10: Delegated Permissions Review [stub - planned]
|   +-- Invoke-M11-StaleAccounts.ps1      M11: Stale Account Quarantine
|   +-- Invoke-M12-PrivilegedGroups.ps1   M12: Privileged Group Review
+-- Logs/       Per-run CSV logs           (auto-created at runtime)
+-- Reports/    HTML reports and snapshots  (auto-created at runtime)
+-- Baselines/  JSON baseline snapshots     (auto-created at runtime)
```

> **M2 (DC Upgrade to Windows Server 2025) is intentionally not scripted.** The upgrade process is a manual, change-controlled activity. M1 produces a DC inventory with upgrade readiness flags and the agent enforces an upgrade gate before M3-M12 remediation can proceed. See [DC Upgrade Workflow](#dc-upgrade-workflow).

---

## Compliance Framework

The agent maps every finding to two frameworks simultaneously:

| Framework | Role |
|---|---|
| **CIS Benchmark Level 1** (Windows Server 2022/2025) | Technical check source -- prescriptive, PowerShell-executable controls |
| **NIST SP 800-53** | Governance and reporting layer -- control IDs travel well in audit and risk register conversations |

Every finding object carries three compliance fields:

| Field | Example | Description |
|---|---|---|
| `CISControl` | `2.3.11.8` | CIS Benchmark control reference |
| `CISLevel` | `L1` | CIS profile level |
| `NISTControl` | `AC-17, SC-8` | NIST SP 800-53 control ID(s) |

The HTML report includes:
- A **CIS L1 Compliance card** showing the count of non-compliant CIS controls found
- A **NIST control cross-reference** section grouping findings by control family
- `CISControl` and `NISTControl` columns in the findings and delta tables

---

## Operating Modes

| Mode | Description | Makes Changes |
|---|---|---|
| `Discover` | Runs all checks, logs findings, produces HTML report | No |
| `Baseline` | Snapshots current AD state as the approved reference point | No |
| `Remediate` | Discovers findings, then prompts for human approval on each remediable item | Yes -- with approval only |
| `Report` | Loads stored baselines and run logs, generates a historical drift report. No AD queries. | No |

### Targeting specific milestones

```powershell
# Run default implemented milestones (M1, M4, M11, M12)
.\Start-ADRemediationAgent.ps1 -Mode Discover

# Run specific milestones
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4,M12

# Run all available milestones
.\Start-ADRemediationAgent.ps1 -Mode Discover -Milestones M1,M3,M4,M5,M6,M7,M8,M9,M10,M11,M12

# Target a specific domain (defaults to current machine's domain)
.\Start-ADRemediationAgent.ps1 -Mode Discover -Domain "corp.contoso.com"

# Custom output path
.\Start-ADRemediationAgent.ps1 -Mode Discover -OutputPath "D:\ADAudit\Output"
```

---

## Quick Start

### 1 -- Initial discovery and CIS baseline (no changes)

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Discover
```

Runs all implemented milestones and produces a findings report with CIS L1 and NIST control annotations. Nothing is changed. Review the HTML report in `.\ADAgent-Output\Reports\`.

### 2 -- Run M2 DC upgrade (manual -- see DC Upgrade Workflow below)

M1 reports will show which DCs need upgrading. The upgrade itself is manual and change-controlled. Once all DCs are on Windows Server 2025, proceed to step 3.

### 3 -- Set an approved post-upgrade baseline

Run this after DC upgrades are complete and the environment is in a known-good state:

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Baseline
```

Snapshots current AD findings to `Baselines\baseline-latest.json`. All future runs diff against this.

### 4 -- Remediate with human approval (post-upgrade)

```powershell
# Highest risk first -- unconstrained delegation
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4

# DC hardening and CIS L1 baseline
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M7

# Kerberos configuration
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M6

# Privileged group membership
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M12

# Stale accounts (bulk approval UI)
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M11
```

### 5 -- Ongoing monitoring

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Discover
```

Each run produces a new report with deltas against your baseline. Schedule weekly for continuous drift visibility.

---

## DC Upgrade Workflow

M2 (DC Upgrade to Windows Server 2025) is a manual, change-controlled process. The agent supports this workflow through M1 reporting and the upgrade gate.

### Recommended upgrade sequence

```
1. Run M1 Discover
   - Review DC inventory: names, IPv4 addresses, OS versions, FSMO roles
   - Confirm SYSVOL is using DFSR (not legacy FRS -- must migrate before 2025 upgrade)
   - Note IP-bound app warning if IPBoundAppsPresent = $true in config

2. Trial in-place upgrade (least important DC first)
   - Attempt: Server 2019 -> Server 2022 in-place upgrade
   - If successful and stable: proceed to Server 2022 -> Server 2025
   - If blockers found: document whether OS upgrade blocks or application issues
   - If in-place fails: build new Server 2025 VM, domain join, DCPromo test, then DCPromo down test DC

3. Swing migration for each DC (preserving IP addresses)
   a. DCPromo down the DC being replaced
   b. Rename it to <DCName>_OLD
   c. Change its IP address to a temporary address
   d. Wait for DNS replication and verify old A records are removed
   e. Run: repadmin /syncall /AdeP
   f. Build new Server 2025 VM, assign the original IP
   g. Rename to original DC name
   h. DCPromo -- promote as additional DC
   i. Validate replication, DNS, SYSVOL before decommissioning _OLD

4. After all DCs upgraded:
   - Run M1 Discover -- confirm all DCs show Windows Server 2025
   - DC Upgrade Gate will pass automatically
   - Run Mode Baseline to set the post-upgrade reference point
   - Proceed with M3-M12 remediation milestones
```

> **IP-bound app risk:** If `IPBoundAppsPresent = $true`, legacy applications are hardcoded to DC IP addresses. Coordinate the IP swap timing with application owners. There is a brief DNS gap between the old DC's demotion and the new DC's A record propagating -- keep `<DCName>_OLD` available until DNS propagation is confirmed and apps are validated.

> **SYSVOL / FRS:** Windows Server 2025 does not support legacy FRS replication. If M1 flags `SYSVOLLegacyFRS`, run `dfsrmig /getglobalstate` and complete the DFSR migration before any DC upgrade attempt.

---

## DC Upgrade Gate

The agent enforces a gate to prevent M3-M12 remediation running before DCs are upgraded.

Controlled by `DCUpgradeGateEnabled` and `TargetDCOS` in `AgentConfig.psd1`.

| Mode | Gate behaviour |
|---|---|
| `Discover` | **Warns** that DCs are not on target OS. Prompts operator to type `CONTINUE` to proceed with discovery. |
| `Baseline` | Same as Discover -- warns, requires confirmation. |
| `Remediate` | **Blocks** execution. Exit code 1. Run with `-Mode Discover` to audit in the current state. |

To disable the gate after all DCs are upgraded:

```powershell
# In Config\AgentConfig.psd1:
DCUpgradeGateEnabled = $false
```

---

## Milestone Reference

M2 is a manual process -- see [DC Upgrade Workflow](#dc-upgrade-workflow). All other milestones are scripted.

| ID | Name | Status | What It Checks | Remediates | Risk |
|---|---|---|---|---|---|
| **M1** | DC Health & Baseline | **Implemented** | Replication, FSMO roles, DNS, SYSVOL replication mode (DFSR/FRS), AD Recycle Bin, time sync, OS versions, IPv4 addresses, functional levels, krbtgt password age, AS-REP roastable accounts, Domain Admins not in Protected Users | No -- flags only; acknowledgment required for CRITICAL/HIGH | INFO to HIGH |
| **M2** | DC Upgrade to 2025 | **Manual** | In-place upgrade trial, swing migration, IP reassignment, SYSVOL/DNS validation -- see DC Upgrade Workflow | Manual process -- no automation script | HIGH / CRITICAL |
| **M3** | OU Structure Cleanup | Planned | Empty OUs, default containers, naming violations, GPO link inventory, nested complexity, block inheritance | Yes -- with approval | LOW / MEDIUM |
| **M4** | Unconstrained Delegation | **Implemented** | Computers and users with `TrustedForDelegation = $true` (excluding DCs) | Yes -- per-object approval; sets `TrustedForDelegation = $false` | HIGH / CRITICAL |
| **M5** | SPN Audit | Planned | Duplicate SPNs (setspn -X -F), Kerberoastable accounts, SPNs on disabled accounts, orphaned SPNs | No -- report only; manual remediation required | MEDIUM / HIGH |
| **M6** | Kerberos Configuration | Planned | RC4-only accounts (no AES), msDS-SupportedEncryptionTypes, Kerberos ticket policy, WHfB Kerberos hybrid trust prerequisites, authentication policies | Partial -- with approval | MEDIUM / HIGH |
| **M7** | DC Hardening & CIS L1 | Planned | LDAP signing (CIS 2.3.11.8), LDAP channel binding (CIS 18.3.3), SMB signing (CIS 2.3.6.x), NLA for RDP (CIS 18.9.65.3), Print Spooler on DCs (CIS 18.3.6), LSASS PPL (CIS 18.9.46.2), WDigest (CIS 18.3.7), Credential Guard (CIS 18.9.46.4), Advanced Audit policy (CIS 17.x) | Yes -- GPO / registry changes with approval | HIGH / CRITICAL |
| **M8** | GPO Cleanup | Planned | Unlinked GPOs, all-settings-disabled GPOs, default domain policy modifications, SYSVOL-orphaned GPOs, WMI filter review | Yes -- backup then remove/disable with approval | LOW / MEDIUM |
| **M9** | Security Group Cleanup | Planned | Empty groups, groups with no ACL usage, circular nesting, AdminSDHolder membership, stale members | Yes -- with approval | LOW / MEDIUM |
| **M10** | Delegated Permissions | Planned | Non-standard ACEs on OUs and domain root (GenericAll, WriteDacl, WriteOwner), DCSync rights, AdminSDHolder ACEs, DNS write access | Yes -- per-ACE approval | HIGH / CRITICAL |
| **M11** | Stale Account Quarantine | **Implemented** | Users and computers inactive > 90 days (configurable), enabled accounts, excludes protected patterns | Yes -- bulk approval; disable + move to Quarantine OU + stamp description | LOW / MEDIUM |
| **M12** | Privileged Group Review | **Implemented** | Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, and more -- new members, stale accounts, service accounts in Tier 0, computer accounts, nested groups | Yes -- per-member approval; removes from group only (account not disabled or deleted) | HIGH / CRITICAL |

---

## Approval Gate Behaviour

Every remediable finding passes through one of two approval gates before any change executes.

### Single-item gate (used by M4, M7, M10, M12)

```
  +----------------------------------------------------------+
  |  APPROVAL REQUIRED  [HIGH]  Milestone: M4                |
  +----------------------------------------------------------+

  ACTION  : Remove unconstrained delegation from computer account
  TARGET  : APPSRV01 (CN=APPSRV01,OU=Servers,DC=corp,DC=com)
  CIS     : N/A
  NIST    : AC-3, IA-2

  --- What will happen if you approve ----------------------------
    > TrustedForDelegation will be set to FALSE on this computer account.
    > If any service on this host uses Kerberos unconstrained delegation, it WILL BREAK.

  --- Rollback if this causes issues -----------------------------
    > Set-ADComputer 'APPSRV01' -TrustedForDelegation $true
    > Verify Kerberos ticket acquisition for affected services

  Options:  [A] Approve   [S] Skip this item   [Q] Quit milestone
```

### CRITICAL and HIGH risk -- typed confirmation required

For HIGH and CRITICAL risk changes, the operator must type the target name exactly before the `[A/S/Q]` prompt appears:

```
  [!] This is a HIGH risk change. Type the target name to unlock approval.

  Type [APPSRV01] to continue, or press ENTER to skip:
```

### Bulk approval gate (used by M11)

Stale accounts are shown as a full list with selective exclusion before bulk action:

```
  Options:
    [A] Approve ALL items above
    [E] Exclude specific accounts then approve the rest
    [N] Skip ALL -- no changes
```

If `[E]` is chosen, enter a comma-separated list of `SamAccountName` values to exclude. The remaining accounts are processed.

### Quitting a milestone

Typing `[Q]` at any approval prompt stops the current milestone immediately without processing further items. Items already approved and applied in that run remain changed. The run log records exactly where the operator stopped.

---

## Baseline and Drift Tracking

### How it works

1. Run `-Mode Baseline` to save the current findings as the approved reference.
2. Every subsequent `Discover` or `Remediate` run compares current findings against the baseline.
3. The HTML run report categorises each finding:
   - **NEW** -- not present at baseline (potential regression or new risk)
   - **PERSISTING** -- present at both baseline and current run (known, accepted risk)
   - **RESOLVED** -- was in the baseline but is no longer found (successfully remediated)

### Recommended baseline points

| Baseline Point | When to run |
|---|---|
| Pre-upgrade baseline | After M1 Discover confirms environment health, before DC upgrade starts |
| Post-upgrade baseline | After all DCs are on Server 2025, before M3-M12 remediation begins |
| Post-remediation baseline | After each remediation wave, to track progress and lock in improvements |

### Baseline files

| File | Description |
|---|---|
| `Baselines/baseline-latest.json` | Active baseline -- overwritten each time `-Mode Baseline` runs |
| `Baselines/baseline-<RunId>.json` | Archived snapshot per Baseline run |

### Drift-only report (no AD queries)

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Report
```

Loads the stored baseline and recent run logs. Produces an HTML drift report with metrics and full action history. No AD write access required.

---

## Hybrid Azure AD Notes

> **Read this if your environment uses Hybrid Azure AD Join or Azure VM-hosted Domain Controllers**

`LastLogonDate` on AD user objects reflects **on-premises Kerberos logons only**. Users who authenticate exclusively via Entra ID or cloud apps will show a stale on-prem `LastLogonDate` and may be incorrectly flagged as inactive by M11.

The default config ships with `HybridAAD = $true` -- this enables a warning reminder at the start of every M11 run.

**Before running M11 in Remediate mode in a hybrid environment:**

**Step 1** -- Cross-reference with Entra ID sign-in logs:

```powershell
# Requires Microsoft.Graph module
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'jsmith@corp.com'" -Top 5
```

**Step 2** -- Export recent Entra sign-in activity and compare against M11's stale user list before approving bulk quarantine.

**Step 3** -- Use the `[E] Exclude` option at the M11 bulk approval prompt to protect cloud-active accounts from quarantine.

**Windows Hello for Business (WHfB) -- Kerberos hybrid trust:**

If WHfB Kerberos hybrid trust is deployed, M6 (when implemented) will check:
- Presence of the Azure AD Kerberos server object in AD
- `msDS-KeyCredentialLink` attribute population on relevant accounts
- That the cloud trust TGT issuance path is intact

Do not remove or restrict accounts used by the WHfB Kerberos trust service without first validating the WHfB M6 checks pass.

---

## Output Files

All output is written to `.\ADAgent-Output\` by default, overridable with `-OutputPath`.

| Path | Description |
|---|---|
| `Logs\RUN-<timestamp>.log` | Structured CSV log for every agent run |
| `Reports\RunReport-<timestamp>.html` | Per-run findings (with CIS/NIST columns), DC OS progression card, delta vs baseline, action log |
| `Reports\DriftReport-<timestamp>.html` | Cross-run drift analysis (Report mode) |
| `Reports\M1-ReplicationSummary-<ts>.txt` | Raw `repadmin /replsummary` output |
| `Reports\M12-PrivGroupSnapshot-<ts>.csv` | Privileged group membership snapshot per run |
| `Baselines\baseline-latest.json` | Active approved baseline snapshot |
| `Baselines\baseline-<RunId>.json` | Archived baseline per Baseline-mode run |

---

## Configuration

Edit `Config\AgentConfig.psd1` to customise behaviour for your environment:

```powershell
@{
    AgentVersion        = "2.0"

    # -- Compliance Framework --------------------------------------------------
    # CIS_L1_NIST800-53 : CIS L1 checks with NIST SP 800-53 control IDs in reports
    # CIS_L1_ONLY       : CIS L1 checks, no NIST mapping
    # NONE              : Health checks only, no compliance framework
    ComplianceFramework = "CIS_L1_NIST800-53"

    # -- DC Upgrade Gate -------------------------------------------------------
    # Warn (Discover) or block (Remediate) M3-M12 until DCs are on TargetDCOS.
    # Set DCUpgradeGateEnabled = $false after all DCs are upgraded.
    DCUpgradeGateEnabled = $true
    TargetDCOS           = "2025"

    # -- Hybrid Azure AD -------------------------------------------------------
    # $true: enables logon-date warning before M11 runs.
    # Cloud-only logons will not update on-prem LastLogonDate.
    HybridAAD            = $true

    # -- IP-Bound App Warning --------------------------------------------------
    # $true: M1 will warn that legacy apps are bound to DC IP addresses.
    # Coordinate IP reassignment during DC swing migration.
    IPBoundAppsPresent   = $true

    # -- M11: Stale Account Thresholds -----------------------------------------
    StaleUserDays        = 90
    StaleComputerDays    = 90
    StalePrivDays        = 60

    # -- M11: Quarantine OU (leave empty to auto-construct from domain DN) ------
    QuarantineOU         = ""

    # -- M11: Protected Accounts (never quarantined) ---------------------------
    ProtectedPatterns    = @("krbtgt", "Guest", "Administrator", "DefaultAccount")

    # -- M12: Privileged Groups to audit ---------------------------------------
    PrivilegedGroups     = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Backup Operators", "Account Operators", "Print Operators",
        "Server Operators", "Group Policy Creator Owners"
    )

    # -- Reporting -------------------------------------------------------------
    LogRetentionCount    = 90
    AutoOpenReport       = $false
}
```

---

## Security Notes

- The agent **never deletes** AD objects. Stale accounts are disabled and moved to a Quarantine OU; deletion is always a separate, deliberate manual step.
- The agent **never runs silently** in `Remediate` mode -- every change requires explicit operator input.
- All actions are logged with timestamps, object DNs, CIS/NIST control references, outcome status, and rollback context.
- Run from a **Privileged Access Workstation (PAW)** and consider wrapping execution in a Just-In-Time privileged session.
- The agent does not store or prompt for credentials. It uses the current Windows user context via the `ActiveDirectory` module.
- The DC Upgrade Gate prevents remediation milestones from running against a pre-upgrade environment, reducing the risk of compounding changes on an inconsistent OS baseline.

---

## Extending the Agent

To add a new milestone module:

1. Create `Modules\Invoke-MXX-YourMilestone.ps1`
2. Define `function Invoke-MXX` with parameters `($Mode, $Domain, $OutputPath)`
3. Use the updated `Add-Finding` signature -- include `CISControl`, `CISLevel`, and `NISTControl`:

```powershell
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
```

4. Use the Core helpers: `Write-AgentLog`, `Invoke-HumanApproval`, `Invoke-BulkApproval`
5. Add the milestone to `$milestoneMap` and `$milestoneNames` in `Start-ADRemediationAgent.ps1`
6. Add `"MXX"` to the `[ValidateSet]` on the `-Milestones` parameter

**PS5.1 coding rules (enforced across all modules):**
- No Unicode characters -- ASCII only
- All AD query pipeline results wrapped in `@()` before `.Count`
- No `?.` or `??` operators (PS7 only) -- use explicit `if/else`
- No `$varName:` inside double-quoted strings -- wrap in `$($varName):`
- `[AllowEmptyCollection()]` instead of `[Parameter(Mandatory)]` on array parameters

---

*AD Remediation Agent v2.0*
