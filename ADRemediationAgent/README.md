# 🛡️ AD Remediation Agent

> A PowerShell-based Active Directory remediation agent with human-in-the-loop approval gates, structured audit logging, baseline drift tracking, and HTML reporting.

Designed for post-DC-upgrade environments (targeting Windows Server 2025) and Hybrid Azure AD deployments.

---

## Contents

- [Overview](#overview)
- [Requirements](#requirements)
- [Directory Structure](#directory-structure)
- [Operating Modes](#operating-modes)
- [Quick Start](#quick-start)
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

The AD Remediation Agent automates discovery and remediation across four Active Directory security milestones, while enforcing human approval before any change is made. Built for use from a domain-joined machine or Privileged Access Workstation (PAW) by a Domain Admin or delegated equivalent.

**Core principles:**

- 🔍 **Discover before you change** — all modes produce findings reports; non-Remediate modes have zero side effects
- 🧑‍💻 **Human in the loop, always** — no change is made without explicit operator approval at the CLI, with full blast-radius warnings
- 📸 **Baseline everything** — snapshot AD state after a known-good build; all subsequent runs diff against it
- 📄 **Full audit trail** — every run, finding, approval, and denial is logged to a structured CSV and an HTML report
- ♻️ **Safe-by-default** — no objects are ever deleted; stale accounts are quarantined (disabled + moved), not removed

---

## Requirements

| Requirement | Detail |
|---|---|
| PowerShell | 5.1 or later (7.x recommended) |
| Module | `ActiveDirectory` (RSAT on a workstation, or run from a DC / member server) |
| Tools in PATH | `repadmin`, `dcdiag`, `w32tm`, `dfsrdiag` |
| Permissions | Domain Admin, or delegated read (Discover) / write (Remediate) access |
| Platform | Windows 10/11 or Windows Server 2016+ domain-joined machine |

---

## Directory Structure

```
ADRemediationAgent/
├── Start-ADRemediationAgent.ps1        ← Entry point
├── README.md
├── Config/
│   └── AgentConfig.psd1                ← Thresholds, group lists, environment settings
├── Core/
│   ├── Write-AgentLog.ps1              ← Structured CSV logging engine
│   ├── Invoke-HumanApproval.ps1        ← CLI approval gate (single-item and bulk)
│   ├── Save-Baseline.ps1               ← Baseline snapshot and drift comparison
│   ├── Compare-Baseline.ps1            ← Baseline comparison wrapper
│   └── New-RunReport.ps1               ← Per-run HTML report generator
├── Modules/
│   ├── Invoke-M1-DCHealthBaseline.ps1  ← M1: DC Health Check
│   ├── Invoke-M4-UnconstrainedDelegation.ps1  ← M4: Delegation Remediation
│   ├── Invoke-M11-StaleAccounts.ps1    ← M11: Stale Account Quarantine
│   └── Invoke-M12-PrivilegedGroups.ps1 ← M12: Privileged Group Audit
├── Logs/           ← Per-run CSV logs          (auto-created at runtime)
├── Reports/        ← HTML reports and snapshots (auto-created at runtime)
└── Baselines/      ← JSON baseline snapshots   (auto-created at runtime)
```

---

## Operating Modes

| Mode | Description | Makes Changes |
|---|---|---|
| `Discover` | Runs all checks, logs findings, produces HTML report | No |
| `Baseline` | Snapshots current AD state as the approved reference point | No |
| `Remediate` | Discovers findings, then prompts for human approval on each remediable item | Yes — with approval only |
| `Report` | Loads stored baselines and run logs, generates a historical drift report. No AD queries. | No |

### Targeting specific milestones

```powershell
# Run all v1 milestones (default)
.\Start-ADRemediationAgent.ps1 -Mode Discover

# Run specific milestones only
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4,M12

# Target a specific domain (defaults to current machine's domain)
.\Start-ADRemediationAgent.ps1 -Mode Discover -Domain "corp.contoso.com"

# Custom output path
.\Start-ADRemediationAgent.ps1 -Mode Discover -OutputPath "D:\ADAudit\Output"
```

---

## Quick Start

### 1 — Initial discovery (no changes)

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Discover
```

Runs all four milestones and produces a findings report. Nothing is changed. Review the HTML report in `.\ADAgent-Output\Reports\`.

### 2 — Set an approved baseline

Run this after your DC upgrades are complete and the environment is in a known-good state:

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Baseline
```

Snapshots current AD findings to `Baselines\baseline-latest.json`. All future runs diff against this, showing **NEW**, **PERSISTING**, and **RESOLVED** findings.

### 3 — Remediate with human approval

```powershell
# Highest risk first — unconstrained delegation
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4

# Then privileged group membership
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M12

# Then stale accounts (bulk approval UI)
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M11
```

### 4 — Ongoing monitoring

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Discover
```

Each run produces a new report with deltas against your baseline. Schedule weekly for continuous drift visibility.

---

## Milestone Reference

| ID | Name | What It Checks | Remediates | Risk |
|---|---|---|---|---|
| **M1** | DC Health & Baseline | Replication, FSMO roles, DNS, SYSVOL, AD Recycle Bin, time sync, OS versions, functional levels | No — flags only; acknowledgment required for CRITICAL | INFO to HIGH |
| **M4** | Unconstrained Delegation | All computers and users with `TrustedForDelegation = $true` (excluding DCs) | Yes — per-object approval; sets `TrustedForDelegation = $false` | HIGH / CRITICAL |
| **M11** | Stale Account Quarantine | Users and computers inactive > 90 days (configurable threshold) | Yes — bulk approval; disable + move to Quarantine OU + stamp description | LOW / MEDIUM |
| **M12** | Privileged Group Review | Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, and more — new members, stale accounts, service accounts in Tier 0, computer accounts, nested groups | Yes — per-member approval; removes from group only (account not disabled or deleted) | HIGH / CRITICAL |

---

## Approval Gate Behaviour

Every remediable finding passes through one of two approval gates before any change executes.

### Single-item gate (used by M4 and M12)

```
  ╔══════════════════════════════════════════════════════════╗
  ║  APPROVAL REQUIRED  [HIGH   ]  Milestone: M4            ║
  ╚══════════════════════════════════════════════════════════╝

  ACTION  : Remove unconstrained delegation from computer account
  TARGET  : APPSRV01 (CN=APPSRV01,OU=Servers,DC=corp,DC=com)

  ─── What will happen if you approve ──────────────────────
    ▸ TrustedForDelegation will be set to FALSE on this computer account.
    ▸ If any service on this host uses Kerberos unconstrained delegation, it WILL BREAK.
    ▸ Affected services: anything relying on this host to delegate Kerberos tickets.

  ─── Rollback steps if this causes issues ──────────────────
    ↩ Set-ADComputer 'APPSRV01' -TrustedForDelegation $true
    ↩ Verify Kerberos ticket acquisition for affected services

  Options:  [A] Approve   [S] Skip this item   [Q] Quit milestone
```

### CRITICAL and HIGH risk — typed confirmation required

For HIGH and CRITICAL risk changes, the operator must type the target name exactly before the `[A/S/Q]` prompt appears. Pressing Enter without a match skips the item automatically.

```
  ⚠  This is a CRITICAL risk change. Type the target name to unlock approval.

  Type [APPSRV01] exactly to continue, or press Enter to SKIP:
```

### Bulk approval gate (used by M11)

Stale accounts are shown as a full list with selective exclusion before bulk action:

```
  Options:
    [A] Approve ALL items above
    [E] Exclude specific accounts then approve the rest
    [N] Skip ALL — no changes
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
   - **NEW** — not present at baseline (potential regression or new risk)
   - **PERSISTING** — present at both baseline and current run (known, accepted risk)
   - **RESOLVED** — was in the baseline but is no longer found (successfully remediated)

### Baseline files

| File | Description |
|---|---|
| `Baselines/baseline-latest.json` | Active baseline — overwritten each time `-Mode Baseline` runs |
| `Baselines/baseline-<RunId>.json` | Archived snapshot per Baseline run |

### Drift-only report (no AD queries)

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Report
```

Loads the stored baseline and the last 10 run logs. Produces an HTML drift report with metrics and full action history. No AD write access required.

---

## Hybrid Azure AD Notes

> ⚠️ **Read this if your environment uses Hybrid Azure AD Join**

`LastLogonDate` on AD user objects reflects **on-premises Kerberos logons only**. Users who authenticate exclusively via Entra ID or cloud apps will show a stale on-prem `LastLogonDate` and may be incorrectly flagged as inactive by M11.

**Recommended steps before running M11 in Remediate mode in a hybrid environment:**

**Step 1** — Cross-reference with Entra ID sign-in logs:

```powershell
# Requires Microsoft.Graph module
Connect-MgGraph -Scopes "AuditLog.Read.All"
Get-MgAuditLogSignIn -Filter "userPrincipalName eq 'jsmith@corp.com'" -Top 5
```

**Step 2** — Export recent Entra sign-in activity and compare against M11's stale user list before approving bulk quarantine.

**Step 3** — Set `HybridAAD = $true` in `Config\AgentConfig.psd1` to display a warning reminder at the start of every M11 run.

**Step 4** — Use the `[E] Exclude` option at the M11 bulk approval prompt to protect cloud-active accounts from quarantine.

---

## Output Files

All output is written to `.\ADAgent-Output\` by default, overridable with `-OutputPath`.

| Path | Description |
|---|---|
| `Logs\RUN-<timestamp>.log` | Structured CSV log for every agent run |
| `Reports\RunReport-<timestamp>.html` | Per-run findings, delta vs baseline, and action log |
| `Reports\DriftReport-<timestamp>.html` | Cross-run drift analysis (Report mode) |
| `Reports\M12-PrivGroupSnapshot-<ts>.csv` | Privileged group membership snapshot per run |
| `Reports\M1-ReplicationSummary-<ts>.txt` | Raw `repadmin /replsummary` output |
| `Baselines\baseline-latest.json` | Active approved baseline snapshot |
| `Baselines\baseline-<RunId>.json` | Archived baseline per Baseline-mode run |

---

## Configuration

Edit `Config\AgentConfig.psd1` to customise behaviour for your environment:

```powershell
@{
    # Stale account thresholds (days inactive before flagging)
    StaleUserDays      = 90
    StaleComputerDays  = 90
    StalePrivDays      = 60    # Privileged accounts flagged after 60 days

    # Quarantine OU — leave empty to auto-construct from domain DN
    QuarantineOU       = ""    # e.g. "OU=Quarantine-Disabled,DC=corp,DC=com"

    # Accounts that are never quarantined regardless of inactivity
    ProtectedPatterns  = @("krbtgt", "Guest", "Administrator", "DefaultAccount")

    # Privileged groups audited by M12
    PrivilegedGroups   = @(
        "Domain Admins", "Enterprise Admins", "Schema Admins",
        "Backup Operators", "Account Operators", "Print Operators",
        "Server Operators", "Group Policy Creator Owners"
    )

    # Set to $true in Hybrid Azure AD environments to enable logon-date warnings
    HybridAAD          = $false
}
```

---

## Security Notes

- The agent **never deletes** AD objects. Stale accounts are disabled and moved to a Quarantine OU; deletion is always a separate, deliberate manual step.
- The agent **never runs silently** in `Remediate` mode — every change requires explicit operator input.
- All actions are logged with timestamps, object DNs, outcome status, and rollback context.
- Run from a **Privileged Access Workstation (PAW)** and consider wrapping execution in a Just-In-Time privileged session.
- The agent does not store or prompt for credentials. It uses the current Windows user context via the `ActiveDirectory` module.

---

## Extending the Agent

To add a new milestone module:

1. Create `Modules\Invoke-MXX-YourMilestone.ps1`
2. Define a function `Invoke-MXX` with parameters `($Mode, $Domain, $OutputPath)`
3. Use the Core helpers: `Write-AgentLog`, `Invoke-HumanApproval`, `Invoke-BulkApproval`
4. Add the milestone to `$milestoneMap` and `$milestoneNames` in `Start-ADRemediationAgent.ps1`
5. Add `"MXX"` to the `[ValidateSet]` on the `-Milestones` parameter

---

*AD Remediation Agent v1.0*
