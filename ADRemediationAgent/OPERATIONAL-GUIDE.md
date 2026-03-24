# AD Remediation Agent — Operational Guide

> **Audience:** AD operators running the agent day-to-day. For architecture, extension, and compliance framework detail see [README.md](README.md).

---

## Contents

- [Prerequisites](#prerequisites)
- [Starting the Agent](#starting-the-agent)
- [Operating Modes](#operating-modes)
- [Milestone Reference](#milestone-reference)
- [Common Scenarios](#common-scenarios)
- [Approval Workflow](#approval-workflow)
- [Reading the Output](#reading-the-output)
- [Configuration Quick Reference](#configuration-quick-reference)
- [Warnings and Limits](#warnings-and-limits)

---

## Prerequisites

Before running the agent, confirm the following on the machine you will run it from:

| Requirement | How to check |
|-------------|--------------|
| PowerShell 5.1 | `$PSVersionTable.PSVersion` |
| ActiveDirectory module (RSAT) | `Get-Module -ListAvailable ActiveDirectory` |
| `repadmin`, `setspn` in PATH | `where.exe repadmin` |
| GroupPolicy module (for M8) | `Get-Module -ListAvailable GroupPolicy` |
| WinRM reachable to all DCs (for M7) | `Test-WSMan -ComputerName <DC>` |
| Domain Admin, or delegated equivalent | Required for Remediate mode |
| Domain-joined machine | Required — agent uses current Windows session credentials |

Run from a **Privileged Access Workstation (PAW)** where possible. The agent never stores or prompts for credentials — it uses your current Kerberos session.

---

## Starting the Agent

```powershell
# Syntax
.\Start-ADRemediationAgent.ps1 -Mode <mode> [-Milestones <list>] [-Domain <fqdn>] [-OutputPath <path>]
```

| Parameter | Required | Default | Description |
|-----------|----------|---------|-------------|
| `-Mode` | Yes | — | `Discover`, `Remediate`, `Baseline`, or `Report` |
| `-Milestones` | No | All (M1,M3–M12) | Comma-separated list of milestones to run, e.g. `M4,M7,M12` |
| `-Domain` | No | Current machine's domain | FQDN of target domain |
| `-OutputPath` | No | `.\ADAgent-Output` | Root folder for all logs, reports, and baselines |

**Examples:**

```powershell
# Full discovery run — all milestones, no changes
.\Start-ADRemediationAgent.ps1 -Mode Discover

# Discover specific milestones only
.\Start-ADRemediationAgent.ps1 -Mode Discover -Milestones M1,M7,M12

# Remediate a specific milestone under a change request
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4

# Save an approved baseline snapshot
.\Start-ADRemediationAgent.ps1 -Mode Baseline

# Generate a drift report without connecting to AD
.\Start-ADRemediationAgent.ps1 -Mode Report

# Target a different domain
.\Start-ADRemediationAgent.ps1 -Mode Discover -Domain corp.contoso.com

# Write output to a specific path
.\Start-ADRemediationAgent.ps1 -Mode Discover -OutputPath D:\ADAudit\Output
```

---

## Operating Modes

| Mode | Makes changes | When to use |
|------|:---:|-------------|
| `Discover` | No | Any time — safe to run repeatedly. Produces a full findings report against the current baseline. Use for routine monitoring, pre-change audits, and post-change validation. |
| `Remediate` | Yes — with approval | Under a MetLife change request, after DC upgrade is complete. Each remediable finding requires explicit operator approval before any change executes. |
| `Baseline` | No | After a known-good state (post-upgrade, post-remediation wave). Snapshots current findings as the reference point for all future drift tracking. |
| `Report` | No | Generates a historical drift report from stored run data. Requires no AD connection — useful for status reporting without needing DA access. |

> **DC Upgrade Gate:** `Remediate` mode is blocked for M3–M12 if any DC is not yet on Windows Server 2025. `Discover` mode will warn and require you to type `CONTINUE`. This is controlled by `DCUpgradeGateEnabled` in `AgentConfig.psd1`.

---

## Milestone Reference

M2 (DC Upgrade to Windows Server 2025) has no automation script — it is a manual, change-controlled process. See the DC Upgrade Workflow section in [README.md](README.md) for the full sequence.

---

### M1 — DC Health Baseline

**Discover-only. Always run first.**

Produces a full DC inventory — names, IP addresses, OS versions, sites, FSMO role holders, and upgrade readiness status (COMPLETE / PENDING / URGENT) for each DC. Also checks:

- Replication health via `repadmin /replsummary` — flags any errors per DC pair
- SYSVOL replication mode — flags legacy FRS as a blocking issue (FRS is incompatible with Server 2025)
- AD Recycle Bin status
- PDC Emulator time sync skew
- `krbtgt` password age — warns at 180 days, critical at 365
- Accounts with pre-authentication disabled (AS-REP roastable)
- Domain Admins not enrolled in Protected Users

**Remediates:** Nothing. HIGH and CRITICAL findings require manual investigation and acknowledgment.

**Run after every DC upgrade** to confirm upgrade completion and clear the DC Upgrade Gate for M3–M12.

**Output:** `Reports\M1-ReplicationSummary-<timestamp>.txt` — raw repadmin output for review.

---

### M2 — DC Upgrade to Windows Server 2025

**Manual process — no automation script.**

M1 produces the DC inventory and upgrade readiness flags used to plan and sequence this work. The upgrade itself (swing migration, IP handover, FSMO transfers, post-upgrade validation) is executed manually under a MetLife change request. Refer to the DC Upgrade Runbook delivered in Phase 2 of the engagement.

---

### M3 — OU Structure Cleanup

**Discover-only.**

Audits the OU hierarchy and produces a prioritised report for the AD team to action through change management. Checks for:

- Objects sitting in default containers (`CN=Computers`, `CN=Users`) that miss OU-level GPOs
- Empty OUs (safe candidates for removal)
- OUs with block inheritance set — hardening GPOs from parent OUs will not apply
- Policy gap OUs — block inheritance enabled AND no direct GPO link, meaning objects receive no policy at all
- OU nesting deeper than 5 levels
- Non-standard delegation ACEs on OUs (GenericAll, WriteDacl, WriteOwner to unexpected principals)

**Remediates:** Nothing — OU restructuring breaks GPO links and group-membership-by-location assumptions; all changes require AD team planning and a change request.

**Output:** `M3-OUInventory-<timestamp>.csv` and `M3-OUDelegation-<timestamp>.csv`.

---

### M4 — Unconstrained Delegation

**Remediates with per-object approval. HIGH / CRITICAL risk.**

Identifies computer and user accounts with unconstrained Kerberos delegation enabled (`TrustedForDelegation = $true`), excluding Domain Controllers (where it is expected). Unconstrained delegation allows any service on that host to impersonate any user to any resource — a critical attack path.

**In Remediate mode:** For each finding, you choose to:
- Remove unconstrained delegation entirely (`TrustedForDelegation = $false`)
- Migrate to constrained delegation (you specify the target SPNs)
- Skip with a documented justification

**Before approving:** Confirm with the application owner whether the service on that host uses Kerberos delegation. Removing it from a service that requires it will break authentication for that service.

**Rollback:** `Set-ADComputer '<name>' -TrustedForDelegation $true`

---

### M5 — SPN Audit

**Partially remediable. MEDIUM / HIGH risk.**

Audits all Service Principal Names registered in the domain. Checks for:

- **Duplicate SPNs** — two accounts registered for the same SPN (causes Kerberos authentication failures). Discover-only; application owner validation required before removal.
- **Kerberoastable accounts** — user accounts with SPNs and no AES encryption type set; any authenticated user can request their service ticket and attempt offline password cracking. Remediable: enables AES encryption on the account.
- **SPNs on disabled accounts** — orphaned SPNs with no running service. Remediable: removes the SPN.
- **SPNs on Tier 0 accounts** — Domain Admins, Enterprise Admins, or Schema Admins with SPNs registered. CRITICAL. Remediable: removes the SPN from the privileged account.

**Note on Kerberoastable remediation:** Enabling AES on an account requires the account password to be reset before the new encryption type takes effect. Coordinate this with the service account owner — the service will need its credentials updated.

**Output:** `M5-SPNInventory-<timestamp>.csv` and `M5-setspn-XF-<timestamp>.txt`.

---

### M6 — Kerberos Configuration

**Partially remediable. MEDIUM / HIGH risk.**

Reviews the Kerberos configuration of the domain, focusing on encryption types and authentication settings:

- **Kerberos ticket policy** — validates MaxTicketAge, MaxRenewAge, MaxClockSkew, and MaxServiceAge against CIS L1 recommendations. Discover-only; fix via Default Domain Policy GPO.
- **RC4-only accounts** — enabled user accounts with no AES encryption type configured. RC4 is weak and Kerberoastable. Remediable: enables AES128 + AES256 on the account (password reset required).
- **Protected Users membership** — verifies all Tier 0 accounts are enrolled in Protected Users; flags service accounts incorrectly inside the group (Protected Users blocks NTLM, delegation, and RC4 — service accounts inside it will break).
- **Windows Hello for Business Kerberos hybrid trust** — confirms the Azure AD Kerberos server object is present, the domain functional level is 2016 or higher, and `msDS-KeyCredentialLink` is populated. Discover-only.
- **Authentication Policy and Silo coverage** — lists configured policies and silos; flags Tier 0 accounts not covered. Discover-only.

---

### M7 — DC Hardening and CIS Level 1 Baseline

**Remediates with per-check, per-DC approval. HIGH / CRITICAL risk.**

Connects to each DC via WinRM and runs 12 CIS Benchmark Level 1 hardening checks. All checks that are not already compliant are flagged and, in Remediate mode, can be corrected with approval:

| Check | CIS Reference | What it fixes |
|-------|---------------|---------------|
| LDAP Signing | 2.3.11.8 | Requires clients to sign LDAP communications — prevents LDAP relay attacks |
| LDAP Channel Binding | 18.3.3 | Prevents LDAP over TLS from being downgraded |
| SMB Server Signing | 2.3.6.6 | Requires SMB clients to sign — prevents SMB relay |
| SMB Client Signing | 2.3.6.2 | Requires the DC to sign when acting as SMB client |
| NLA for RDP | 18.9.65.3.3.1 | Enforces Network Level Authentication before RDP session is established |
| Print Spooler | 18.3.6 | Disables the Print Spooler service on DCs — eliminates PrintNightmare attack surface |
| LSASS Protected Process Light | 18.9.46.2 | Prevents credential dumping from LSASS memory — **requires reboot** |
| Guest Account | 2.3.1.2 | Confirms Guest account is disabled |
| Anonymous SAM / Share Enumeration | 2.3.10.2/.3 | Prevents unauthenticated enumeration of accounts and shares |
| WDigest | 18.3.7 | Disables WDigest — prevents plaintext credential caching in LSASS |
| Credential Guard | 18.9.46.4 | Enables Credential Guard to protect NTLM hashes and Kerberos TGTs — **requires reboot** |
| Advanced Audit Policy | 17.x | Discovers audit subcategory gaps — Discover-only; fix via GPO |

**Reboot tracking:** DCs that require a reboot after remediation (LSASS PPL, Credential Guard) are tracked and a consolidated reboot list is displayed at the end of the milestone. Schedule reboots through change management — do not reboot all DCs simultaneously.

**Prerequisite:** WinRM must be reachable on each DC. A DC where WinRM is unavailable is itself flagged as a finding.

---

### M8 — GPO Cleanup

**Remediates with per-GPO approval. LOW / MEDIUM risk.**

Audits all Group Policy Objects in the domain. **In Remediate mode, a full GPO backup (`Backup-GPO -All`) runs automatically before any changes. If the backup fails, the entire remediation phase aborts.**

| Check | Remediable | Action |
|-------|:----------:|--------|
| Unlinked GPOs | Yes | Disable all settings (safe first step before deletion) |
| All-settings-disabled + unlinked | Yes | Delete (already inert — second approval required) |
| Empty GPOs (version 0/0, XML-confirmed) | Yes | Delete (never configured) |
| Default Domain Policy / DDCP modifications | No | Reports custom settings that risk being overwritten by `dcgpofix` |
| SYSVOL orphans | No | Reports GPOs with no SYSVOL folder and SYSVOL folders with no AD object |
| Disabled GPO links | No | Reports links that are set to disabled but still cluttering the namespace |
| GPO delegation audit | No | Reports non-standard edit/modify permissions on GPOs |

**Output:** `M8-GPOInventory-<timestamp>.csv`, `M8-GPODelegation-<timestamp>.csv`, and a full GPO backup folder at `OutputPath\GPOBackup-<timestamp>\`.

**Prerequisite:** GroupPolicy module (GPMC) must be installed on the machine running the agent.

---

### M9 — Security Group Cleanup

**Partially remediable. LOW / MEDIUM risk.**

Audits security group membership and structure across the domain:

- **Empty security groups** — groups with no members; Discover-only (confirm not used for resource ACLs before removing).
- **Disabled accounts in security groups** — disabled users and computers still holding group memberships. Remediable: removes the disabled account from each group with per-item approval.
- **Privileged group audit** — non-user objects (computer accounts, nested unprivileged groups) in DA/EA/SA; groups with more than 10 members; disabled members. Discover-only.
- **Circular group nesting** — A is a member of B, B is a member of A (or longer chains). Discover-only; causes unpredictable token bloat and must be broken manually.
- **Large universal groups** — groups with membership above threshold. Universal group membership is replicated to every Global Catalog server in the forest — large groups cause significant replication overhead.
- **AdminSDHolder remnants** — accounts with `AdminCount = 1` that are no longer members of any protected group. SDProp has left them with locked-down ACLs blocking normal permission inheritance. Remediable: clears `AdminCount` to re-enable inheritance.
- **Mail-enabled security groups** — security groups with email attributes set, exposing membership via email directory.

---

### M10 — Delegated Permissions Review

**Minimally remediable. HIGH / CRITICAL risk.**

Audits the most sensitive ACL positions in the domain. Most checks are Discover-only because incorrect ACL changes at the domain root or AdminSDHolder carry a blast radius of full domain compromise.

| Check | Remediable | Notes |
|-------|:----------:|-------|
| DCSync rights | No | Lists all non-standard principals with `DS-Replication-Get-Changes-All` on the domain root. Removal requires `dsacls` or ADSI Edit under a separate change request. |
| Domain root high-risk ACEs | No | GenericAll, WriteDacl, WriteOwner on the domain naming context root — any of these grants effective domain admin. |
| AdminSDHolder ACEs | No | Non-standard ACEs propagate to every protected account every 60 minutes via SDProp — review carefully before any removal. |
| DC OU delegation | Yes | Non-standard ACEs on `OU=Domain Controllers` — per-ACE removal with CRITICAL-level typed confirmation required. |
| DNS permissions | No | DnsAdmins membership and non-standard write ACEs on the MicrosoftDNS container — DnsAdmins can execute code on DCs. |
| DC computer object delegation | No | Constrained or unconstrained delegation flags set on DC computer objects. |

**Output:** `M10-DCsyncRights-<timestamp>.csv` — take this to management if any unexpected principals appear.

---

### M11 — Stale Account Quarantine

**Remediates with bulk approval. LOW / MEDIUM risk.**

Identifies user and computer accounts that have not logged on within the configured threshold (default: 90 days for users and computers, 60 days for privileged accounts). Protected accounts (`krbtgt`, `Guest`, `Administrator`, `DefaultAccount`, and any patterns in `ProtectedPatterns`) are always excluded.

**Quarantine process (never deletes):**
1. Account is **disabled**
2. Account is **moved** to the Quarantine OU (auto-created at `OU=Quarantine,<domain root>` if not configured)
3. Account description is **stamped** with `QUARANTINED by AD Agent <date>`

To recover an account: re-enable it and move it back to its original OU. The original OU is not preserved automatically — check the run log for the DN before quarantine.

**Hybrid Azure AD warning:** On-premises `LastLogonDate` only reflects Kerberos logons against on-premises DCs. Users who authenticate exclusively through Entra ID will appear stale here. Before approving bulk quarantine in Remediate mode, cross-reference against Entra ID sign-in logs and use the `[E] Exclude` option to protect cloud-active accounts.

**Bulk approval flow:**
```
  [A] Approve ALL — quarantine every account in the list
  [E] Exclude specific accounts, then approve the rest
       (enter comma-separated SamAccountNames to exclude)
  [N] Skip ALL — no changes
```

---

### M12 — Privileged Group Review

**Remediates with per-member approval. HIGH / CRITICAL risk.**

Inventories membership in all configured privileged groups (Domain Admins, Enterprise Admins, Schema Admins, Backup Operators, Account Operators, Print Operators, Server Operators, Group Policy Creator Owners) and compares against the stored baseline.

Flags:
- **New members not in baseline** — CRITICAL; unexpected privilege elevation
- **Stale privileged accounts** (no logon > 60 days) — HIGH; dormant Tier 0 credentials are a significant attack target
- **Service accounts in Tier 0 groups** — HIGH; service accounts should never be in privileged groups
- **Computer accounts in privileged groups** — CRITICAL
- **Nested groups** — flags visibility gaps where effective membership is hidden

**In Remediate mode:** Per-member removal with approval. Only group membership is changed — the account is not disabled or deleted.

**Output:** `M12-PrivGroupSnapshot-<timestamp>.csv` saved after every run. Review this file to track Tier 0 membership trends over time.

---

## Common Scenarios

### First run — establish the baseline

```powershell
# Step 1: Full discovery — review all findings, no changes
.\Start-ADRemediationAgent.ps1 -Mode Discover

# Step 2: Review Reports\RunReport-<timestamp>.html
# Step 3: After DC upgrade is complete, set the post-upgrade baseline
.\Start-ADRemediationAgent.ps1 -Mode Baseline
```

### Targeted remediation session (under a change request)

```powershell
# Run Discover first to confirm current state before making changes
.\Start-ADRemediationAgent.ps1 -Mode Discover -Milestones M4

# Then remediate under the approved change window
.\Start-ADRemediationAgent.ps1 -Mode Remediate -Milestones M4

# Validate by running Discover again — resolved findings will show as RESOLVED vs baseline
.\Start-ADRemediationAgent.ps1 -Mode Discover -Milestones M4
```

### Recommended remediation order (risk-first)

Run each milestone as a separate Remediate session under its own change request:

1. `M4` — Unconstrained delegation (highest attack impact)
2. `M10` — DC OU ACE cleanup (Discover all checks; remediate DC OU only)
3. `M7` — DC hardening (schedule DC reboots after session)
4. `M6` — Kerberos encryption types
5. `M5` — SPN cleanup and Kerberoastable accounts
6. `M12` — Privileged group membership
7. `M11` — Stale account quarantine (cross-reference Entra ID first)
8. `M8` — GPO cleanup
9. `M9` — Security group cleanup

M1 and M3 are Discover-only — run these at any time.

### Ongoing monitoring (post-remediation)

```powershell
# Weekly scheduled run — flags any drift against baseline
.\Start-ADRemediationAgent.ps1 -Mode Discover

# Generate a drift summary without connecting to AD (e.g. for a status meeting)
.\Start-ADRemediationAgent.ps1 -Mode Report
```

### Check whether a specific DC has been upgraded

```powershell
.\Start-ADRemediationAgent.ps1 -Mode Discover -Milestones M1
# Review the DC inventory in the report — each DC shows COMPLETE / PENDING / URGENT upgrade status
```

---

## Approval Workflow

Every remediable finding in Remediate mode passes through an approval gate before any change executes.

### Standard approval (M4, M5, M7, M9, M10, M12)

```
  +----------------------------------------------------------+
  |  APPROVAL REQUIRED  [HIGH]  Milestone: M4                |
  +----------------------------------------------------------+

  ACTION  : Remove unconstrained delegation from computer account
  TARGET  : APPSRV01 (CN=APPSRV01,OU=Servers,DC=corp,DC=com)

  --- What will happen if you approve ---
    TrustedForDelegation will be set to FALSE on this account.
    Services on this host relying on Kerberos delegation WILL BREAK.

  --- Rollback ---
    Set-ADComputer 'APPSRV01' -TrustedForDelegation $true

  Options:  [A] Approve   [S] Skip   [Q] Quit milestone
```

### CRITICAL and HIGH — typed confirmation required

Before the `[A/S/Q]` prompt appears, you must type the target object name exactly:

```
  [!] HIGH risk change. Type the target name to unlock:

  Type [APPSRV01] to continue, or press ENTER to skip:
```

### Bulk approval (M11)

Stale accounts are listed in full before any action. You can exclude individual accounts before approving the rest:

```
  [A] Approve ALL     [E] Exclude specific, then approve rest     [N] Skip ALL
```

### Quitting a milestone

Type `[Q]` at any prompt to stop the current milestone immediately. Items already approved in that run remain changed and are recorded in the action log. Remaining items are skipped.

---

## Reading the Output

All output is written to `.\ADAgent-Output\` by default.

| File | Description |
|------|-------------|
| `Logs\RUN-<timestamp>.log` | Structured CSV — every finding, approval, and action with timestamps and CIS/NIST references |
| `Reports\RunReport-<timestamp>.html` | Full findings report with CIS L1 compliance card, NIST control grouping, and delta vs baseline (NEW / PERSISTING / RESOLVED) |
| `Reports\DriftReport-<timestamp>.html` | Cross-run drift summary (Report mode only) |
| `Reports\M1-ReplicationSummary-<ts>.txt` | Raw `repadmin /replsummary` output |
| `Reports\M12-PrivGroupSnapshot-<ts>.csv` | Privileged group membership snapshot — review after every run |
| `Baselines\baseline-latest.json` | Active baseline — overwritten each time Baseline mode runs |
| `Baselines\baseline-<RunId>.json` | Archived baseline per Baseline-mode run — retain these |
| `M3-OUInventory-<ts>.csv` | Full OU inventory with GPO link and delegation flags |
| `M5-SPNInventory-<ts>.csv` | Full SPN inventory across the domain |
| `M8-GPOInventory-<ts>.csv` | Full GPO inventory with link counts and status |
| `M10-DCsyncRights-<ts>.csv` | All principals holding DCSync rights — review immediately if unexpected entries appear |
| `OutputPath\GPOBackup-<ts>\` | Full GPO backup taken before any M8 remediation |

### Finding severity levels

| Severity | Meaning |
|----------|---------|
| `CRITICAL` | Immediate remediation recommended — active attack path or compliance failure |
| `HIGH` | Should be remediated promptly — significant security exposure |
| `MEDIUM` | Plan to remediate — meaningful risk reduction |
| `LOW` | Hygiene improvement — low direct risk |
| `INFO` | Informational — no action required, context only |

### Baseline delta labels

| Label | Meaning |
|-------|---------|
| `NEW` | Not present at baseline — potential regression or new risk introduced since last baseline |
| `PERSISTING` | Present at both baseline and this run — known, accepted state |
| `RESOLVED` | Was in baseline, no longer found — successfully remediated |

---

## Configuration Quick Reference

Edit `Config\AgentConfig.psd1` to adjust behaviour for your environment.

| Setting | Default | Description |
|---------|---------|-------------|
| `DCUpgradeGateEnabled` | `$true` | Set `$false` after all DCs are on Server 2025 |
| `TargetDCOS` | `"2025"` | Matched against the DC's `OperatingSystem` string |
| `HybridAAD` | `$true` | Enables Entra ID cross-reference warning before M11 runs |
| `IPBoundAppsPresent` | `$true` | Adds IP-binding warning to M1 DC inventory output |
| `StaleUserDays` | `90` | Inactivity threshold for user accounts in M11 |
| `StaleComputerDays` | `90` | Inactivity threshold for computer accounts in M11 |
| `StalePrivDays` | `60` | Inactivity threshold for privileged accounts in M11 |
| `QuarantineOU` | `""` | Leave empty to auto-create `OU=Quarantine,<domain root>` |
| `ProtectedPatterns` | See config | Account names never quarantined by M11 |
| `PrivilegedGroups` | See config | Groups audited by M12 |
| `AutoOpenReport` | `$false` | Set `$true` to auto-open the HTML report in the browser after each run |
| `LogRetentionCount` | `90` | Number of log files to retain before rotation |

---

## Warnings and Limits

- **M7 requires WinRM** on all DCs. A DC where WinRM is unreachable is itself logged as a HIGH finding and its hardening checks are skipped for that run.
- **M8 requires the GroupPolicy module (GPMC)**. Run `Add-WindowsFeature GPMC` on the agent machine if it is not available.
- **M11 does not cross-reference Entra ID sign-in logs** — it can only see on-premises `LastLogonDate`. Always review the stale user list against Entra ID before approving bulk quarantine in a hybrid environment.
- **No object is ever deleted** by the agent. Stale accounts are quarantined (disabled + moved). GPOs are backed up and disabled before deletion is offered. Deleted GPO links are reported only.
- **Baseline mode overwrites `baseline-latest.json`**. The previous latest is archived with a timestamped filename — do not delete the `Baselines\` folder between runs.
- **Remediate mode requires a change request** for every session. The action log (`Logs\RUN-<timestamp>.log`) is the audit record for that change request — retain it.
- **M10 DC OU ACE removal is CRITICAL risk**. An incorrect ACE removal on `OU=Domain Controllers` can break DC management delegation. Read the rollback steps carefully before approving.
- The agent runs under your current Windows session. If your session token does not have Domain Admin rights (or appropriate delegated rights), AD write operations will fail silently at the change and be recorded as errors in the log.

---

*AD Remediation Agent v2.2 — Operational Guide. Updated March 2026.*
