# AD Remediation Agent -- Design Decisions

This document records the key design and implementation decisions made during
the development of the AD Remediation Agent for the MetLife engagement.
Updated: 2026-03-20.

---

## Language and Runtime

### PS5.1 Only (No PowerShell 7)
**Decision:** Target PowerShell 5.1 exclusively. No PS7-specific syntax.
**Why:** Client DCs run Windows Server 2019 today and will move to 2025.
PowerShell 5.1 ships in-box on both. PS7 requires a separate install and
MSI deployment that is not scoped to this engagement.
**Enforced by:**
- Pre-commit validation: `[System.Management.Automation.Language.Parser]::ParseFile`
- Non-ASCII grep check (box-drawing chars fail the parser)
- PS7 operator grep check (`?.`, `??`, `??=` are not valid in PS5.1)

### Set-StrictMode -Version Latest
**Decision:** Enable strict mode inside every Invoke-Mx function.
**Why:** Forces early detection of undefined variables and property access on
$null (PropertyNotFoundException). Caught multiple bugs during development where
`@()` wrapping was missing.
**Implication:** Every pipeline result that could be $null or empty must be
wrapped in `@()`. Use `[AllowEmptyCollection()]` on array parameters, not
`[Parameter(Mandatory)]`.

### Output Path Default
**Decision:** Default `$OutputPath` resolves to `Join-Path $PSScriptRoot "ADAgent-Output"`.
**Why:** When running as Administrator, the working directory resolves to
`C:\Windows\system32`. Using `$PSScriptRoot` anchors output next to the script
regardless of how it is invoked.

---

## Architecture

### Global State via $Global:FindingsList and $Global:RunTimestamp
**Decision:** Findings are accumulated in a module-level `[System.Collections.Generic.List[PSCustomObject]]`
and timestamp is shared via `$Global:RunTimestamp`.
**Why:** Each Invoke-Mx function is called from a central orchestrator. Findings
need to be aggregated and report-card stamped at the end of all milestones.
A shared list avoids passing collections by reference through every call frame.

### Human-in-the-Loop Approval Gates
**Decision:** Every remediable action requires operator approval via
`Invoke-HumanApproval` before execution. Bulk approval via `Invoke-BulkApproval`
is available for lower-risk items.
**Why:** Client scope explicitly requires change-controlled remediation. The
agent must never silently modify production AD. Every approved action is logged
to the action log with the operator response.
**Rollback steps** are always presented to the operator before they approve.

### Discover vs Remediate Mode
**Decision:** Every module accepts a `$Mode` parameter (`"Discover"` or `"Remediate"`).
Checks marked Discover-only never attempt changes regardless of mode.
**Why:** Safe default. Client can run agent in audit-only mode first, review
the report, then selectively run Remediate mode for specific milestones.

### DC Upgrade Gate
**Decision:** M3 through M12 Remediate mode is blocked until all DCs report
Windows Server 2025. M1 Discover still runs and flags PENDING/URGENT upgrade
status per DC.
**Why:** Several hardening controls (Protected Users full support, Auth Policies,
Credential Guard by default) behave differently on Server 2019 vs 2025.
Remediating against the wrong baseline wastes effort and risks misconfiguration.
IP-bound application risk also needs to be resolved at DC upgrade time.

### M2 Not Scripted
**Decision:** Milestone 2 (DC Upgrade) is a manual change-controlled process.
No automation script was created.
**Why:** DC upgrades at MetLife require change management approval, application
owner sign-off (IP-bound app risk), DFSR health verification, and a swing
migration approach for IP reassignment. These are not automatable without
out-of-scope infrastructure orchestration.

---

## Compliance Framework

### CIS Level 1 Checks + NIST SP 800-53 Control IDs
**Decision:** Use CIS Benchmark Level 1 (Windows Server 2022/2025) as the
technical check source. Surface NIST SP 800-53 control IDs in findings and
reports as the governance/reporting layer.
**Why:** Client preferred CIS L1 as the operational baseline (specific,
prescriptive, directly auditable). NIST provides the control framework for
the client's governance reporting and audit evidence requirements.
**Mapping:** Each finding includes `CISControl`, `CISLevel`, and `NISTControl`
fields. The final report card maps findings to NIST control families.

---

## Milestone-Specific Decisions

### M1 -- DC Health Baseline

**DFSR vs FRS Replication**
SYSVOL replication mode is detected and flagged HIGH if FRS is still in use.
FRS is a prerequisite blocker for the DC upgrade to Server 2025 (FRS was
removed in Server 2019 -- any remaining FRS nodes must be migrated to DFSR
before upgrade). Flagged as URGENT.

**IPv4 Address per DC**
DC IP addresses are captured in the inventory finding `Data` field. This
supports the IP-bound application risk analysis for the DC upgrade plan.

**FSMO Role Annotation**
Each DC's FSMO roles (if any) are annotated in the DCInventory finding.
Important for upgrade sequencing -- FSMO holders should be upgraded last
(or roles seized/transferred) to minimise impact.

---

### M3 -- OU Structure Cleanup

**All checks Discover-only**
OU restructuring has a high blast radius -- OU path changes break existing
GPO links and membership-by-location assumptions. M3 produces a full audit
report for the AD team to act on via the normal change management process.
No automated remediation is offered.

**Checks implemented (7):**
1. OU Inventory -- CSV export with depth, GPO link flag, block-inheritance
   flag, user/computer/child-OU counts, protection status.
2. Default Container Usage -- objects in CN=Computers or CN=Users instead
   of purpose-built OUs (receive only domain-root GPOs).
3. Empty OUs -- zero users, computers, and child OUs.
4. Block Inheritance OUs -- gPOptions bit 0 set; security hardening GPOs
   from parent/root will not apply.
5. Policy Gap OUs -- populated OUs with block inheritance AND no direct
   GPO link. Escalated to HIGH (objects may receive no policy at all).
6. Deep OU Nesting -- depth > 5 levels.
7. Non-Standard OU Delegation -- non-inherited Allow ACEs with GenericAll,
   WriteDacl, WriteOwner, or GenericWrite to non-standard principals.
   CSV export. Checked via Get-Acl on the AD: PSDrive.

**Efficiency note**
Object-count maps are built via three bulk queries (Get-ADUser, Get-ADComputer,
OU depth from allOUs loop) rather than per-OU queries. DN parent extraction
uses a simple IndexOf(",") substring -- no regex overhead per object.

---

### M5 -- SPN Audit

**Single Scan Strategy**
All SPN-bearing objects are fetched once at module start (`$allSpnObjects`,
`$spnMap`). All checks re-use this snapshot. Avoids repeated LDAP queries
and ensures consistency across checks within a single run.

**Tier 0 Scope**
Built once from the union of Domain Admins, Enterprise Admins, and Schema
Admins. Used to escalate findings to CRITICAL for privileged accounts.

**Kerberoastable Definition**
User accounts that are Enabled=true AND have at least one SPN AND lack AES
encryption type bits (0x8 AES128, 0x10 AES256) in msDS-SupportedEncryptionTypes.
RC4-only Kerberoastable accounts are the highest-risk class -- attackers can
crack the TGS ticket offline.

**Remediation: Set AES bits, then prompt for password reset**
Setting KerberosEncryptionType alone does not change the existing TGS keys.
A password reset causes the KDC to re-derive keys using the new enc types.
A `PendingPasswordReset` follow-up finding is raised for each fixed account.

**Duplicate SPN Remediation: Discover-Only**
Duplicate SPNs may indicate a valid service migration or misconfiguration.
The correct registration must be determined by the application owner before
any SPN is removed. The agent flags duplicates but never removes them.

**Tier 0 SPN Presence: CRITICAL, Typed Confirmation**
Service accounts with SPNs on Tier 0 accounts (DA, EA, SA) require the
operator to type "CONFIRM" before any action is offered. These accounts are
high-value Kerberoasting targets.

---

### M6 -- Kerberos Configuration

**RC4 Audit Scope Broader than M5**
M5 checks Kerberoastable accounts (accounts with SPNs). M6 checks ALL enabled
user accounts for RC4-only configuration. An account without an SPN cannot
be Kerberoasted, but it can still authenticate via RC4 (AS-REQ), exposing
session keys to NTLM-relay and downgrade attacks. Different threat vector.

**SYSVOL GptTmpl.inf for Ticket Policy**
Kerberos ticket policy (MaxTicketAge, MaxRenewAge, MaxClockSkew, MaxServiceAge)
is set in the Default Domain Policy's GptTmpl.inf, which is Unicode-encoded.
The file is read via `Get-Content -Encoding Unicode`. A direct read of the
SYSVOL path is used rather than GPRESULT to avoid dependency on policy
application state.

**Protected Users: Flag Service Accounts INSIDE the Group**
Protected Users disables RC4, all delegation, cached credentials, and caps
the TGT at 4 hours. Service accounts with SPNs inside Protected Users will
have their delegation silently fail. The check flags this as HIGH and
recommends removing the service account from the group.

**WHfB Kerberos Hybrid Trust**
Checked via: (1) DFL >= 2016, (2) presence of CN=AzureADKerberos in the
CN=Computers container, (3) msDS-KeyCredentialLink set on the AzureADKerberos
object, (4) sample of 500 users for WHfB enrollment (msDS-KeyCredentialLink).
This is the Microsoft Kerberos Cloud Trust model used at MetLife.

**Auth Policy + Silo: Graceful Degradation**
Authentication Policies and Silos require AD functional level 2016+. If the
cmdlets are unavailable (older RSAT), the check logs a WARN and skips rather
than crashing. The DFL check finding warns if the environment is not yet eligible.

---

### M7 -- DC Hardening

**WinRM Remote Checks via Invoke-Command**
All checks run remotely against each DC via WinRM (Invoke-Command). A generic
registry read scriptblock (`$regReadBlock`) is defined once and passed as a
parameter -- avoids re-defining it inside each Invoke-Command call.

**Test-WSMan Prereq per DC**
WinRM availability is tested with `Test-WSMan` before any remote commands.
DCs where WinRM is unavailable receive a HIGH finding (WinRM itself is a
hardening gap) and are skipped for the remaining checks.

**WDigest: Absent Key = Compliant**
If `HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest\UseLogonCredential`
does not exist, the OS defaults to WDigest disabled (Windows 8.1/Server 2012 R2+).
Only flag if the key exists AND equals 1. Avoids false positives on clean systems.

**NLA/RDP: GPO Path First, Then Direct Path**
NLA enforcement (UserAuthentication) is checked first via the GPO Terminal
Services path, then via the direct Terminal Server registry path. Ensures
correct detection when GPO vs local setting is in effect.

**Audit Policy: Discover-Only**
The audit policy check reads subcategory configuration via `auditpol /get`
parsed remotely. It is intentionally Discover-only -- subcategory audit
configuration is environment-specific and must not be changed without a
log ingestion design review (volume implications for the SIEM).

**Reboot Tracking**
LSASS Protected Process Light (check 7) and Credential Guard (check 11)
require a reboot to take effect after the registry change. These DCs are
tracked in `$rebootRequired` and a consolidated banner is printed after
the remediation loop. The banner lists the specific DCs and commands to
apply the pending changes.

---

### M8 -- GPO Cleanup

**Backup-GPO -All Before Any Change**
A full GPO backup runs to a timestamped folder before any remediation action.
If the backup fails, the entire remediation phase is aborted. No GPO changes
are ever applied without a successful backup on record.

**Unlinked GPO Remediation: Disable, Not Delete**
Unlinked GPOs are first disabled (AllSettingsDisabled) rather than deleted.
Deletion is reserved for GPOs that are already disabled AND confirmed unlinked
(check 3) or empty (check 4). This gives the GPO owner a window to identify
and reclaim GPOs that were unlinked by accident.

**Empty GPO Confirmation via XML Report**
DSVersion 0/0 is a necessary but not sufficient condition for "empty."
Get-GPOReport -ReportType Xml is called for each candidate to confirm the
absence of ExtensionData in both Computer and User nodes. This eliminates
false positives from DSVersion counter resets.

**DDP/DDCP Modification: Discover-Only**
Modifications to the Default Domain Policy and Default Domain Controllers
Policy are flagged but never auto-remediated. CIS guidance is to migrate
custom settings to separate GPOs; dcgpofix is a nuclear option. This requires
a deliberate, change-managed process.

**SYSVOL Orphan Detection: Both Directions**
Orphans are checked in both directions:
- AD GPO object with no SYSVOL folder (clients get error 1058)
- SYSVOL folder with no AD GPO object (replication traffic, potential confusion)
Both require manual cleanup due to risk of DFSR replication conflicts.

**GPO Delegation Standard Patterns**
Standard GPO editors: Domain Admins, Enterprise Admins, SYSTEM (Edit);
Authenticated Users (Apply Group Policy -- read-only Apply, not Edit).
ENTERPRISE DOMAIN CONTROLLERS and Creator Owner are also standard.
Any other principal with GpoEdit / GpoEditDeleteModifySecurity / GpoCustom
is flagged as non-standard and exported to a delegation CSV.

**GroupPolicy Module Prereq: Early Return**
If the GroupPolicy module is not available, a HIGH finding is raised and
the function returns immediately. The module requires GPMC (RSAT-Group-Policy
on workstations, Add-WindowsFeature GPMC on servers) or must be run from a DC.

---

### M10 -- Delegated Permissions Review

**ACL Enumeration via AD: PSDrive**
All ACL checks use `Get-Acl "AD:\<DN>"` via the AD: PSDrive (provided by the
ActiveDirectory module). No ADSI or direct LDAP binding required. If the AD:
drive is unavailable, M10 returns immediately with a CRITICAL finding.

**DCSync: Flag All Non-Standard Principals, Not Just Unknown Ones**
Rather than attempting to identify known-legitimate service accounts (e.g.
Azure AD Connect, ADFS), M10 flags ALL principals that are not Domain Admins,
Enterprise Admins, Administrators, SYSTEM, or ENTERPRISE DOMAIN CONTROLLERS.
The operator decides which are legitimate (e.g. an AAD sync account). This
avoids false negatives from name-pattern matching on service account SAM names.

DCSync rights are exported to a CSV inventory regardless of whether violations
are found -- the operator gets a full list of who can replicate hashes.

**DS-Replication-Get-Changes-All is the Critical Right**
DS-Replication-Get-Changes alone does not grant access to password hashes.
DS-Replication-Get-Changes-All does. Both are flagged, but Get-Changes-All
findings are elevated to CRITICAL. The Filtered-Set right is also checked.

**AdminSDHolder: SDProp Persistence Risk**
A non-standard ACE on AdminSDHolder is effectively permanent -- SDProp re-stamps
the ACL onto all protected accounts every 60 minutes. Even if an operator manually
removes the backdoor ACE from a specific user account, SDProp will restore it.
The root fix is always at CN=AdminSDHolder, not on individual accounts.
AdminSDHolder findings are Discover-only: removal requires ADSI Edit or dsacls
under a separate change request given the scope of the change.

**DC OU Delegation: Only Remediable Check in M10**
The DC OU (OU=Domain Controllers) is the only ACL target where M10 offers
automated per-ACE removal. This scope is chosen because:
- The DC OU is a single, well-known, high-value target
- Non-standard ACEs here are almost always misconfiguration, not legitimate delegation
- Blast radius is limited to the one OU object (no child objects affected)
All other ACL checks (domain root, AdminSDHolder, DNS, DCSync) are Discover-only
because those changes require deliberate review and change management.

**Rollback for ACE Removal**
Rollback steps are printed to the operator before approval. The exact PowerShell
`New-Object DirectoryServices.ActiveDirectoryAccessRule` / `AddAccessRule` /
`Set-Acl` sequence is provided so the operator can restore the ACE if needed.
The agent log records the removed ACE in full detail.

**DC Delegation: Complements M4**
M4 remediates unconstrained delegation on non-DC accounts. M10 check 6 focuses
exclusively on DC computer objects, covering:
- Unconstrained delegation on DCs outside OU=Domain Controllers (unexpected placement)
- Constrained delegation (msDS-AllowedToDelegateTo) on DCs (non-default, should be reviewed)
- Protocol-transition delegation (TrustedToAuthForDelegation) on DCs (CRITICAL -- very unusual)
Normal DCs have TrustedForDelegation=True inside OU=Domain Controllers; this is
expected Kerberos infrastructure behaviour and is not flagged.

---

## Baseline and Drift Tracking

**JSON Snapshots**
Finding snapshots are saved as JSON at the end of each run. Subsequent runs
compare current findings against the previous baseline and label findings as:
- `NEW` -- not in previous baseline
- `PERSISTING` -- same finding, same object, both runs
- `RESOLVED` -- in previous baseline but not current run

This gives the client a clear view of remediation progress over time.

---

## Security and Operational Safety

### No Silent Changes
The agent never modifies AD objects, GPOs, registry, or audit policy without
explicit operator approval and log entry.

### Action Log
Every approved remediation action is written to the action log with:
- Timestamp
- Milestone
- Action description
- Target object
- Operator response

### Secrets and Credential Handling
No credentials are stored in scripts or config files. The agent runs under
the operator's current session context. WinRM connections use the operator's
Kerberos token.

### .gitignore
Runtime output (logs, reports, baselines, GPO backups) is excluded from git.
Only source code and config are tracked. The `.claude/settings.local.json`
(local Claude Code overrides) is also excluded.

---

## Outstanding / Deferred Decisions

| Item | Status | Notes |
|------|--------|-------|
| M11 Fine-Grained Password Policy | Stub | TBD |
| M12 Privileged Access Workstation Audit | Stub | TBD |
| GitHub Actions CI lint | Deferred | PSScriptAnalyzer + PS5.1 parse on PR |
| Report card HTML/PDF output | Deferred | Final deliverable format TBD with client |
| Authentication Policies: Tier 0 silo creation | Discover-only for now | Silo design requires AD team input |
