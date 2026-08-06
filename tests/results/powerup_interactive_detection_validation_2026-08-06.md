# PowerUp interactive audit and Wazuh detection validation — 2026-08-06

## Verdict

```text
Interactive low-privilege execution:       PASS
PowerUp full audit execution:              PASS
PowerShell 4104 collection:                PASS
Original custom detection coverage:        GAP
Custom rule 100521 live positive:          PASS
Documentation-string negative control:     PASS
Manager alerts.json proof:                 PASS
Indexer/dashboard exact-document proof:    PASS
Endpoint cleanup requirement:              WAIVED by lab retention policy
CredSSP retention:                          INTENTIONAL for later lab work
```

## Scope

```text
Endpoint: WIN01
Agent: 004
Identity: SIMULATION\yassine.karimi
Session: local interactive PowerShell
Artifact: %TEMP%\power.ps1
Source commit: d943001a7defb5e0d1657085a77a0e78609be58f
Expected SHA-256: 9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22
Command: Invoke-AllChecks
Rule XML: rules/powerup_detection.xml
```

## Interactive execution

The operator ran `Invoke-AllChecks` from a genuine local Yassine shell. This removed the remote WinRM/CredSSP token limitation that had prevented complete service-manager enumeration.

PowerShell Operational records received by the manager:

```text
Invoke-AllChecks:           104573
Get-UnquotedService:        104676
Get-ModifiableServiceFile:  104681
Get-ModifiableService:      126085
```

All four were present in `archives.json` without a selected alert rule. This proved a detection gap rather than a collection failure.

PowerUp returned candidate findings for `edgeupdate`, `edgeupdatem`, and the user-owned `%PATH%` directory `C:\Users\yassine.karimi\AppData\Local\Microsoft\WindowsApps`.

The service finding is not classified as exploitable from this output alone. PowerUp associated the service path with ACL rights on `C:\`, not with proven write access to the quoted executable under `C:\Program Files (x86)\Microsoft\EdgeUpdate`. `CanRestart` was false. Binary, parent-directory, service DACL, and privileged load behavior were not proven writable.

The `%PATH%` finding proves Yassine can modify the user's own WindowsApps path. It does not prove a privileged process loads `wlbsctrl.dll` from that location. No DLL was written and no hijack was attempted.

## Rule engineering

Rule `100521`, level 12, detects exact `Invoke-AllChecks` or `Invoke-PrivescAudit` script-block invocation semantics. It is independent of the PowerUp filename and excludes function definitions, alias creation, command discovery, and documentation strings.

MITRE mappings:

```text
T1059.001 — PowerShell
T1007     — System Service Discovery
```

The first candidate inherited native informational parent `60009`. Live record `130904` reached archives as exact `Invoke-AllChecks`, but no custom alert fired. Verdict: FAIL. Root cause: PowerShell 4104 records carry `VERBOSE` severity and follow native chain `60000 → 91801 → 91802` on this Wazuh version.

The rule was corrected to inherit `91802`, syntax-tested with `wazuh-analysisd -t`, deployed, and manager health verified before retest.

## Live positive

Harmless child PowerShell defined a stub named `Invoke-AllChecks` and invoked only that stub:

```powershell
powershell.exe -NoProfile -NonInteractive -Command "function Invoke-AllChecks { 'SyntheticPowerUpRuleTest2' }; Invoke-Expression 'Invoke-AllChecks'"
```

Observed result:

```text
Output: SyntheticPowerUpRuleTest2
PowerShell event: 4104
Record: 131587
Script block: Invoke-AllChecks
Rule: 100521
Level: 12
Timestamp: 2026-08-06T10:56:21.337+0000
```

The exact record exists in both `archives.json` and `alerts.json`.

## False-positive control

```powershell
powershell.exe -NoProfile -NonInteractive -Command "Write-Output 'Invoke-AllChecks documentation reference only 2'"
```

Observed records:

```text
4104 record 131674 — outer command
4104 record 131678 — documentation string
Custom rule 100521 alerts: 0
```

Generic process visibility still produced native/custom process alerts; those are not PowerUp attribution.

## Index and Dashboard

Exact index query for agent `004`, rule `100521`, and record `131587` returned one document:

```text
total: 1
rule.id: 100521
rule.level: 12
data.win.system.eventID: 4104
data.win.system.eventRecordID: 131587
data.win.eventdata.scriptBlockText: Invoke-AllChecks
```

Dashboard filter:

```text
agent.id:"004" AND rule.id:"100521" AND data.win.system.eventRecordID:"131587"
```

## Retained reproducible lab posture

No endpoint cleanup is required. An earlier automated cleanup command timed out,
so the current presence of `%TEMP%\power.ps1` is not claimed either way; future
reproductions may retain or re-download it. CredSSP remains enabled and
restricted to `wsman/WIN01.SIMULATION.LOCAL`. Lab tools, vulnerable
configuration, and useful access posture are retained by default; cleanup or
rollback occurs only on explicit operator request or when required for test
validity or containment outside the isolated lab.
