# PowerSploit PowerUp CredSSP behavioral retest — 2026-08-06

## Verdict

```text
Pinned source and SHA-256:              PASS
CredSSP Yassine/Kerberos session:       PASS
PowerUp import:                         PASS
Get-RegistryAlwaysInstallElevated:      EXECUTED
Get-UnquotedService:                    ACCESS DENIED under remote low token
Get-ModifiableService:                  SCM ACCESS DENIED under remote low token
Defender block during retest:           NO
Wazuh native detection:                 PASS (91823 / level 14)
Dashboard confirmation:                 PENDING operator view
Target artifact/process cleanup:        PASS
CredSSP retention:                       INTENTIONAL for later lab work
Overall: PARTIAL — execution proven; two host checks limited by token/context
```

This remote-session verdict remains accurate for the CredSSP execution context.
The host-check limitation was later closed from a genuine local Yassine shell;
see `powerup_interactive_detection_validation_2026-08-06.md`.

This behavioral retest does not replace the original Defender prevention result. The original `HackTool:PowerShell/EventVwrBypass` event and native Wazuh rule `62123` remain valid.

## Scope

```text
Repository: PowerShellMafia/PowerSploit
Commit: d943001a7defb5e0d1657085a77a0e78609be58f
Artifact: Privesc/PowerUp.ps1
SHA-256: 9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22
Host: WIN01
Identity: SIMULATION\yassine.karimi
Authentication: Kerberos through CredSSP
```

Only three read-only checks ran. `Invoke-PrivescAudit`, service mutation, UAC bypass, persistence, credential checks, privilege manipulation, and exploitation functions were not invoked.

## Execution

The first wrapper stopped after an unlabelled `Access denied` result. It produced PowerShell records `99935` and `100008`, no Defender match, and cleaned all target artifacts. A corrected per-function run then preserved each check result independently:

```text
Start: 2026-08-06T09:58:37.5465604Z
End:   2026-08-06T09:58:45.7026943Z
Identity: SIMULATION\yassine.karimi
AuthenticationType: Kerberos
Verdict: EXECUTION_PASS_WITH_CHECK_FAILURES

Get-RegistryAlwaysInstallElevated:
  Status: PASS
  Returned objects: 1

Get-UnquotedService:
  Status: ACCESS_DENIED_OR_FAILED
  Error: Access denied

Get-ModifiableService:
  Status: ACCESS_DENIED_OR_FAILED
  Error: Cannot open Service Control Manager on computer '.'; additional privileges may be required
```

A direct read under Yassine verified `AlwaysInstallElevated` was absent in both HKLM and HKCU; therefore the returned PowerUp object is not reported as an exploitable misconfiguration:

```text
HKLM AlwaysInstallElevated: absent
HKCU AlwaysInstallElevated: absent
Exploitable: false
```

The two denied checks were an execution-context limitation, not Defender
prevention. A later interactive low-privilege Yassine run completed the host
audit and is documented separately in
`powerup_interactive_detection_validation_2026-08-06.md`.

No matching Defender `1116/1117` event occurred in either behavioral run. Final Defender real-time, behavior, IOAV, and tamper protections were enabled.

## Wazuh evidence

```text
Agent: 004 / WIN01
Event: PowerShell Operational 4104
Record: 100167
Rule: 91823
Level: 14
Timestamp: 2026-08-06T09:58:35.213+0000
Description: PowerShell Invoke-Command remote execution
```

The manager contained the event in both `archives.json` and `alerts.json`. No custom rule was added because native rule `91823` detected the actual execution at level 14. Dashboard confirmation was not received before documentation.

Dashboard query:

```text
agent.id:"004" AND rule.id:"91823" AND data.win.system.eventRecordID:"100167"
```

No fresh queue-loss rule `203` occurred during the PowerView/PowerUp window.

## Cleanup and retained lab posture

```text
PowerSploitLab: absent
PowerUp/PowerSploit processes: 0
C:\Windows\Temp\HermesCredSSPRunner.ps1: absent
WazuhSvc: Running
WIN01 agent 004: Active
Wazuh manager: active
Defender real-time/behavior/IOAV/tamper: enabled
CredSSP client/server: enabled
Delegation target: wsman/WIN01.SIMULATION.LOCAL only
```

CredSSP remains enabled by explicit operator direction for reproducible later
lab work, restricted to `wsman/WIN01.SIMULATION.LOCAL`. No rollback is required
unless the operator requests it or the isolated-lab boundary changes.
