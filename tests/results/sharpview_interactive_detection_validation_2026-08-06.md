# SharpView interactive and detection validation — 2026-08-06

## Verdict

```text
Execution identity:                         PASS — SIMULATION\yassine.karimi
Integrity:                                  PASS — Medium
Explicit DC LDAP query:                     PASS
AS-REP-roastable account returned:          PASS — hannah.reed
Native process telemetry:                   PASS
Rule 100522 named-tool control:              PASS
Rule 100523 initial path-anchored control:   FAIL
Rule 100523 corrected renamed-tool test:     PASS
Documentation-only negative control:        PASS
Artifact retention:                         PASS — intentional
Overall:                                    PASS
```

## Artifact and execution

Pinned source:

```text
Repository: tevora-threat/SharpView
Commit: b60456286b41bb055ee7bc2a14d645410cca9b74
SHA-256: c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93
```

The operator executed the retained binary interactively as ordinary domain user
`SIMULATION\yassine.karimi`:

```powershell
.\sharpview.exe Get-NetUser -PreauthNotRequired -Domain simulation.local -Server DC01.simulation.local
```

SharpView bound to:

```text
LDAP://DC01.simulation.local/DC=simulation,DC=local
```

The query returned `hannah.reed` with `DONT_REQ_PREAUTH`. This proves successful
read-only LDAP enumeration; it is not another WinRM/CredSSP partial result.

Wazuh evidence for the successful named execution:

```text
Security 4688 record: 39160
Sysmon Event 1 record: 50410
Native Wazuh rule:     67027 / level 3
```

## Custom rules

`rules/sharpview_detection.xml` contains:

```text
100522 / level 12 — known SharpView filename plus Get-NetUser/Get-DomainUser
                     -PreauthNotRequired semantics
100523 / level 10 — filename-independent executable child of PowerShell/pwsh/cmd
                     with the same exact discovery semantics
MITRE: T1087.002, T1558.004
Parent: native Windows Security 4688 rule 67027
```

### Rule 100522 positive control

A harmless live matcher control used a copy of `whoami.exe` named
`SharpViewRuleTest\sharpview.exe` with SharpView-compatible arguments. This was
only a rule-unit test; it was not represented as SharpView execution.

```text
Security record: 39193
Rule:            100522
Level:           12
Result:          PASS
```

The real SharpView LDAP execution above independently proves tool behavior.

### Rule 100523 failed first attempt and correction

The first rename-resistant rule anchored the entire decoded Windows path. Wazuh
preserved doubled path separators in decoded fields, so real control record
`39194` selected only native rule `67027`. Verdict: **FAIL**.

The rule was corrected to avoid path-separator dependence. It now requires:

- an executable child process;
- a `powershell.exe`, `pwsh.exe`, or `cmd.exe` parent basename;
- `Get-NetUser` or `Get-DomainUser` with `-PreauthNotRequired` in process argv.

### Real renamed SharpView validation

The operator copied the actual pinned SharpView binary to `survey.exe` and ran:

```powershell
.\survey.exe Get-NetUser -PreauthNotRequired -Domain simulation.local -Server DC01.simulation.local
```

Sysmon proved this was the actual SharpView binary rather than a filename-only
simulation:

```text
Security 4688 record: 39237
Sysmon Event 1 record: 50599
Image:                 C:\Users\yassine.karimi\AppData\Local\Temp\survey.exe
OriginalFileName:      SharpView.exe
Product/Description:   SharpView
SHA-256:               c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93
User:                  SIMULATION\yassine.karimi
Integrity:             Medium
Parent:                powershell.exe
Rule:                  100523
Level:                 10
Result:                PASS
```

Rule `100522` did not identify the renamed event. Rule `100523` supplied the
intended filename-independent coverage.

## False-positive control

```powershell
Write-Output 'Get-NetUser -PreauthNotRequired documentation only'
```

```text
PowerShell 4104 record: 139332
Rule 100522 alerts:     0
Rule 100523 alerts:     0
Result:                 PASS
```

This control remains quiet because the custom rules require Windows Security
4688 executable-process telemetry, not documentation text in a script block.

## Retention

The following are intentionally retained for reproducibility:

```text
C:\Users\yassine.karimi\AppData\Local\Temp\sharpview.exe
C:\Users\yassine.karimi\AppData\Local\Temp\survey.exe
```

No Defender, CredSSP, tool, or lab-state rollback was performed. Cleanup occurs
only by explicit operator request or when required for safety/test validity.
