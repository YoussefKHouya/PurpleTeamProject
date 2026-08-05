# Delegated GPO persistence validation — 2026-08-05

## Verdict

```text
Operational Wazuh GPO preserved:       PASS
Disposable realistic GPO created:      PASS
Target restricted to WIN01:            PASS
Low-privilege GPO edit abuse:          PASS
Endpoint policy application:           PASS
DC/Wazuh detection:                    PASS
Endpoint GroupPolicy telemetry:        PASS
Sysmon Run-value telemetry:             GAP
Read-only false-positive control:       PASS
Rollback and tattoo cleanup:           PASS
Final health:                           PASS
Overall: PASS WITH ENDPOINT SYSMON GAP
```

## Safety decision

The operational `Wazuh - Windows Auditing` GPO was not overwritten. It remained
the detector baseline throughout. Instead, a realistic disposable policy was
created:

```text
Name: Workstation Software Update
GUID: 270b30fc-4a68-41a2-96ef-d44d6f2dc265
Link: domain root, enabled, not enforced, order 3
Authenticated Users: GpoRead only
WIN01$: GpoApply
SIMULATION\yassine.karimi: GpoEdit
```

This modeled a vulnerable delegated workstation-management GPO while preventing
application to other computers.

Operational Wazuh GPO final fingerprint:

```text
GUID:             0738bd22-e453-4f0b-89a7-950cba627004
Modified UTC:     2026-07-27T14:42:44.0000000Z
User version:     0
Computer version: 17
```

It matched the preserved baseline.

## Benign persistence target

WIN01 received a harmless local updater script:

```text
C:\ProgramData\WazuhLab\UpdateHealth.cmd
SHA-256: 049a14d86eb3311a35184d3c7d934f31aaa147f6369ee766748447c3df3690d8
Potential marker: C:\ProgramData\WazuhLab\gpo_update_health.json
```

The marker was absent before and after policy application because no interactive
logon occurred. Payload execution was not claimed.

## Delegated abuse

The GPO mutation executed as ordinary user `SIMULATION\yassine.karimi`, not as
Administrator:

```text
Start: 2026-08-05T19:04:20.2507977Z
End:   2026-08-05T19:04:20.7352927Z
Computer version: 0 -> 1
Key: HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Value: WindowsUpdateHealth
Data: C:\ProgramData\WazuhLab\UpdateHealth.cmd
```

WIN01 forced computer-policy refresh from `19:04:36Z` to `19:04:45Z`:

```text
Computer Policy update completed successfully
Workstation Software Update listed under Applied Group Policy Objects
WindowsUpdateHealth value present with exact updater path
WazuhSvc running
Marker absent — no execution claim
```

## Detection

DC Security 5136 proved the delegated actor and target GPO:

```text
Record 30586: yassine.karimi deleted versionNumber 0
Record 30587: yassine.karimi added versionNumber 1
Record 30588: yassine.karimi added gPCMachineExtensionNames
GPO DN: CN={270B30FC-4A68-41A2-96EF-D44D6F2DC265},CN=Policies,CN=System,...
```

Wazuh agent `001` ingested all three as native rule `60229`, level `4`, mapped to
MITRE `T1484` Domain Policy Modification.

WIN01 application telemetry:

```text
GroupPolicy 5312 record 6714: test GPO applicable
GroupPolicy 4016 record 6719: Registry extension processed test GPO
GroupPolicy 8004 record 6725: manual computer policy complete
System 1502 record 5073: three GPOs applied successfully
```

No Sysmon Event 13 matched `WindowsUpdateHealth`. Endpoint registry-write
visibility remains a documented telemetry gap; endpoint application was instead
proved by exact registry state plus native GroupPolicy logs.

## False-positive control

Same low-privilege actor performed read-only `Get-GPO`:

```text
Start: 2026-08-05T19:06:29.8220145Z
End:   2026-08-05T19:06:30.5653085Z
Action: Get-GPO read only
Computer version remained 1
DC 5136 count: 0
Wazuh 60229 count: 0
```

Control verdict: PASS.

## Dashboard queries

Set time range to include `2026-08-05T19:04:15Z–19:04:40Z`:

```text
agent.id:001 AND rule.id:60229 AND data.win.eventdata.subjectUserName:"yassine.karimi"
agent.id:001 AND rule.id:60229 AND data.win.system.eventRecordID:(30586 OR 30587 OR 30588)
agent.id:001 AND rule.id:60229 AND data.win.eventdata.objectDN:*270B30FC-4A68-41A2-96EF-D44D6F2DC265*
```

Fallback exact-record queries:

```text
agent.id:001 AND data.win.system.eventRecordID:30586
agent.id:001 AND data.win.system.eventRecordID:30587
agent.id:001 AND data.win.system.eventRecordID:30588
```

## Rollback

Yassine removed the policy value through the same delegated path:

```text
Start: 2026-08-05T19:07:13.5199275Z
End:   2026-08-05T19:07:14.2015594Z
Computer version: 1 -> 2
Action: Remove-GPRegistryValue
```

After WIN01 policy refresh, the arbitrary HKLM Run value remained tattooed.
Cleanup removed only `WindowsUpdateHealth` explicitly and verified absence.
Administrator then removed the domain link and disposable GPO.

Final proof:

```text
Test GPO absent
Domain link count: 0
SYSVOL policy directory absent
WIN01 Run value absent
Updater script absent
Marker absent
Test GPO absent from gpresult
WIN01 WazuhSvc: Running
WIN01 WinRM: Running
Wazuh manager: active
Agents 001/004: Active
Operational Wazuh GPO unchanged
```
