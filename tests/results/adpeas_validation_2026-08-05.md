# adPEAS validation — 2026-08-05

## Verdict

```text
Source pin and SHA-256:              PASS
Low-privilege PowerShell import:     PASS
Authenticated LDAP session:         BLOCKED by WinRM delegation boundary
Bounded Domain module execution:     PARTIAL
Defender prevention:                 NOT TRIGGERED
Wazuh process alert:                 PASS
False-positive control:              PASS
Queue-loss check:                    PASS (no rule 203)
Cleanup and endpoint health:         PASS
Overall: PARTIAL
```

## Source

```text
Repository: 61106960/adPEAS
Commit: 1ea06f1d2dc92152b5aaeca6eacff24dd096d82e
Artifact: adPEAS_min.ps1
SHA-256: 7d7c1535ef4d33f24b738509af3962500453070ae94b0cbb23927c6e65d0a10b
```

Only `-OPSEC -Module Domain` was allowed. No credential, roast, ticket, spray, DCSync, RBCD, Shadow Credential, ADCS-abuse, BloodHound, or write operation ran.

## Execution

Pinned script transferred successfully and its target hash matched. It imported under:

```text
Identity: SIMULATION\yassine.karimi
Start: 2026-08-05T17:00:31.8534872Z
Import: successful
```

`Invoke-adPEAS -Domain SIMULATION.LOCAL -UseWindowsAuth -OPSEC -Module Domain` reached its LDAP connection phase but reported invalid credentials because the remote WinRM token could not delegate usable credentials to LDAP. A constrained follow-up called `Get-DomainInformation`; it emitted limited policy-style output but also reported no domain controllers. That output is not accepted as complete authenticated AD enumeration.

No explicit credentials were inserted into endpoint commands or telemetry. Result remains `PARTIAL`, not full enumeration success.

## Endpoint and Wazuh evidence

Fresh low-privilege process event:

```text
UTC: 2026-08-05T17:02:09.4087462Z
Security event: 4688
Record: 35217
User: yassine.karimi
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
Parent: C:\Windows\System32\wsmprovhost.exe
Integrity: medium
```

Manager alert:

```text
Timestamp: 2026-08-05T17:02:11.061+0000
Agent: 004 / WIN01
Rule: 100134
Level: 11
Description: Encoded PowerShell command executed with policy bypass
MITRE: T1059.001, T1027
Event record: 35217
```

This proves PowerShell execution and wrapper behavior. It does not provide rename-resistant adPEAS attribution or prove successful LDAP enumeration.

Dashboard filter:

```text
agent.id:"004" AND rule.id:"100134" AND data.win.system.eventRecordID:"35217"
```

Exact index API confirmation remained unavailable because the available dashboard credential was rejected by the indexer API. Manager `alerts.json` evidence is proven.

## False-positive control

At `2026-08-05T17:03:47.5069383Z`, Yassine emitted:

```text
ADPeas documentation reference only
```

Matching Defender `1116/1117` events: `0`.

## Cleanup and health

```text
ADPeasLab directory: absent
adPEAS processes: 0
WazuhSvc: Running
Real-time protection: enabled
Behavior monitoring: enabled
IOAV protection: enabled
Tamper protection: enabled
Fresh Wazuh rule 203 queue-loss alerts: 0
```

## Limitation

Current management route creates a WinRM double-hop boundary for adPEAS Windows-auth LDAP. Full authenticated Domain-module validation requires a genuine interactive Yassine context or a credential-delegation design that does not leak secrets into process/script-block telemetry. No workaround was forced.
