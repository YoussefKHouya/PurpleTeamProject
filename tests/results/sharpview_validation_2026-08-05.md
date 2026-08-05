# SharpView validation — 2026-08-05

## Verdict

```text
Source pin and SHA-256:              PASS
Low-privilege execution intent:      PASS
Binary transfer/write:               BLOCKED by Defender
SharpView Get-Domain execution:      NOT REACHED
Defender prevention:                 PASS
Wazuh Defender alert:                PASS
Dashboard/index confirmation:        PENDING operator view
False-positive test:                 PASS
Cleanup and endpoint health:         PASS
Overall: detection COMPLETE; enumeration execution BLOCKED
```

## Source

```text
Repository: tevora-threat/SharpView
Commit: b60456286b41bb055ee7bc2a14d645410cca9b74
Compiled/SharpView.exe SHA-256: c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93
Size: 736256 bytes
```

Source review confirmed that SharpView contains both read-only and mutating methods. Only `Get-Domain` was selected. No mutating method was invoked.

## Execution and prevention

The binary was streamed directly to WIN01 through the management path without persistent staging on the bridge or Pi. Defender blocked the file write before Yassine could execute `Get-Domain`.

Fresh endpoint evidence after restarting the Wazuh agent and performing one bounded replay:

```text
Time: 2026-08-05T16:56:46.2491691Z
Defender event: 1116
Record: 1270
Threat: VirTool:MSIL/Menace.C!MTB
Threat ID: 2147757125
Severity: Severe
Category: Tool
Path: C:\Users\yassine.karimi\AppData\Local\Temp\SharpViewLab\SharpView.exe
Execution state: Suspended
```

No `SharpView.exe` process creation occurred and no domain-enumeration output was returned. Result is `BLOCKED`, not successful enumeration.

## Wazuh evidence

Manager `alerts.json` and `archives.json` received record `1270`:

```text
Indexed/manager timestamp: 2026-08-05T16:56:51.675+0000
Agent: 004 / Win01
Rule: 62123
Level: 12
Event: Defender 1116 / record 1270
Threat field: VirTool:MSIL/Menace.C!MTB
```

Dashboard filter:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1270"
```

Exact index API confirmation was unavailable because the existing dashboard/indexer credential returned `Unauthorized`; manager alert evidence is proven and the filter is ready for operator confirmation.

## False-positive test

At `2026-08-05T16:57:28.7626058Z`, Yassine emitted only:

```text
SharpView documentation reference only
```

Observed matching Defender events after that timestamp: `0`.

## Cleanup and health

```text
SharpViewLab directory: absent
SharpView processes: 0
WazuhSvc: Running
Real-time protection: enabled
Behavior monitoring: enabled
IOAV protection: enabled
Tamper protection: enabled
Temporary SMB firewall change: restored; rule disabled with LocalSubnet scope
```

## Follow-up behavioral execution gate

At `2026-08-05T17:25:03.0351946Z`, after the prevention evidence had been
preserved, an administrator attempted a temporary process-level Defender
real-time-monitoring disable for a separate behavioral test. `Set-MpPreference`
returned no error, but live status remained:

```text
RealTimeProtectionEnabled: true
BehaviorMonitorEnabled: true
IoavProtectionEnabled: true
IsTamperProtected: true
```

Tamper Protection silently vetoed the change. No SharpView restaging or execution
was attempted, and no Defender registry/GPO workaround, exclusion, obfuscation,
or persistent policy change was used. An explicit enable command was issued and
the final protection baseline remained fully enabled. This follow-up is
`BLOCKED AT CONTROL GATE`; the original prevention verdict is unchanged.

## Limitation

This validates Defender-backed prevention and Wazuh alerting for the pinned SharpView binary. It does not validate rename-resistant LDAP behavior detection because Defender prevented process start and no LDAP enumeration occurred.
