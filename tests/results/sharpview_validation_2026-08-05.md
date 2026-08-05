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

## Follow-up behavioral execution — GUI allowance

A separate behavioral retest ran after the operator changed Defender controls in
the GUI. The pinned binary remained present with SHA-256
`c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93` and no new
Defender event occurred.

Two low-privilege executions were observed:

```text
2026-08-05T17:40:55.7921378Z
  SharpView.exe Get-Domain
  Security 4688 record 35684
  Sysmon 1 record 42164
  Result: process started; bundled parser threw IndexOutOfRangeException

2026-08-05T17:41:14.7592481Z
  SharpView.exe Get-Domain -Domain simulation.local
  Security 4688 record 35689
  Sysmon 1 record 42175
  Identity: SIMULATION\yassine.karimi
  Integrity: Medium
  Returned forest: SIMULATION.LOCAL
  Result: controller expansion stopped by WinRM credential delegation boundary
```

Both process events reached Wazuh native rule `67027`, level 3. Manager archives
also preserved Sysmon start/stop events with the pinned hash, original filename,
product, command line, identity, integrity, and PowerShell parent. This proves
SharpView process execution and partial domain enumeration; it does not prove
complete domain-group enumeration.

A harmless `SharpView documentation reference only` control produced zero matching
Defender events. The binary and test directory were removed and no process
remained. The exact SharpView file exclusion was then removed.

Final inspection revealed the GUI change had disabled real-time, behavior, and
IOAV protection in addition to adding the exact exclusion. Tamper Protection
prevented remote re-enablement. The exact exclusion was removed, but the final
post-batch checkpoint still showed real-time, behavior, and IOAV disabled with
Tamper Protection enabled. Current Defender health is **NOT PASS**; restoration
remains a manual WIN01 GUI gate.

## Limitation

Original prevention remains valid (`62123`, level 12). Behavioral retest verdict
is `EXECUTION PASS / ENUMERATION PARTIAL / GENERIC WAZUH VISIBILITY PASS`.
WinRM did not provide a delegateable domain credential for full DirectoryServices
enumeration. No password was placed in SharpView argv or Wazuh-visible telemetry,
and no custom behavioral rule was authored from generic process evidence alone.
