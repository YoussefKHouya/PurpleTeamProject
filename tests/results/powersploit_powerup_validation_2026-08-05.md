# PowerSploit PowerUp validation — 2026-08-05

## Verdict

```text
Source pin and SHA-256:              PASS
Binary/script staging:               BLOCKED by Defender
PowerUp import:                      NOT REACHED
Read-only checks:                    NOT REACHED
Defender prevention:                 PASS
Wazuh Defender alert:                PASS
False-positive control:              PASS
Queue-loss check:                    PASS (no rule 203)
Cleanup and endpoint health:         PASS
Overall: detection COMPLETE; execution BLOCKED
```

## Source and prevention

```text
Repository: PowerShellMafia/PowerSploit
Commit: d943001a7defb5e0d1657085a77a0e78609be58f
Artifact: Privesc/PowerUp.ps1
SHA-256: 9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22
```

Pinned script was streamed directly to WIN01. Defender prevented the write before target hash verification and before Yassine could dot-source PowerUp.

Fresh endpoint evidence:

```text
UTC: 2026-08-05T17:18:17.9993360Z
Defender event: 1116
Record: 1284
Threat: HackTool:PowerShell/EventVwrBypass
Threat ID: 2147777634
Severity: High
Category: Tool
Path: C:\Users\yassine.karimi\AppData\Local\Temp\PowerSploitLab\PowerUp.ps1
Process: powershell.exe
Execution state: Suspended
```

No PowerUp function was imported or invoked. This is endpoint prevention, not successful T1012/T1007 impact.

## Wazuh evidence

Manager alert:

```text
Timestamp: 2026-08-05T17:18:18.999+0000
Agent: 004 / WIN01
Rule: 62123
Level: 12
Event: Defender 1116 / record 1284
Threat: HackTool:PowerShell/EventVwrBypass
```

Dashboard filter:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1284"
```

Manager `alerts.json` proves alert receipt. Exact index API confirmation remains unavailable because available dashboard credentials were rejected by the indexer API.

## False-positive control

At `2026-08-05T17:18:58.8757612Z`, low-privilege Yassine ran native registry/service reads and emitted:

```text
PowerSploit PowerUp documentation reference only
```

Low token returned no registry object and no CIM service rows. Matching Defender `1116/1117` events after control timestamp: `0`.

## Cleanup and health

```text
PowerSploitLab directory: absent
PowerUp/PowerSploit processes: 0
WazuhSvc: Running
Real-time protection: enabled
Behavior monitoring: enabled
IOAV protection: enabled
Tamper protection: enabled
Fresh Wazuh rule 203 queue-loss alerts: 0
```

## Follow-up behavioral execution gate

The same temporary real-time-monitoring gate was evaluated after the PowerUp
prevention evidence was preserved. WIN01 reported Tamper Protection enabled and
`Set-MpPreference -DisableRealtimeMonitoring $true` did not change live status;
real-time, behavior, and IOAV protections all remained enabled. Because the
control gate failed, PowerUp was not restaged or imported. No persistent
registry/GPO workaround or exclusion was introduced. Final protection status,
Wazuh service health, and artifact absence all passed.

## Limitation

This validates Defender prevention and Wazuh ingestion for pinned PowerUp content. Because prevention occurred before import, it does not validate behavioral detection for the three read-only PowerUp checks.
