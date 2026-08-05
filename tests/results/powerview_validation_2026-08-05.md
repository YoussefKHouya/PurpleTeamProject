# PowerView reconnaissance validation — 2026-08-05

## Verdict

```text
Source pin and review:                 PASS
Low-privilege Yassine preflight:       PASS
LDAP read preflight:                   PASS
PowerView staging and hash check:      PASS on final rerun
PowerView script import:               BLOCKED by Defender
PowerView Get-* execution:             NOT REACHED
Defender prevention:                   PASS
Wazuh generic process alert:           PASS
Defender Operational collection:       PASS after telemetry update
Native Wazuh Defender alert:           PASS
Dashboard confirmation:                PASS for 100110/34415 and 62123/1245
False-positive test:                   PASS
Cleanup and service recovery:          PASS
Overall: detection validation COMPLETE; reconnaissance execution BLOCKED
```

This result proves prevention and telemetry, not successful PowerView domain reconnaissance.

## Source

```text
PowerSploit commit: d943001a7defb5e0d1657085a77a0e78609be58f
PowerView.ps1 SHA-256: 507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87
```

The selected functions were source-reviewed as read-only. Mutating functions in the same script were not invoked.

## Identity and telemetry gates

Direct WIN01 WinRM authentication succeeded as:

```text
SIMULATION\yassine.karimi
SID: S-1-5-21-2009282649-2561501988-1253369040-1129
Integrity: Medium
Administrator: False
```

Yassine could read LDAP RootDSE:

```text
DefaultNamingContext: DC=SIMULATION,DC=LOCAL
ConfigurationNamingContext: CN=Configuration,DC=SIMULATION,DC=LOCAL
```

Endpoint telemetry gates passed: Security 4688 command lines, PowerShell Script Block Logging, WazuhSvc, and Defender protections were enabled.

## First blocked attempt

The pinned script retrieval was attempted under Yassine. Defender blocked the PowerShell command before `PowerView.ps1` remained on disk:

```text
Threat: Trojan:PowerShell/Powersploit.G
Defender Operational records: 1230, 1231
PowerView.ps1 present afterward: False
PowerView functions executed: None
```

Security Event 4688 evidence:

```text
Record: 34415
Time: 2026-08-05T14:39:59.2956212Z
User: SIMULATION\yassine.karimi
Process: powershell.exe
Parent: wsmprovhost.exe
```

Wazuh indexed this under existing rule `100110`, level `10`. The operator confirmed it in Dashboard using:

```text
agent.id:"004" AND rule.id:"100110" AND data.win.system.eventRecordID:"34415"
```

Rule `100110` proved encoded PowerShell execution only; it did not identify PowerView.

## Defender telemetry gap and fix

WIN01 originally collected only Application, Security, System, and Sysmon Operational. Defender Operational was absent from the agent configuration and records `1230`/`1231` did not exist in manager archives.

The dedicated `workstation-sysmon` group received:

```text
Microsoft-Windows-Windows Defender/Operational
```

Endpoint `ossec.log` then confirmed:

```text
2026/08/05 15:48:11 wazuh-agent: INFO: (1951): Analyzing event log: 'Microsoft-Windows-Windows Defender/Operational'.
```

A single bounded replay produced fresh events:

```text
1116 / record 1235 — Trojan:PowerShell/Powersploit.G / Severe
1116 / record 1236 — same detection instance
1117 / record 1237 — action Remove
Threat ID: 2147725325
```

Manager archives received all three with exact decoded fields. Native Wazuh handling generated:

```text
62123 / level 12 / records 1235 and 1236 — Defender detection
62124 / level 3  / record 1237          — Defender remediation
```

Packaged descriptions omit the threat name and carry no MITRE mapping, but the alert level and exact decoded `win.eventdata.threat Name` field preserve high-confidence evidence.

## Final screenshot rerun

At the operator's request, the same pinned test was rerun once for a clean
Dashboard screenshot. Staging completed as Yassine and the downloaded file hash
matched the pinned value. The default execution policy first prevented import.
The retry changed only the current PowerShell process scope to `Bypass`; no user
or machine policy, Defender control, AMSI setting, exclusion, or allow action was
changed.

Defender then blocked PowerView at script import before any selected `Get-*`
function ran. Fresh endpoint and indexed evidence:

```text
Staging UTC: 2026-08-05T15:08:03.8759633Z
Identity: SIMULATION\yassine.karimi
SHA-256: 507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87
1116 / record 1243 — HackTool:PowerShell/InvKerber.B
1116 / record 1245 — HackTool:PowerShell/PowerView
Wazuh: rule 62123 / level 12
Indexed timestamp: 2026-08-05T15:08:58.251Z
```

The operator confirmed record `1245` in Dashboard and captured the screenshot:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1245"
```

This is stronger attribution than the first generic encoded-PowerShell alert.
Built-in rule `62123` is sufficient for alerting because the decoded event retains
the exact `HackTool:PowerShell/PowerView` threat name. No custom rule is required.

## Rejected custom-rule attempt

Candidate children `100494` and `100495` matched the dynamic Defender fields containing spaces. Local XML parsing and `/var/ossec/bin/wazuh-analysisd -t` passed. Archived replay decoded as generic JSON and could not validate the live `62123/62124` parent chain.

After deployment, Wazuh manager startup exceeded its systemd timeout. The candidate file was removed immediately, the manager returned to `active`, and WIN01 agent `004` returned `Active`. The unvalidated custom rules were removed from both manager and repository. Native `62123/62124` remain the proven baseline. No repeated rule iteration was performed.

## False-positive test

At `2026-08-05T14:56:26.8894905Z`, Yassine executed only:

```text
PowerView documentation reference only
```

Observed result:

```text
Matching Defender 1116/1117: 0
Matching Wazuh 62123/62124: 0
```

This confirms the native path depends on Defender malware classification, not a harmless textual reference.

## Cleanup and health

PowerView-specific cleanup passed:

```text
PowerViewLab directory: absent
PowerView.ps1: absent
WazuhLab-PowerView-Preflight task: absent
PowerView/PowerSploit processes: 0
WazuhSvc: Running
Defender platform: 4.18.26070.9
Real-time / behavior / IOAV / tamper protection: enabled
Wazuh manager: active
WIN01 agent 004: Active
```

BlueHammer artifacts, its exact threat allowance, one-shot task, and RDP-related retained controls were intentionally not touched per user direction.

## Limitation

Because Defender prevented script import, no PowerView function returned domain,
group, trust, or ACL data. Result remains `execution BLOCKED`, not successful
reconnaissance. Wazuh now has exact Defender attribution to
`HackTool:PowerShell/PowerView`; rename-resistant behavioral attribution to the
underlying LDAP discovery actions was not proven because those actions never ran.
