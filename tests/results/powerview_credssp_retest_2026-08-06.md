# PowerView CredSSP reconnaissance retest — 2026-08-06

## Verdict

```text
Pinned source and SHA-256:              PASS
CredSSP Yassine/Kerberos/LDAP preflight: PASS
PowerView import and execution:          PASS
Broad read-only reconnaissance:          PASS (20/20 checks)
Defender block during retest:            NO
Wazuh native detection:                  PASS (91823 / level 14)
Dashboard confirmation:                  PASS
Target artifact/process cleanup:         PASS
CredSSP rollback:                        DEFERRED by operator until lab closure
Overall: PASS
```

This behavioral retest does not replace the original Defender prevention result. The original `HackTool:PowerShell/PowerView` detection under native Wazuh rule `62123` remains valid.

## Scope

```text
Repository: PowerShellMafia/PowerSploit
Commit: d943001a7defb5e0d1657085a77a0e78609be58f
Artifact: Recon/PowerView.ps1
SHA-256: 507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87
Host: WIN01
Identity: SIMULATION\yassine.karimi
Authentication: Kerberos through CredSSP
Integrity: Medium
Administrator: false
```

Credential bytes were supplied to the native Windows CredSSP client through process stdin. They did not enter argv, script text, evidence, or Git. Delegation remained restricted to `wsman/WIN01.SIMULATION.LOCAL`; no wildcard SPN was configured.

Mutating, credential-access, ticket-request, roasting, impersonation, and remote-action PowerView functions were excluded. Those behaviors require separate atomic scenarios and rollback evidence.

## Double-hop preflight

```text
Identity: SIMULATION\yassine.karimi
AuthenticationType: Kerberos
DefaultNamingContext: DC=SIMULATION,DC=LOCAL
Integrity: Medium
Administrator: false
```

## Execution

```text
Start: 2026-08-06T09:53:07.5880710Z
End:   2026-08-06T09:53:18.4345818Z
Verdict: EXECUTION_PASS
```

All selected read-only checks passed:

```text
Domain: SIMULATION.LOCAL
Forest: SIMULATION.LOCAL
Forest domains: SIMULATION.LOCAL
Domain controllers: DC01.SIMULATION.LOCAL
Users: 22
Groups: 62
Domain Admin members: Administrator
Computers: 5
OUs: 13
GPOs: 3
Trusts: 0
Sites: 1
Subnets: 0
Yassine ACL sample: 20 entries
Domain policy: returned
File servers: 0
DFS shares: 0
Managed security groups: 0
Foreign users: 0
Foreign group members: 0
```

No Defender `1116/1117` event matching PowerView/PowerSploit occurred in the retest window. Defender real-time, behavior, IOAV, and tamper protection were enabled at final verification.

## Wazuh evidence

```text
Agent: 004 / WIN01
Event: PowerShell Operational 4104
Record: 99403
Rule: 91823
Level: 14
Timestamp: 2026-08-06T09:53:11.449+0000
Description: PowerShell Invoke-Command remote execution
```

PowerShell record `99503` was also preserved in manager archives without a corresponding alert. No custom rule was added because native rule `91823` detected the actual run at level 14.

Dashboard confirmation was provided by the operator using:

```text
agent.id:"004" AND rule.id:"91823" AND data.win.system.eventRecordID:"99403"
```

No fresh queue-loss rule `203` occurred during the PowerView/PowerUp window.

## Cleanup and retained lab posture

```text
PowerViewLab: absent
PowerView processes: 0
C:\Windows\Temp\HermesCredSSPRunner.ps1: absent
WazuhSvc: Running
WIN01 agent 004: Active
Wazuh manager: active
Defender real-time/behavior/IOAV/tamper: enabled
CredSSP client/server: enabled
Delegation target: wsman/WIN01.SIMULATION.LOCAL only
```

CredSSP remains enabled by explicit operator direction until the broader lab phase closes. It must then be disabled and the exact fresh-credential delegation policy removed.
