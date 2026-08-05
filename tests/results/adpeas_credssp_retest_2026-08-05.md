# adPEAS CredSSP retest — 2026-08-05

## Verdict

```text
Pinned source and SHA-256:                 PASS
CredSSP delegated Yassine session:         PASS
Kerberos identity on WIN01:                PASS
Authenticated LDAP to DC01:                PASS
Bounded adPEAS Domain module:              PASS
Actual-run Wazuh visibility (91823):       PASS
Custom adPEAS rule validation (100520):    PASS
Documentation-only negative control:       PASS
CredSSP and artifact cleanup:              PASS
Overall: PASS
```

This is a separate behavioral retest. It does not replace the original standard-WinRM `PARTIAL` result in `adpeas_validation_2026-08-05.md`.

## Scope and artifact

```text
Repository: 61106960/adPEAS
Commit: 1ea06f1d2dc92152b5aaeca6eacff24dd096d82e
Artifact: adPEAS_min.ps1
SHA-256: 7d7c1535ef4d33f24b738509af3962500453070ae94b0cbb23927c6e65d0a10b
Identity: SIMULATION\yassine.karimi
Host: WIN01
Mode: -UseWindowsAuth -OPSEC -Module Domain
```

No credential dumping, spraying, roasting, DCSync, RBCD, Shadow Credentials, ADCS abuse, BloodHound collection, or write-oriented AD operation ran.

Defender real-time, behavior-monitoring, and IOAV protections were already disabled for this explicitly approved lab behavior window. Therefore this retest makes no Defender-prevention claim. Tamper Protection remained enabled.

## Double-hop proof

CredSSP client delegation was restricted to `WIN01.SIMULATION.LOCAL`; no wildcard target was configured. CredSSP server role was temporary on WIN01. Credential bytes entered the native PowerShell client through stdin and never appeared in argv, scripts, repository files, or reports.

Preflight result:

```text
Identity: SIMULATION\yassine.karimi
AuthenticationType: Kerberos
Computer: WIN01
DefaultNamingContext: DC=SIMULATION,DC=LOCAL
LDAPSuccess: true
```

This proves CredSSP supplied a delegatable Yassine credential and removed the standard WinRM double-hop boundary.

## Actual adPEAS execution

Validated run window:

```text
Start: 2026-08-05T20:22:19.5581220Z
End:   2026-08-05T20:22:30.0455397Z
Output: 7,978 bytes / 131 lines
DomainMentioned: true
DC01Mentioned: true
```

Observed output included:

```text
Successfully connected to SIMULATION.LOCAL on DC01.SIMULATION.LOCAL
Authenticated as SIMULATION\yassine.karimi via LDAP
Found 1 domain controller
Analyzed LDAP signing/channel binding through SYSVOL GPO data
```

The module disconnected and removed itself from the runspace after completion.

## Wazuh evidence

PowerShell Operational event collection was added to the WIN01 workstation profile. The actual adPEAS run produced:

```text
Agent: 004 / WIN01
Event: PowerShell Operational 4104
Record: 96416
ScriptBlockId: ce025a10-60d3-4886-96fd-5fe4b2e10fa0
Native rule: 91823
Level: 14
Description: PowerShell Invoke-Command remote execution
```

Custom rule `100520` matches the bounded semantic invocation rather than the script filename:

```text
Invoke-adPEAS + -Domain + -UseWindowsAuth + -OPSEC + -Module Domain
Parent: 91823
Level: 14
MITRE: T1059.001, T1482
```

Because the actual event had already been processed before the final parent chain was corrected, the custom rule was validated with a live synthetic positive containing the exact invocation syntax but a stub function that performed no LDAP query and loaded no adPEAS module:

```text
Rule: 100520
Level: 14
Event record: 96942
ScriptBlockId: d361cf19-e86e-41f3-b9fa-4d7f89a306bf
SyntheticPositive: true
LDAPPerformed: false
```

A documentation-only control (`adPEAS documentation reference only`) did not trigger rule `100520`.

Dashboard filters:

```text
agent.id:"004" AND data.win.system.eventRecordID:"96416"
agent.id:"004" AND rule.id:"100520" AND data.win.system.eventRecordID:"96942"
```

## Cleanup

Verified after testing:

```text
WIN01 client CredSSP: false / registry 0
WIN01 server CredSSP: false / registry 0
AllowFreshCredentials target policy: absent
ADPeasLab staging/output directory: absent
Kali CredSSP venv and runner: absent
WazuhSvc: Running
Wazuh manager: active
WIN01 agent 004: Active
```

PowerShell Operational collection and custom rule `100520` remain deployed as intended detection coverage.
