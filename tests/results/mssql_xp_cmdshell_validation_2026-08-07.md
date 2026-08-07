# MSSQL `xp_cmdshell` detection validation — 2026-08-07

## Verdict

```text
SQL Express installation/authentication: PASS
xp_cmdshell OS execution:              PASS
Rule 100541 live alert:                PASS
Rule payload independence:             PASS
Manager XML/parser validation:         PASS
Rules 100539/100540 fresh live alert:   PENDING
Interactive false-positive telemetry:   UNGRADED — marker absent from archives
Dashboard/index document confirmation:  NOT RECORDED
```

The execution detection is complete and live-proven. Configuration enablement
rules use exact live Event `15457` fields captured before deployment, but have not
yet received a fresh post-deployment enablement event. Do not represent replay or
parser validation as a fresh endpoint alert.

## Environment

```text
Endpoint: WIN01 / Wazuh agent 004
SQL instance: WIN01\SQLEXPRESS
SQL service identity: NT SERVICE\MSSQL$SQLEXPRESS
Wazuh manager: 4.14.6
```

SQL TCP `1433` and WinRM `5985` were closed from Kali, so SQL execution remained
local to WIN01. Kali was used only as the controlled management path to Wazuh. No
firewall or SQL network exposure was added.

## Live telemetry

Enabling `xp_cmdshell` produced Windows Application telemetry before custom-rule
deployment:

```text
Event ID:       15457
Record:         5605
Provider:       MSSQL$SQLEXPRESS
System time:    2026-08-07T10:40:10.7963194Z
Message:        Configuration option 'xp_cmdshell' changed from 0 to 1.
Decoded data:   xp_cmdshell, 0, 1
```

Initial execution returned:

```text
NT SERVICE\MSSQL$SQLEXPRESS
```

The final payload-independent marker generated:

```text
Timestamp:      2026-08-07T11:13:40.916+0000
Event:          Security 4688
Record:         44020
Rule:           100541
Level:          13
Parent:         ...\MSSQL16.SQLEXPRESS\MSSQL\Binn\sqlservr.exe
Child:          C:\Windows\System32\cmd.exe
Command:        cmd.exe /c echo XP_CMDSHELL_RULE_RETEST
MITRE:          T1505.001, T1059.003
```

This proves detection does not depend on `whoami`, `hostname`, or a named attack
tool. It keys on the SQL Server process spawning the Windows command interpreter.

Two additional post-fix executions closed the sibling-selection and payload-impact
gates:

```text
Record 44022: rule 100541 / level 13
Command: cmd.exe /c echo TEMP=%TEMP% & echo XP_CMDSHELL_WRITE_PROOF>... & type ...

Record 44077: rule 100541 / level 13
Command: cmd.exe /c whoami
Child record 44079: native rule 67027 / whoami.exe
```

Before the parent-chain fix, the same `whoami` shape selected `100316` on records
`43763` and `43782`. Post-fix record `44077` proves `100541` now outranks that
competing discovery rule while remaining payload-independent.

## Rule engineering

Rules were added in:

```text
rules/mssql_xp_cmdshell_detection.xml
```

```text
100539 / level 5  — xp_cmdshell state-change visibility
100540 / level 12 — xp_cmdshell enabled from 0 to 1
100541 / level 13 — sqlservr.exe -> cmd.exe /c execution
```

The first live candidate inherited from native Security rule `67027`. Existing
repository rule `100316` won sibling selection for discovery commands, so `100541`
did not evaluate. The parent was corrected to the repository's normalized CMD base
rule `100300`. After redeployment and manager restart, record `44020` selected
`100541` at level 13.

## Validation gates

```text
Local XML parse:                     PASS
Duplicate custom rule IDs:           PASS
Manager wazuh-analysisd -t:          PASS
Manager restart via wazuh-control:   PASS
wazuh-analysisd/remoted/db/modulesd: RUNNING
WIN01 agent 004 after reconnect:      Active
```

Attempting to replay archived Event `5605` with `wazuh-logtest` decoded it as generic
JSON rather than through the live Windows Application parent `60600`. That replay
cannot validate child-rule traversal. The limitation is preserved instead of
claiming a synthetic pass.

## Dashboard query

```text
agent.id:004 AND rule.id:100541 AND data.win.system.eventRecordID:(44020 OR 44022 OR 44077)
```

All MSSQL layers:

```text
agent.id:004 AND rule.id:(100539 OR 100540 OR 100541)
```

## False-positive boundary

Rule `100541` requires all of:

```text
Security 4688
parent basename sqlservr.exe
new process basename cmd.exe
command line containing /c
```

Normal SQL queries do not create that process relationship. Interactive `cmd.exe`
execution has a different parent. A dedicated live negative should be rerun if the
rule is later broadened.

After deployment, the operator reported running
`MSSQL_XP_CMDSHELL_FALSE_POSITIVE`. Agent `004` was Active, but two bounded manager
searches found the marker zero times in both `archives.json` and `alerts.json`,
including a 120,000-line window. Because the source event was absent, this test is
not graded PASS or FAIL and no false-positive claim is made from it.

Manager `alerts.json` proves alert creation for the MSSQL records above. A matching
Dashboard/index document was not independently captured during this phase; the
Dashboard gate is therefore `NOT RECORDED`, not implied by the query text.

## Final state

The vulnerable SQL configuration and any controlled canary are retained unless the
operator explicitly performs the cleanup in `tests/mssql_xp_cmdshell_cmd.md`.
