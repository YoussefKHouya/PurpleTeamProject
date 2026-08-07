# MSSQL `xp_cmdshell` detection validation — 2026-08-07

## Verdict

```text
SQL Express installation/authentication: PASS
xp_cmdshell OS execution:              PASS
Rule 100541 live alert:                PASS
Rule payload independence:             PASS
Manager XML/parser validation:         PASS
Rules 100539/100540 fresh live alert:   PASS
Normal-SQL false-positive test:          PASS
Interactive-CMD false-positive test:    PASS
Indexer document confirmation:          PASS
```

All three MSSQL rules are live-proven. Fresh post-deployment disable and enable
events selected `100539` and `100540`; normal SQL and an interactive user-launched
CMD control did not select `100541`. OpenSearch contains the exact configuration
and execution alert documents.

## Environment

```text
Endpoint: WIN01 / Wazuh agent 004
SQL instance: WIN01\SQLEXPRESS
SQL service identity: NT SERVICE\MSSQL$SQLEXPRESS
Wazuh manager: 4.14.6
```

SQL TCP `1433` remained closed from Kali. WinRM TCP became reachable, but the
configured account was denied shell authorization, so SQL execution remained local
to WIN01. Kali was used only as the controlled management path to Wazuh. No firewall
or SQL network exposure was added.

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

The final post-deployment configuration test toggled `xp_cmdshell` from enabled to
disabled and back to enabled. It produced two fresh Application events:

```text
Record 5618: Event 15457 / rule 100539 / level 5
Message: Configuration option 'xp_cmdshell' changed from 1 to 0

Record 5619: Event 15457 / rule 100540 / level 12
Message: Configuration option 'xp_cmdshell' changed from 0 to 1
```

Both appeared in manager `alerts.json` and the
`wazuh-alerts-4.x-2026.08.07` OpenSearch index.

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
Rule 100539 fresh disable alert:      PASS / record 5618
Rule 100540 fresh enable alert:       PASS / record 5619
OpenSearch exact-document query:      PASS / 5 documents
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

Exact live-validated records:

```text
agent.id:004 AND ((rule.id:(100539 OR 100540) AND data.win.system.eventRecordID:(5618 OR 5619)) OR (rule.id:100541 AND data.win.system.eventRecordID:(44020 OR 44022 OR 44077)))
```

## False-positive boundary

Rule `100541` requires all of:

```text
Security 4688
parent basename sqlservr.exe
new process basename cmd.exe
command line containing /c
```

The final normal SQL query returned `WIN01\SQLEXPRESS` and database `master` without
creating a SQL Server child CMD event or selecting `100541`.

The interactive control ran as `WIN01\adam.wilson` and emitted marker
`MSSQL_XP_CMDSHELL_FP_FINAL_20260807`. Its Security 4688 record `44211` showed
`powershell.exe -> cmd.exe /d /c ...` and selected generic CMD rule `100339`, level
8—not MSSQL rule `100541`. Sysmon records `62295`/`62296` independently preserved
the CMD and `whoami.exe` process chain. This closes the previous ungraded control
with source telemetry present.

The operator command's trailing `Get-Date -AsUTC` failed because Windows PowerShell
5.1 does not support that parameter. It ran after the SQL toggle, normal query, and
CMD control, so it did not invalidate any test action or event.

Manager `alerts.json` and the OpenSearch alerts index both contain records `5618`,
`5619`, `44020`, `44022`, and `44077` under the expected custom rule IDs. Dashboard
UI rendering was not separately captured; index-document delivery is proven.

## Final state

`xp_cmdshell` ended enabled and is deliberately retained as isolated-lab posture for
follow-on exercises. The earlier temp-canary cleanup state was not rechecked; the
playbook retains the explicit cleanup command.
