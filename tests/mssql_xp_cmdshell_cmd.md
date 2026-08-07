# MSSQL `xp_cmdshell` detection validation

## Objective

Validate Microsoft SQL Server `xp_cmdshell` configuration telemetry and detect
actual OS-command execution using the live Windows process relationship:

```text
sqlservr.exe -> cmd.exe /c <command>
```

The execution rule is payload-independent: it must detect `whoami`, `hostname`,
a harmless marker, and controlled file operations without naming those commands.

## Preconditions

- Run on the authorized WIN01 SQL Express lab host.
- Wazuh agent `004` is Active.
- Security Event `4688` includes process command lines.
- SQL Server Application events are collected.
- The operator has an authorized SQL login with `sysadmin` privileges.
- Execute one case at a time and verify Wazuh before continuing.

Open an integrated-authentication SQL prompt locally:

```powershell
sqlcmd -S "WIN01\SQLEXPRESS" -E
```

## Enablement test

At the `sqlcmd` prompt:

```sql
EXEC sp_configure 'show advanced options',1;
RECONFIGURE;
EXEC sp_configure 'xp_cmdshell',1;
RECONFIGURE;
GO
```

Expected telemetry:

```text
Application Event 15457
Provider: MSSQL$SQLEXPRESS
Message: Configuration option 'xp_cmdshell' changed from 0 to 1
```

Expected rules:

```text
100539 / level 5  — xp_cmdshell configuration changed
100540 / level 12 — xp_cmdshell enabled from 0 to 1
```

## Positive execution test

```sql
EXEC xp_cmdshell 'echo XP_CMDSHELL_RULE_RETEST';
GO
```

Expected output:

```text
XP_CMDSHELL_RULE_RETEST
```

Expected process telemetry:

```text
ParentProcessName: ...\sqlservr.exe
NewProcessName:    ...\cmd.exe
CommandLine:       ...\cmd.exe /c echo XP_CMDSHELL_RULE_RETEST
SubjectUserName:   MSSQL$SQLEXPRESS
```

Expected alert:

```text
100541 / level 13 — SQL Server spawned cmd.exe with /c
MITRE: T1505.001, T1059.003
```

## Controlled impact test

This creates and reads a canary only in the SQL service temporary directory:

```sql
EXEC xp_cmdshell 'echo TEMP=%TEMP% & echo XP_CMDSHELL_WRITE_PROOF>"%TEMP%\xp_cmdshell_proof.txt" & type "%TEMP%\xp_cmdshell_proof.txt"';
GO
```

Expected output includes:

```text
XP_CMDSHELL_WRITE_PROOF
```

This proves shell execution plus bounded file-write/read impact without reading
real user data.

## False-positive controls

Normal SQL does not spawn `cmd.exe` from `sqlservr.exe` and must not match
`100541`:

```sql
SELECT @@SERVERNAME AS ServerName, DB_NAME() AS CurrentDatabase;
GO
```

An ordinary command shell launched by the interactive user also must not match
`100541` because its parent is not `sqlservr.exe`:

```powershell
cmd.exe /d /c "echo MSSQL_XP_CMDSHELL_NEGATIVE"
```

Native/general command-shell rules may still alert; that is expected. The strict
false-positive condition is absence of custom rule `100541` for those controls.

## Dashboard queries

All MSSQL alerts:

```text
agent.id:004 AND rule.id:(100539 OR 100540 OR 100541)
```

Execution only:

```text
agent.id:004 AND rule.id:100541
```

Validated generic marker record:

```text
agent.id:004 AND rule.id:100541 AND data.win.system.eventRecordID:(44020 OR 44022 OR 44077)
```

## Evidence checks

Inspect:

```text
data.win.system.eventID
data.win.system.eventRecordID
data.win.system.providerName
data.win.system.message
data.win.eventdata.parentProcessName
data.win.eventdata.newProcessName
data.win.eventdata.commandLine
data.win.eventdata.subjectUserName
```

Do not claim `xp_cmdshell` execution from `whoami.exe` alone. The discriminating
evidence is `sqlservr.exe -> cmd.exe /c ...`.

## Cleanup

After evidence capture:

```sql
EXEC xp_cmdshell 'del /q "%TEMP%\xp_cmdshell_proof.txt" 2>nul';
GO
EXEC sp_configure 'xp_cmdshell',0;
RECONFIGURE;
GO
EXIT
```

Cleanup is optional when the lab phase intentionally retains vulnerable state for
follow-on detection exercises. Record the chosen final state.
