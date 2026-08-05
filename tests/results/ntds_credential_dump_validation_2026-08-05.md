# NTDS IFM validation result — 2026-08-05

## Verdict

**COMPLETE / PASS** for controlled NTDS IFM extraction, Security Event 4688
collection, custom Wazuh rule `100480`, indexed Dashboard delivery, cleanup, and
DC recovery validation.

A separate first attempt was prevented by Microsoft Defender. The successful
stdin-driven attempt and the prevention attempt are recorded independently.

## Scope

```text
Technique: T1003.003 — NTDS
Endpoint: DC01
Wazuh agent: 001
Utility: C:\Windows\System32\ntdsutil.exe
Method: Install From Media (IFM), subcommands delivered over stdin
Sensitive contents inspected/transferred: no
```

Rule source:

```text
rules/ntds_credential_dump_detection.xml
```

Command playbook:

```text
tests/ntds_credential_dump_cmd.md
```

## Attempt 1 — Defender prevention

Microsoft Defender blocked the first bounded attempt before IFM output was
created.

```text
Threat: Trojan:Win32/Commando.A!ml
Severity: Severe
Defender events: 1116, 1117
Action: Remove
Wazuh records: 29663, 29664
Native Wazuh rule: 67027 / level 3
Process: C:\Windows\System32\ntdsutil.exe
IFM artifact created: no
NTDS service after attempt: Running
```

Verdict for this attempt:

```text
Defender prevention: PASS
NTDS extraction: BLOCKED
Wazuh detection: PARTIAL / generic
```

## Attempt 2 — successful stdin-driven IFM

```text
Start: 2026-08-05 09:50:59 UTC
End: 2026-08-05 09:51:07 UTC
Exit code: 0
Output root: C:\ProgramData\WazuhLab\NTDS_IFM_20260805
NTDS service after execution: Running
```

Metadata-only output verification:

| Relative path | Size (bytes) |
|---|---:|
| `Active Directory\ntds.dit` | 33,554,432 |
| `Active Directory\ntds.jfm` | 16,384 |
| `registry\SECURITY` | 65,536 |
| `registry\SYSTEM` | 16,515,072 |

No database or hive contents were opened, parsed, transferred, hash-dumped, or
stored in Git.

## Native Wazuh coverage gap

Original successful-run telemetry:

```text
Record 29775 — PowerShell wrapper — rule 100110 / level 10
Record 29777 — ntdsutil.exe      — rule 67027 / level 3
Record 29779 — VSSVC.exe         — rule 67027 / level 3
```

Rule `67027` supplied generic process visibility without NTDS-specific severity
or ATT&CK context. Rule `100110` identified the encoded PowerShell launcher but
did not prove NTDS extraction.

The successful process Event 4688 command line contained only:

```text
"C:\Windows\System32\ntdsutil.exe"
```

IFM commands were absent because they were delivered over stdin. Command-line
matching alone therefore cannot identify the successful path.

## Final custom rules

```text
100480 / level 12 — sensitive ntdsutil.exe execution
100481 / level 14 — explicit visible IFM media-creation arguments
MITRE: T1003.003
```

Rule `100480` uses the live-proven `win.eventdata.newProcessName` field and native
parent `67027`. Rule `100481` is supplemental and applies only when IFM arguments
are visible in Event 4688.

Experimental VSS/ESENT correlation rule `100482` was removed. VSS process starts
are not reliable per extraction because VSS may already be running. ESENT/VSS
iterations did not produce a reliable end-to-end custom alert within the bounded
iteration budget.

## Final indexed validation

A fresh bounded IFM run generated the Dashboard evidence used for final proof:

```text
Timestamp: 2026-08-05T10:25:27.950Z
Agent: DC01 / 001
Rule: 100480
Level: 12
Event ID: 4688
Record ID: 29838
Process: C:\Windows\System32\ntdsutil.exe
MITRE: T1003.003 — NTDS
Dashboard filter: agent.id:"001" AND rule.id:"100480"
Dashboard window: 2026-08-05 10:25:10–10:25:40 UTC
```

The operator confirmed the Dashboard screenshot was captured. Manager-side alert
and indexed custom-rule proof were used because direct Dashboard API login
returned HTTP 401.

## Five-gate result

| Gate | Result | Evidence |
|---|---|---|
| Controlled simulation | PASS | IFM exit `0`; four expected files verified by metadata only |
| Telemetry collection | PASS | Security 4688 records for wrapper, `ntdsutil.exe`, and VSS |
| Custom alert | PASS | `100480` / level 12 / record `29838` |
| Dashboard/index | PASS | Indexed alert at `2026-08-05T10:25:27.950Z`; screenshot captured |
| Cleanup/recovery | PASS | IFM absent, zero shadows, services/security healthy, `dcdiag` exit `0` |

## Cleanup and recovery

Final verification after the screenshot run:

```text
IFM artifacts: absent
Temporary Defender test allowance: removed
Defender service: Running
Real-time protection: enabled
NTDS service: Running
VSS service: Stopped
Shadow-copy count: 0
Wazuh agent: Running
Wazuh manager: Running
dcdiag exit: 0
Secrets copied off DC01: no
```

## Limitations and false-positive boundary

- `100480` alerts on every `ntdsutil.exe` execution. Legitimate AD maintenance can
  therefore produce a level-12 alert.
- A standalone benign `ntdsutil.exe` false-positive test was not preserved during
  this phase. This remains explicit future hardening work.
- Event 4688 cannot distinguish stdin-delivered IFM commands from other bare
  `ntdsutil.exe` uses.
- Rule `100481` does not cover stdin or interactive command delivery.
- No reliable semantic VSS/ESENT correlation was proven; unvalidated rule
  `100482` was removed rather than retained.

These limitations do not invalidate the live-proven high-risk executable
coverage. They prevent claiming semantic proof of IFM from rule `100480` alone.
