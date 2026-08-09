Wazuh Dashboard queries — comprehensive validated attack catalog
================================================================

Use Wazuh Dashboard Discover / Threat Hunting with the `wazuh-alerts-*` data view.
Set the timestamp range in UTC and sort newest first. These examples use DQL/Lucene-
compatible field syntax. If grouped numeric syntax fails, quote agent/rule values.

Core agents used by this project
--------------------------------

- `001` — DC01
- `003` — Linux endpoint
- `004` — WIN01
- `006` — current OTDC01 enrollment; historical RBCD impact also exists under `005`

POWERSHELL — T1059.001
----------------------

agent.id:004 AND rule.id:(100110 OR 100111 OR 100112 OR 100113 OR 100114 OR 100115 OR 100116 OR 100117 OR 100118 OR 100119 OR 100120 OR 100121 OR 100122 OR 100123 OR 100130 OR 100131 OR 100132 OR 100133 OR 100134 OR 100135 OR 100136 OR 100137 OR 100138 OR 100139)

WINDOWS COMMAND SHELL — T1059.003
--------------------------------

agent.id:004 AND rule.id:(100310 OR 100311 OR 100312 OR 100313 OR 100314 OR 100315 OR 100316 OR 100330 OR 100331 OR 100332 OR 100333 OR 100334 OR 100335 OR 100336 OR 100337 OR 100338 OR 100339 OR 100340 OR 100341 OR 100342 OR 100343 OR 100344)

UNIX SHELL — T1059.004
----------------------

agent.id:003 AND rule.id:(100202 OR 100203 OR 100204 OR 100205 OR 100206 OR 100207 OR 100208 OR 100209 OR 100210 OR 100220 OR 100221 OR 100222 OR 100223 OR 100224 OR 100225 OR 100226)

KERBEROASTING — T1558.003
-------------------------

agent.id:001 AND rule.id:(100400 OR 100401)

High-confidence RC4 service ticket:

agent.id:001 AND rule.id:100401

AS-REP ROASTING — T1558.004
---------------------------

DC issuance:

agent.id:001 AND rule.id:(100410 OR 100411 OR 100414)

WIN01 Rubeus / renamed asreproast execution:

agent.id:004 AND rule.id:(100412 OR 100413)

Combined:

(rule.id:(100411 OR 100414) AND agent.id:001) OR (rule.id:(100412 OR 100413) AND agent.id:004)

Rule `100414` is versioned and deployed as the RC4 child of `100411`.

LSASS CREDENTIAL DUMPING — T1003.001
------------------------------------

agent.id:004 AND rule.id:(100420 OR 100421 OR 100423 OR 100424 OR 100425 OR 92900)

High-confidence command/access/file layers:

agent.id:004 AND rule.id:(100420 OR 100423 OR 100425)

RBCD — T1134.001 / T1550.003
----------------------------

All custom RBCD lifecycle alerts across DC and target enrollments:

rule.id:(100430 OR 100431 OR 100432 OR 100433 OR 100434 OR 100436)

Directory mutation and S4U2Proxy:

agent.id:001 AND rule.id:(100431 OR 100432 OR 100436)

Target-side delegated impact (current and historical enrollment IDs):

agent.id:(005 OR 006) AND rule.id:100434

SHADOW CREDENTIALS — T1098.005
------------------------------

agent.id:001 AND rule.id:(100451 OR 100452)

CERTIGHOST / AD CS — CVE-2026-54121
-----------------------------------

Rule-only query is intentional because CA enrollment identity may differ by snapshot:

rule.id:(100440 OR 100441 OR 100442 OR 100443 OR 100444 OR 100445)

High-confidence attempt, denial, and issuance:

rule.id:(100442 OR 100443 OR 100444)

Supporting CA network visibility only:

rule.id:100445

ARP SPOOFING — T1557.002
------------------------

agent.id:004 AND rule.id:(100490 OR 100491 OR 100493)

Poisoning and restoration only:

agent.id:004 AND rule.id:(100491 OR 100493)

ROGUE IPV6 / WPAD — T1557
--------------------------

agent.id:004 AND rule.id:(100460 OR 100461)

WPAD DNS lookup:

agent.id:004 AND rule.id:100461

WINPEAS ENUMERATION
-------------------

agent.id:004 AND rule.id:(100470 OR 100471)

LINPEAS ENUMERATION
-------------------

agent.id:003 AND (rule.id:100203 OR rule.id:100205 OR rule.id:100207 OR rule.id:100220 OR rule.id:203)

Rule `203` indicates queue loss and invalidates exhaustive telemetry claims.

LOLBINS
-------

agent.id:004 AND rule.id:(100473 OR 100474 OR 100475 OR 100476 OR 100477)

PROCESS INJECTION — T1055
-------------------------

agent.id:004 AND rule.id:100479

High-confidence LoadLibrary injection:

agent.id:004 AND rule.id:100479

NTDS IFM EXTRACTION — T1003.003
-------------------------------

agent.id:001 AND rule.id:(100480 OR 100481)

Live-proven process rule:

agent.id:001 AND rule.id:100480

MASSCAN + NMAP SYN SCANS
------------------------

agent.id:004 AND rule.id:(100510 OR 100511 OR 100512 OR 100513)

Detected scan bursts:

agent.id:004 AND rule.id:100511

Exact validated Masscan/Nmap records:

agent.id:004 AND rule.id:100511 AND data.win.system.eventRecordID:(4469 OR 4471)

Watcher recovery:

agent.id:004 AND rule.id:100513 AND data.win.system.eventRecordID:(4470 OR 4472)

POWERVIEW
---------

Defender prevention:

agent.id:004 AND rule.id:(62123 OR 62124)

Validated Defender record:

agent.id:004 AND rule.id:62123 AND data.win.system.eventRecordID:1245

CredSSP behavioral PowerShell evidence:

agent.id:004 AND rule.id:91823 AND data.win.system.eventRecordID:99403

SHARPVIEW
---------

Defender prevention:

agent.id:004 AND rule.id:62123

Custom named-tool and filename-independent behavior:

agent.id:004 AND rule.id:(100522 OR 100523)

ADPEAS
------

agent.id:004 AND rule.id:100520

Validated semantic record:

agent.id:004 AND rule.id:100520 AND data.win.system.eventRecordID:96942

POWERSPLoit POWERUP
-------------------

Defender prevention:

agent.id:004 AND rule.id:62123 AND data.win.system.eventRecordID:1284

Interactive comprehensive audit:

agent.id:004 AND rule.id:100521

SEATBELT
--------

agent.id:004 AND rule.id:(100542 OR 100524)

Bounded Host Recon classifier:

agent.id:004 AND rule.id:100524

PSEXEC
------

agent.id:004 AND rule.id:92650

Supporting service/process telemetry:

agent.id:004 AND data.win.system.eventID:(7045 OR 4688)

WINRM
-----

agent.id:004 AND rule.id:(100331 OR 100110)

GPO MODIFICATION / PERSISTENCE
------------------------------

agent.id:001 AND rule.id:(60229 OR 60230)

Delegated actor:

agent.id:001 AND rule.id:60229 AND data.win.eventdata.subjectUserName:"yassine.karimi"

Exact validated mutation records:

agent.id:001 AND rule.id:60229 AND data.win.system.eventRecordID:(30586 OR 30587 OR 30588)

CHISEL TUNNEL / SOCKS — T1572
-----------------------------

agent.id:004 AND rule.id:(100543 OR 100525 OR 100526)

Known pinned Chisel build only:

agent.id:004 AND rule.id:(100525 OR 100526)

Validated SOCKS record:

agent.id:004 AND rule.id:100526 AND data.win.system.eventRecordID:55794

HTTP FILE EXFILTRATION
----------------------

agent.id:004 AND rule.id:(100530 OR 100531 OR 100532 OR 100544 OR 100545)

Priority sensitive-source, rename-resistant, and staging layers:

agent.id:004 AND rule.id:(100531 OR 100544 OR 100545)

DNS FILE EXFILTRATION
---------------------

agent.id:004 AND rule.id:(100533 OR 100534 OR 100535 OR 100546)

Framed chunks, PowerShell behavior, and framing-independent burst:

agent.id:004 AND rule.id:(100534 OR 100535 OR 100546)

DEFENDER PREFERENCE TAMPERING — T1562.001
-----------------------------------------

agent.id:004 AND rule.id:100536

AMSI BYPASS ATTEMPT / PREVENTION — T1562.001
--------------------------------------------

agent.id:004 AND rule.id:(100537 OR 100538)

High-confidence blocked bypass attempt:

agent.id:004 AND rule.id:100538

MSSQL XP_CMDSHELL — T1505.001 / T1059.003
-----------------------------------------

All MSSQL configuration and execution alerts:

agent.id:004 AND rule.id:(100539 OR 100540 OR 100541)

xp_cmdshell configuration state change:

agent.id:004 AND rule.id:(100539 OR 100540)

Live-proven xp_cmdshell OS-command execution:

agent.id:004 AND rule.id:100541

Exact manager-validated marker, file-impact, and competing-payload records:

agent.id:004 AND rule.id:100541 AND data.win.system.eventRecordID:(44020 OR 44022 OR 44077)

Exact live-validated configuration transitions:

agent.id:004 AND rule.id:(100539 OR 100540) AND data.win.system.eventRecordID:(5618 OR 5619)

Interactive-CMD false-positive control (generic CMD rule, not MSSQL execution):

agent.id:004 AND rule.id:100339 AND data.win.system.eventRecordID:44211

Inspect these fields on rule `100541`:

- `data.win.eventdata.parentProcessName` — SQL Server `sqlservr.exe`
- `data.win.eventdata.newProcessName` — `cmd.exe`
- `data.win.eventdata.commandLine` — `/c <command>`
- `data.win.eventdata.subjectUserName` — SQL service identity

Validation note: rules `100539`, `100540`, and `100541` are live-proven. Fresh
post-deployment records `5618`/`5619` validate disable/enable transitions. Interactive
CMD record `44211` selected generic rule `100339` rather than `100541`. Manager
`alerts.json` and the OpenSearch alerts index contain the exact MSSQL custom-rule
documents; Dashboard UI rendering was not separately captured.

TROUBLESHOOTING EMPTY RESULTS
-----------------------------

1. Confirm the `wazuh-alerts-*` data view and widen the UTC range.
2. Try quoted string values, for example `agent.id:"004" AND rule.id:"100541"`.
3. Some templates expose `win.system.*`; others use `data.win.system.*`.
4. Manager `alerts.json` proves alert creation; index presence and Dashboard display
   are separate delivery gates.
5. Exact historical record IDs are evidence shortcuts, not portable detection logic.
