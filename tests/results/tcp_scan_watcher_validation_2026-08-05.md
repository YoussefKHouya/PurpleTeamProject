# TCP scan watcher validation — 2026-08-05

## Verdict

```text
Target-side packet source:            PASS — Windows built-in pktmon
Exact source/target filter:           PASS
Behavior correlation:                 PASS — distinct destination ports / 10 s
Single-port false-positive control:   PASS
Masscan trigger:                      PASS
Nmap SYN trigger:                     PASS
Local Windows events:                 PASS
Wazuh delivery/rules:                 PASS
Atomic cleanup:                       PASS
Overall: PASS
```

## Design

WIN01 ran `agents/windows/tcp_scan_watcher.ps1` as a temporary SYSTEM scheduled
task. The watcher created one `pktmon` filter for TCP SYN traffic containing the
exact Kali/WIN01 address pair, then enforced inbound direction while parsing.
It alerted only after at least 20 distinct destination ports occurred inside a
10-second sliding window. Tool names, executable paths, fixed scan order, and
open-port results were not detection conditions.

Event contract:

```text
1100  watcher ready
1101  broad TCP scan detected
1102  watcher error
1103  activity quiet/reset
```

Wazuh rules:

```text
100510 level 3   watcher ready
100511 level 12  TCP scan, MITRE T1046
100512 level 7   watcher error
100513 level 5   quiet/reset
```

Rule XML passed `wazuh-analysisd -t`. Manager restarted successfully and agent
`004` returned Active before triggers.

## Backend correction

The first implementation used Windows Firewall DROP logging. A one-port TCP/445
probe appeared, but the representative Masscan test did not provide broad-port
records. Closed-port SYN handling was therefore not a complete packet source.
That backend was rejected rather than credited.

Built-in `pktmon` real-time capture was then validated. It observed exact inbound
SYN packets even when no firewall DROP record existed. Firewall logging was
restored to its original disabled state and its temporary log was removed before
the final validation.

## Deployment evidence

Final watcher SHA-256:

```text
a09d6498a25921538d0b9e204008aa9316a665e3d89ab4f18bf547e95a505456
```

Readiness:

```text
Task: WazuhTcpScanWatcher — Running as SYSTEM
Application event: 1100, record 4468
Sensor: pktmon
Filter: exact Kali/WIN01 IP pair, TCP SYN
WazuhSvc: Running
```

A prior startup failure emitted Event 1102 record `4467`: PowerShell treated the
harmless `pktmon stop` message `Packet Monitor is not running` as terminating
under `ErrorActionPreference=Stop`. Idempotent pre-clean was corrected through
`cmd.exe` with output suppressed. Final task started cleanly and produced no new
1102 events.

## False-positive control

```text
Start: 2026-08-05T18:53:33.815816882Z
End:   2026-08-05T18:53:34.197484247Z
Probe: Nmap SYN, WIN01 TCP/445 only, zero retries
```

After more than one complete correlation window:

```text
Event 1101 count: 0
New Event 1102 count: 0
Task state: Running
```

Repeated WinRM handshakes to TCP/5985 also stayed below the distinct-port
threshold. Control verdict: PASS.

## Masscan trigger

Representative watcher validation used only WIN01 TCP ports `1-100`, rate `50`,
wait `2`, explicit lab interface, and the already verified target MAC. The wrapper
hit its hard timeout while Masscan waited, so wrapper exit status was not treated
as execution proof. Target-side packet evidence proved 99 matching SYNs.

```text
Application 1101 record: 4469
Alert time:              2026-08-05T18:54:22.8802141Z
Distinct ports at alert: 47
Packets in window:       48
Total matching SYNs:     99
Application 1103 record: 4470
Wazuh rule:              100511, level 12, T1046
Wazuh recovery:          100513, level 5
```

Verdict: watcher detection PASS. Existing full 65,535-port Masscan packet proof
remains the authoritative scanner-execution record.

## Nmap trigger

```text
Start: 2026-08-05T18:55:54.396371750Z
End:   2026-08-05T18:56:35.281988906Z
Elapsed: 40.84 seconds
Scope: WIN01 only, top 1,000 TCP ports, max 50 pps, one retry
Open: 135, 3389, 5985
```

Detection:

```text
Application 1101 record: 4471
Alert time:              2026-08-05T18:56:04.9476382Z
Distinct ports at alert: 54
Packets in window:       104
Total matching SYNs:     2,017
Application 1103 record: 4472
Wazuh rule:              100511, level 12, T1046
Wazuh recovery:          100513, level 5
```

Verdict: execution and watcher detection PASS.

## Dashboard queries

Set time range to include `2026-08-05T18:54:15Z–18:57:10Z`:

```text
agent.id:004 AND rule.id:100511
agent.id:004 AND rule.id:100511 AND data.win.system.eventRecordID:(4469 OR 4471)
agent.id:004 AND rule.id:100513 AND data.win.system.eventRecordID:(4470 OR 4472)
```

If DQL rejects grouped values, run exact records separately:

```text
agent.id:004 AND data.win.system.eventRecordID:4469
agent.id:004 AND data.win.system.eventRecordID:4471
```

## Cleanup

The scheduled task, endpoint script, pktmon session, pktmon filter, output/error
files, fatal log, and temporary Event Log source were removed. Final proof:

```text
Task absent
Script absent
Pktmon not running
Pktmon filters: none
Pktmon processes: 0
Output/error files absent
WazuhSvc: Running
Wazuh manager: active
Agent 004: Active
```

The versioned watcher and Wazuh rule remain in the repository. The manager rule
remains deployed for reuse.
