# PsExec validation — 2026-08-05

## Verdict

```text
Privileged identity/ADMIN$ gate:      PASS
Temporary scoped SMB firewall gate:  PASS
Impacket service execution:          PASS
SYSTEM marker execution:             PASS
Endpoint process/service evidence:   PASS
Wazuh high-signal detection:         PASS
SMB-only false-positive test:         PASS
Cleanup/restoration:                 PASS
Defender prevention coverage:        NOT TESTED — operator left protection disabled
Overall: COMPLETE / PASS
```

## Atomic execution

Impacket `v0.14.0.dev0` authenticated through an in-memory prompt, found writable
`ADMIN$`, uploaded one randomized service binary, created and started one randomized
service, executed the bounded command, then stopped/removed the service and binary.
No password appeared in argv or evidence.

Current-run identifiers:

```text
Service: auAA
Service binary: %systemroot%\ZsPaFxsJ.exe
Marker: C:\ProgramData\WazuhLab\psexec_20260805T1750Z.txt
```

The controller wrapper returned `1` when the forced SSH PTY closed. This is not
used as the execution verdict. Target proof is authoritative:

```text
Marker created UTC: 2026-08-05T17:50:40.0728833Z
Identity: nt authority\system
Hostname: Win01
Service absent after Impacket cleanup: yes
Binary absent after Impacket cleanup: yes
```

## Endpoint evidence

```text
System 7045 record 5066:
  service auAA
  image %systemroot%\ZsPaFxsJ.exe
  account LocalSystem

Security 4688:
  35750 — services.exe -> ZsPaFxsJ.exe
  35751 — service binary -> cmd.exe bounded marker command
  35757 — service child execution

Sysmon Event 1:
  42334 — services.exe -> randomized service binary as SYSTEM
  42335 — service binary -> cmd.exe as SYSTEM
  42337 — whoami.exe
  42339 — hostname.exe
```

The randomized Impacket service executable crashed after command execution and
created Windows Error Reporting telemetry. Marker execution completed first; WER
artifacts were removed during cleanup.

## Wazuh evidence

Primary alert:

```text
Timestamp: 2026-08-05T17:50:38.988+0000
Agent: 004 / WIN01
Rule: 92650
Level: 12
Event: System 7045 / record 5066
MITRE: T1021.002, T1569.002
Description: service from Windows root path, likely dropped via admin share
```

Supporting alerts:

```text
67027 / level 3 — randomized service process
92052 / level 4 — cmd.exe from abnormal parent
100313 / level 8 — chained identity/host discovery marker command
60602 / level 9 — service binary application error
```

Native rule `92650` already provides high-signal PsExec-equivalent coverage. No
custom rule was required.

## False-positive test

At `2026-08-05T17:51:58.424951260Z`, the same account performed authenticated
SMB share listing only. `ADMIN$`, `C$`, and `IPC$` were listed. Results:

```text
New System 7045 events: 0
New Wazuh 92650 alerts: 0
Marker/service/binary: none
```

## Cleanup and health

```text
Marker: absent
Service auAA: absent
ZsPaFxsJ.exe: absent
Matching WER report directories: 0
Temporary scoped firewall rule: absent
TCP/445 from Kali: returned to timeout baseline
WazuhSvc: Running
MpsSvc: Running
Fresh Wazuh rule 203 alerts: 0
```

Defender real-time protection remained disabled by explicit operator choice. This
is retained as a limitation and not reported as cleanup health PASS for Defender.
