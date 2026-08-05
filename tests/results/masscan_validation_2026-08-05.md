# Masscan validation — 2026-08-05

## Verdict

```text
Explicit WIN01 /32 scope:            PASS
Direct lab route/source:             PASS
Masscan availability/version:        PASS — 1.3.2
Raw scanner privilege:               PASS — interactive sudo prompt
Bounded full-port execution:         PASS
Independent packet evidence:         PASS
Endpoint/Wazuh scan detection:       PASS — pktmon watcher; Wazuh 100511 level 12
Single-port false-positive test:      PASS — watcher stayed quiet
Cleanup:                              PASS
Overall: EXECUTION AND DETECTION PASS
```

## Preflight and first attempt

Kali had a direct route from its dedicated lab interface to WIN01. `dumpcap`
carried `cap_net_admin,cap_net_raw=eip`; Masscan received raw-socket privilege
through an interactive sudo prompt. The password never entered argv, files, Git,
or evidence.

The first launch stopped before sending scan traffic:

```text
FAIL: ARP timed-out resolving MAC address for router eth1: "0.0.0.0"
Start: 2026-08-05T18:00:04.624642092Z
End:   2026-08-05T18:02:44.144571551Z
RC:    1
```

WIN01 was directly connected on a host-only interface, so no gateway IP existed.
The target MAC was recovered from the existing neighbor table and supplied through
`--router-mac`; it was not guessed. This retry changed routing mechanics only, not
scope, rate, ports, or target.

## Successful bounded trigger

```text
Start: 2026-08-05T18:03:12.347240800Z
End:   2026-08-05T18:14:12.564640737Z
Exit:  0
Scope: one WIN01 /32
Ports: TCP 1-65535
Rate:  100 packets/second
Wait:  5 seconds
Timeout: 15 minutes
```

Masscan reported five SYN-ACK-open ports:

```text
135/tcp
3389/tcp
5040/tcp
5985/tcp
7680/tcp
```

No service/version probes, NSE, UDP, OS detection, banners, discovery expansion,
decoys, fragmentation, subnet scan, or additional target was used.

## Independent packet proof

A simultaneous `dumpcap` capture was parsed with `tshark` before deletion:

```text
Capture size: 5,768,376 bytes
Outbound SYN packets: 65,535
Unique destination ports: 65,535
Unique destination hosts: 1
Masscan JSON open records: 5
```

The capture filter intentionally retained only source-Kali to destination-WIN01
TCP packets, so SYN-ACK replies were not counted by the PCAP parser. Masscan JSON
recorded the five SYN-ACK responses with TTL `128`.

## Detection result

WIN01's `Filtering Platform Packet Drop` and `Filtering Platform Connection` audit
subcategories were both `No Auditing`. During the positive window:

```text
Security 5152/5156/5157 events: 0
Wazuh scan/port-scan alerts: 0
Wazuh rule 203 queue-loss alerts: 0
WazuhSvc: Running
MpsSvc: Running
```

Half-open SYN traffic did not create process telemetry. No host network sensor or
Wazuh integration observed Kali traffic. This is an honest telemetry gap, not a
failed Masscan execution and not a detection PASS. Defender was intentionally
disabled by the operator for the wider batch; that state is unrelated to this
network-telemetry gap.

## False-positive test

At `2026-08-05T18:15:49.051845968Z`, a one-port Nmap SYN control targeted only
WIN01 TCP/445 with no retries. It completed in `0.32` seconds and returned
`filtered/no-response`.

```text
Control WFP events: 0
Control Wazuh scan alerts: 0
Control Wazuh rule 203 alerts: 0
```

No nonexistent scan detector was credited. The control proves the benign bounded
check did not create a false scan alert in the current telemetry configuration.

## Detection closure — target-side watcher

The original full-port window above correctly exposed a telemetry gap. A later
atomic closure phase deployed `agents/windows/tcp_scan_watcher.ps1`: a SYSTEM
watcher over Windows built-in `pktmon`, filtered to the exact Kali/WIN01 IP pair.
It correlated at least 20 distinct inbound SYN destination ports inside ten
seconds and emitted Windows Application events collected by Wazuh.

A representative Masscan `1-100` trigger produced:

```text
Application 1101 record: 4469
Distinct ports at alert: 47
Packets in window: 48
Total matching SYNs: 99
Application 1103 record: 4470
Wazuh: 100511 level 12, MITRE T1046
Recovery: 100513 level 5
```

The trigger wrapper timed out during Masscan wait handling, so endpoint pktmon
records—not wrapper exit status—proved packet emission. The original 65,535-port
PCAP remains authoritative full-execution proof.

A one-port TCP/445 control from `18:53:33.815816882Z` to
`18:53:34.197484247Z` produced zero Event 1101 and zero new watcher errors.
Watcher task, script, pktmon session/filter, and output files were removed after
validation. See `tests/results/tcp_scan_watcher_validation_2026-08-05.md`.

## Cleanup

Masscan, dumpcap, and control processes exited. JSON, PCAPNG, metadata, and capture
log files under `/tmp/t3-a6-*` were deleted. No endpoint file, service, account,
firewall rule, WFP policy, persistence artifact, or network configuration change
was created during the original scan. Temporary watcher artifacts from the later
detection-closure phase were also removed.
