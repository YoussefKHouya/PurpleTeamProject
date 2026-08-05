# Nmap SYN validation — 2026-08-05

## Verdict

```text
Explicit WIN01-only scope:           PASS
Direct lab route/source:             PASS
Nmap availability/version:           PASS — 7.98
Bounded -sS execution:               PASS
Independent packet evidence:         PASS
Endpoint/Wazuh scan detection:       PASS — pktmon watcher; Wazuh 100511 level 12
Single-port false-positive test:      PASS — watcher stayed quiet
Cleanup:                              PASS
Overall: EXECUTION AND DETECTION PASS
```

## Bounded positive trigger

Nmap received raw-socket privilege through an interactive sudo prompt. The password
never entered argv, files, Git, or evidence.

```text
Start: 2026-08-05T18:17:15.171625951Z
End:   2026-08-05T18:17:56.170454259Z
Elapsed reported by Nmap: 40.89 seconds
Exit: 0
Scope: WIN01 only
Scan: TCP SYN (-sS), host discovery disabled (-Pn), no DNS (-n)
Ports: Nmap top 1,000 TCP ports
Rate cap: 50 packets/second
Retries: 1
Timing: T3
Hard timeout: 10 minutes
```

Nmap reported:

```text
135/tcp  open      msrpc         syn-ack ttl 128
3389/tcp open      ms-wbt-server syn-ack ttl 128
5985/tcp open      wsman         syn-ack ttl 128
997 ports filtered/no-response
```

No service/version probes, NSE, OS detection, aggressive mode, UDP, decoys,
fragmentation, subnet expansion, or additional target was used.

## Independent packet proof

The simultaneous `dumpcap` capture was parsed with `tshark` before deletion:

```text
Capture size: 189,784 bytes
Outbound SYN packets: 2,027
Unique destination ports: 1,000
Unique destination hosts: 1
```

The SYN count exceeds 1,000 because Nmap used the permitted single retry for
filtered ports. Capture scope independently proves that traffic stayed on the sole
authorized target.

## Detection result

WIN01 had `No Auditing` for both Filtering Platform audit subcategories. During
the positive window:

```text
Security 5152/5156/5157 events: 0
Wazuh scan/port-scan alerts: 0
Wazuh rule 203 queue-loss alerts: 0
WazuhSvc: Running
MpsSvc: Running
```

Half-open SYN traffic produced no process telemetry. No host network sensor or
Wazuh network integration observed the traffic. Verdict is a telemetry gap—not a
scan failure and not detection PASS. Defender was intentionally disabled by the
operator for the wider batch; that does not explain or repair absent network
telemetry.

## False-positive test

At `2026-08-05T18:15:49.051845968Z`, Nmap performed a one-port SYN control against
WIN01 TCP/445 with zero retries. It ended at `2026-08-05T18:15:49.428702390Z`:

```text
Host: up by ARP response
445/tcp: filtered/no-response
Elapsed: 0.32 seconds
WFP events: 0
Wazuh scan alerts: 0
Wazuh rule 203 alerts: 0
```

No nonexistent scan detector was credited. The control proves a benign bounded
check caused no false scan alert under current telemetry.

## Detection closure — target-side watcher

The original execution window correctly documented the absence of a network
sensor. A later atomic closure phase deployed a SYSTEM watcher over Windows
built-in `pktmon`, filtered to the exact Kali/WIN01 address pair and correlated
by distinct inbound SYN destination ports.

The same bounded top-1,000-port Nmap profile reran successfully:

```text
Start: 2026-08-05T18:55:54.396371750Z
End: 2026-08-05T18:56:35.281988906Z
Elapsed: 40.84 seconds
Open: 135, 3389, 5985
Application 1101 record: 4471
Distinct ports at alert: 54
Packets in window: 104
Total matching SYNs: 2,017
Application 1103 record: 4472
Wazuh: 100511 level 12, MITRE T1046
Recovery: 100513 level 5
```

A one-port TCP/445 control produced zero Event 1101 and zero new watcher errors.
Watcher task, script, pktmon session/filter, and output files were removed. See
`tests/results/tcp_scan_watcher_validation_2026-08-05.md`.

## Cleanup

Nmap and dumpcap exited. `.nmap`, `.gnmap`, `.xml`, PCAPNG, metadata, and capture
log files under `/tmp/t3-a7-*` were deleted. No endpoint mutation, audit-policy
change, firewall rule, service, account, network change, or persistence artifact
was created during the original scan. Temporary watcher artifacts from the later
detection-closure phase were also removed.
