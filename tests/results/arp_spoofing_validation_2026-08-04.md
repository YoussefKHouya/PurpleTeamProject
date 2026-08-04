# ARP spoofing validation result — 2026-08-04

## Verdict

**PASS** — direct Layer-2 poisoning, victim-side watcher detection, Wazuh alerting, and restoration were live-proven.

## Topology

```text
Kali:  172.16.2.100 / eth2 / 08-00-27-D3-7C-3B
WIN01: 172.16.2.16 / 08-00-27-AE-0A-E5 / agent 004
Peer:  172.16.2.17 / 08-00-27-0C-FE-D8
```

## Live attack evidence

Bounded command:

```bash
sudo timeout 7 arpspoof -i eth2 -t 172.16.2.16 172.16.2.17
```

Observed transition:

```text
172.16.2.17 expected: 08-00-27-0C-FE-D8
172.16.2.17 poisoned: 08-00-27-D3-7C-3B
172.16.2.17 restored: 08-00-27-0C-FE-D8
```

## Wazuh evidence

```text
100491 / level 12 / T1557.002 — poisoning detected
Alert timestamp: 2026-08-04T14:48:20.517+0000
100493 / level 5 — approved mapping restored
Alert timestamp: 2026-08-04T14:48:20.523+0000
```

The correct native parent is `60600`, the informational Windows Application event rule. The watcher emits provider `WazuhArpWatcher` Event IDs 1000, 1001, and 1003.

## Cleanup

`arpspoof` sent corrective ARP replies on termination. WIN01 `Get-NetNeighbor` confirmed `172.16.2.17` mapped to `08-00-27-0C-FE-D8` and was reachable.

## Artifacts

```text
agents/windows/arp_neighbor_watcher.ps1
rules/arp_spoofing_detection.xml
tests/arp_spoofing_cmd.md
```
