# ARP spoofing — WIN01 watcher validation

## Detection components

```text
agents/windows/arp_neighbor_watcher.ps1
rules/arp_spoofing_detection.xml
```

WIN01 scheduled task `WazuhArpNeighborWatcher` runs as SYSTEM and writes provider `WazuhArpWatcher` events to the Windows Application log. The Wazuh agent already collects that channel.

Approved mapping:

```text
172.16.2.17 -> 08-00-27-0C-FE-D8
```

## Trigger from Kali

Interface and participants must be verified before execution:

```text
Kali:  172.16.2.100 / eth2
WIN01: 172.16.2.16
Peer:  172.16.2.17
```

Bounded one-way poison window:

```bash
sudo timeout 7 arpspoof -i eth2 -t 172.16.2.16 172.16.2.17
```

Alternative bounded bidirectional test:

```bash
sudo timeout 8 ettercap -T -q -i eth2 -M arp:remote /172.16.2.16// /172.16.2.17//
```

`arpspoof` restores the legitimate mapping when the timeout sends termination. Verify restoration rather than trusting cleanup text alone.

## Expected evidence

```text
100490 / level 3  — watcher baseline
100491 / level 12 — watched peer remapped, T1557.002
100493 / level 5  — approved mapping restored
```

Dashboard filter:

```text
agent.id:004 AND (rule.id:100491 OR rule.id:100493)
```

## Cleanup verification

On WIN01:

```powershell
Get-NetNeighbor -InterfaceAlias Ethernet -AddressFamily IPv4 -IPAddress 172.16.2.17 |
  Select-Object IPAddress,LinkLayerAddress,State
```

Expected restored MAC: `08-00-27-0C-FE-D8`.
