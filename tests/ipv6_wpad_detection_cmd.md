# IPv6/DHCPv6/DNS/WPAD — detection validation

## Objective

Validate Wazuh visibility for DHCPv6 client configuration activity and the controlled WPAD DNS lookup on WIN01.

## Telemetry prerequisites

- WIN01 Wazuh agent is Active.
- Wazuh manager retains raw events in `archives.json`.
- WIN01 collects `Microsoft-Windows-Dhcp-Client/Operational` and `Microsoft-Windows-DNS-Client/Operational`.
- Wazuh manager loads `ipv6_wpad_detection.xml`.

## Attack execution — Kali

Use only Kali `eth1`. Responder configuration must remain HTTP/WPAD-only: disable DNS so mitm6 can use port 53.

Terminal 1:

```bash
sudo responder -I eth1 -wFv
```

Terminal 2:

```bash
sudo mitm6 -i eth1 -d simulation.local
```

## Victim trigger — WIN01

Run locally on the single test victim after the two Kali processes show ready:

```powershell
ipconfig /renew6 "Ethernet 3"
Resolve-DnsName wpad.simulation.local
```

Expected during test:

```text
wpad.simulation.local resolves to Kali lab address
WIN01 requests /wpad.dat
```

## Bounded positive test

After recovery validation, repeat only DNS lookup to validate rule `100461`:

```powershell
Resolve-DnsName wpad.simulation.local
```

## Expected raw Wazuh fields

| Source | Provider | Event ID | Field |
|---|---|---:|---|
| DNS Client Operational | `Microsoft-Windows-DNS-Client` | `3008` | `win.eventdata.queryName=wpad.simulation.local` |
| DHCP Client Operational | `Microsoft-Windows-Dhcp-Client` | `50093` | `win.system.channel=Microsoft-Windows-Dhcp-Client/Operational` |

## Expected Wazuh evidence

| Rule | Level | Meaning |
|---:|---:|---|
| 100460 | 3 | DHCPv6 client configuration telemetry |
| 100461 | 10 | WIN01 queried `wpad.simulation.local` |

## False-positive test

```powershell
Resolve-DnsName dc01.simulation.local
```

Expected: DNS telemetry arrives; rule `100461` does not fire.
