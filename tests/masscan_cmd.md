# Bounded Masscan full-port playbook

## Scope

- Technique: `T1046` — Network Service Discovery
- Source: controlled Kali lab interface
- Target: WIN01 only, explicit `/32`
- Excluded: DC, Wazuh manager, Kali, OT host, and every subnet/range
- Tool observed: Masscan `1.3.2`

Use local ignored variables:

```bash
LAB_IF=<KALI_LAB_INTERFACE>
WIN01_IPV4=<WIN01_IPV4>
WIN01_MAC=$(ip neigh show "$WIN01_IPV4" dev "$LAB_IF" | awk '{print $5}')
```

## Mandatory gate

```bash
command -v masscan dumpcap
masscan --version
ip -o -4 address show dev "$LAB_IF"
ip route get "$WIN01_IPV4"
ping -c 1 -W 1 "$WIN01_IPV4" >/dev/null 2>&1 || true
ip neigh show "$WIN01_IPV4" dev "$LAB_IF"
test -n "$WIN01_MAC"
sudo -n true
```

Require direct lab route, expected source address, packet-capture capability, and
noninteractive raw-socket privilege. If sudo/capabilities are absent, classify
`BLOCKED`; never substitute a TCP-connect scan for Masscan.

WIN01 gate:

```powershell
auditpol /get /subcategory:"Filtering Platform Packet Drop"
auditpol /get /subcategory:"Filtering Platform Connection"
Get-Service WazuhSvc,MpsSvc
```

## Packet capture

```bash
timeout 15m dumpcap -q -i "$LAB_IF" \
  -f "src host $KALI_LAB_IPV4 and dst host $WIN01_IPV4 and tcp" \
  -w /tmp/t3-a6-masscan.pcapng
```

## Bounded trigger

```bash
sudo timeout 15m masscan "$WIN01_IPV4/32" \
  -p1-65535 --rate 100 --wait 5 \
  --interface "$LAB_IF" --router-mac "$WIN01_MAC" \
  -oJ /tmp/t3-a6-masscan.json
```

On directly connected/host-only NICs, Masscan may otherwise try resolving router
`0.0.0.0` and fail before sending. `--router-mac` must come from the neighbor table
for the sole scoped target; never guess it.

Safety: one `/32`, TCP only, 100 packets/second, 15-minute hard timeout, no
service probes, scripts, UDP, banners, discovery, evasion, or additional hosts.

## Evidence

Record tool version, interface, source/target uniqueness, UTC window, exit code,
packet count/SYN count, open ports, WIN01 WFP events `5152/5156/5157`, Wazuh
archives/alerts, and rule `203` queue-loss status.

Half-open SYN traffic may not create Sysmon Event 3. If WFP auditing is disabled
and no network sensor exists, report a telemetry gap rather than inventing an
endpoint detection.

## False-positive tests

Only after a scan rule exists:

```bash
sudo nmap -sS -Pn -n -p 445 --max-retries 0 "$WIN01_IPV4"
sudo nmap -sS -Pn -n -p 135,139,445,3389 --max-rate 1 --max-retries 0 "$WIN01_IPV4"
```

Single-port and slow four-port checks must not meet a scan threshold.

## Cleanup

Stop scanner/capture processes, remove `/tmp/t3-a6-*`, restore any temporary WFP
or firewall settings to the recorded baseline, and verify agents/services. No
endpoint mutation is expected.
