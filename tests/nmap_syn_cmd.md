# Bounded Nmap SYN playbook

## Scope

- Technique: `T1046` — Network Service Discovery
- Source: controlled Kali lab interface
- Target: WIN01 only
- Excluded: DC, Wazuh manager, Kali, OT host, and every subnet/range
- Tool observed: Nmap `7.98`

Use ignored local variables:

```bash
LAB_IF=<KALI_LAB_INTERFACE>
WIN01_IPV4=<WIN01_IPV4>
```

## Mandatory gate

```bash
command -v nmap dumpcap
nmap --version
ip -o -4 address show dev "$LAB_IF"
ip route get "$WIN01_IPV4"
sudo -n true
```

A true `-sS` scan requires raw-socket privilege. If unavailable, classify
`BLOCKED`; do not silently downgrade to `-sT`.

## Packet capture

```bash
timeout 10m dumpcap -q -i "$LAB_IF" \
  -f "src host $KALI_LAB_IPV4 and dst host $WIN01_IPV4 and tcp" \
  -w /tmp/t3-a7-nmap-syn.pcapng
```

## Bounded trigger

```bash
sudo timeout 10m nmap \
  -sS -Pn -n --top-ports 1000 \
  --max-rate 50 --max-retries 1 \
  -T3 --reason \
  -oA /tmp/t3-a7-nmap-syn \
  "$WIN01_IPV4"
```

No `-sV`, `-O`, `-A`, NSE, UDP, decoys, fragmentation, subnet discovery, or
evasion options.

## Evidence

Record version, route, UTC window, exit status, exact selected ports, packet/SYN
counts, target uniqueness, Nmap result, WFP events, Wazuh archives/alerts, and
rule `203` state. Do not use Sysmon Event 3 as guaranteed half-open SYN evidence.

## False-positive tests

```bash
sudo nmap -sS -Pn -n -p 445 --max-retries 0 "$WIN01_IPV4"
sudo nmap -sS -Pn -n -p 135,139,445,3389 --max-rate 1 --max-retries 0 "$WIN01_IPV4"
```

## Cleanup

Terminate scanner/capture, remove `/tmp/t3-a7-*`, restore temporary audit/firewall
changes exactly, and verify WIN01/Wazuh health.
