# IPv6/DHCPv6/DNS/WPAD validation result — 2026-08-04

## Verdict

**PHASE CLOSED WITH LIMITATION** — controlled IPv6/DNS/WPAD behavior, authentication capture, Windows telemetry, rule deployment, syntax, and cleanup were validated. A fresh post-fix `100461` alert could not be generated because WIN01 agent `004` was disconnected during final review. Phase closure was explicitly accepted despite this remaining live-alert gap.

## Controlled simulation

- Kali `mitm6` supplied scoped rogue DHCPv6/DNS behavior for `simulation.local`.
- Responder handled scoped HTTP/WPAD authentication capture.
- WIN01 performed DHCPv6 renewal, resolved `wpad.simulation.local`, and requested `wpad.dat`.
- Controlled NTLM challenge-response material was observed during the bounded test.

## Source telemetry

Historical WIN01 EventChannel evidence in Wazuh archives confirmed:

```text
Provider: Microsoft-Windows-DNS-Client
Channel:  Microsoft-Windows-DNS-Client/Operational
Event ID: 3020
Field:     win.eventdata.queryName=wpad.simulation.local
Agent:     004 / WIN01
```

DHCPv6 telemetry target:

```text
Provider: Microsoft-Windows-Dhcp-Client
Channel:  Microsoft-Windows-Dhcp-Client/Operational
Event ID: 50093
```

## Detection

```text
100460 / level 3  — DHCPv6 client configuration activity
100461 / level 10 — exact controlled WPAD DNS response
MITRE: T1557
```

Final rules inherit native Windows informational-event rule `60009`. Event ID `3020`, not `3008`, is used for the observed DNS response path.

## Deployment verification

```text
XML parse: PASS
Wazuh analysisd syntax: PASS
Wazuh manager: active
Local/deployed SHA-256:
6fa899467e22a22400fc02889e921304a21ec8166f375fc6f52872fff6a4cc68
```

## Dashboard query

```text
agent.id:004 AND (rule.id:100460 OR rule.id:100461)
```

## Cleanup and recovery

- Bounded `mitm6` and Responder processes were stopped.
- Windows DHCPv6/DNS state was returned to the normal lab configuration.
- No persistent rogue service was installed.

## Fresh live closure — 2026-09-01

The historical final-review limitation was closed after WIN01 agent `004` returned
Active and the deployed rule hash was reconciled with the repository.

```text
Positive alert
Timestamp:      2026-09-01T11:15:09.652+0000
Agent:          WIN01 / 004
Rule:           100461 / level 10
Event record ID: 340046
Query name:     wpad.SIMULATION.LOCAL
Manager path:   alerts.json
```

A bounded false-positive control generated the unique DNS query
`benign-dns-593f7414b173.simulation.local`. WIN01 produced fresh DNS Client
Operational archive records `341771` through `341783`, including Event `3020`.
No Wazuh alert was generated for that query, and no `100461` selection occurred.

This closes the live-positive and false-positive gap. Index/Dashboard evidence
remains a separate delivery check and is not implied by manager-side alert proof.

## Artifacts

```text
rules/ipv6_wpad_detection.xml
tests/ipv6_wpad_detection_cmd.md
tests/results/ipv6_wpad_validation_2026-08-04.md
```
