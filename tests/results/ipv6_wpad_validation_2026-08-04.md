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

## Limitation

During final review, Wazuh reported agent `004` as disconnected and both known WIN01 WinRM paths were unavailable. Therefore no fresh live post-fix `100461` alert or final false-positive replay was proven. Historical raw telemetry proves the fields, while XML/syntax/hash checks prove the deployed rule artifact; this is not equivalent to live alert proof.

## Artifacts

```text
rules/ipv6_wpad_detection.xml
tests/ipv6_wpad_detection_cmd.md
tests/results/ipv6_wpad_validation_2026-08-04.md
```
