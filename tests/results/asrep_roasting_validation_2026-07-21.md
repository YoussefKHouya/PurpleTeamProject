# AS-REP Roasting Detection Validation — 2026-07-21

## Scope

Controlled AS-REP Roasting validation for MITRE ATT&CK T1558.004 against the dedicated lab account `hannah.reed`. No password cracking or credential reuse occurred. The account intentionally remains pre-authentication-disabled for continued lab work.

## Telemetry gate

- DC audit subcategory `Kerberos Authentication Service`: Success and Failure.
- Wazuh EventChannel collector includes the DC Security channel and does not exclude Event 4768.
- Controlled target: enabled, `DoesNotRequirePreAuth=True`, no SPN.
- Primary event: 4768.
- Expected fields: `Status=0x0`, `PreAuthType=0`, `TicketEncryptionType=0x17`.

## Initial detection gap

The DC generated successful Event 4768 records, but Wazuh produced no alert. Built-in Wazuh 4.14.6 rule analysis established:

```text
60000 — Windows eventchannel root
60001 — Security channel, level 0
60103 — Windows audit success, level 0
```

Built-in rule 60106 explicitly covers successful event IDs including 4769 but excludes 4768. Successful Event 4768 therefore stopped at rule 60103, level 0, and was invisible in the alert index.

## Custom rules

File:

```text
rules/asrep_roasting_detection.xml
```

Rules:

```text
100410 / level 3
Parent: 60103
Successful Event 4768 visibility

100411 / level 10
Parent: 100410
PreAuthType=0, non-machine/non-krbtgt target
MITRE T1558.004
```

Deployment checks:

- XML parse: PASS.
- Manager rule IDs were unused before deployment.
- Ownership/mode: `wazuh:wazuh 660`.
- `wazuh-analysisd -t`: PASS.
- Wazuh manager restart/status: PASS.
- DC agent reconnection verified before final request.

## Final live validation

One controlled `GetNPUsers.py` invocation requested AS-REP material for `hannah.reed`. The tool returned RC4 AS-REP marker 23. Extracted material was deleted immediately.

The invocation produced two successful DC Event 4768 records:

| Record | UTC | Target | Status | PreAuthType | Encryption | Source class |
|---:|---|---|---:|---:|---:|---|
| 20567 | 2026-07-21T11:18:10.5393771Z | hannah.reed | 0x0 | 0 | 0x17 | VirtualBox NAT |
| 20568 | 2026-07-21T11:18:10.5984457Z | hannah.reed | 0x0 | 0 | 0x17 | VirtualBox NAT |

Both exact records appeared in Wazuh:

```text
Rule ID: 100411
Level: 10
MITRE: T1558.004
```

Result: **PASS** — Event 4768 visibility and AS-REP Roasting detection are live-proven.

## WorkStation and operator attribution retest

WorkStation prerequisites were verified before the direct Rubeus test:

- Wazuh agent ID `002`: active.
- Security Event 4688 Process Creation auditing: Success.
- Process command-line capture: enabled.
- WorkStation Security channel: collected by Wazuh.
- WorkStation DC-facing address: `172.16.2.16`.
- WorkStation timezone: Morocco Standard Time.
- WorkStation time source: `DC01.SIMULATION.LOCAL`.

Custom endpoint rules:

```text
100412 / level 12
Parent: 67027
Any Event 4688 execution where the image ends in Rubeus.exe
No technique-specific MITRE mapping because Rubeus supports many Kerberos operations

100413 / level 13
Parent: 67027
Any Event 4688 command line containing a known Rubeus verb, regardless executable name
No technique-specific MITRE mapping because several verbs are multi-purpose
```

Generic Rubeus policy was live-validated with a non-roasting `currentluid` invocation:

```text
WorkStation record 14712
UTC: 2026-07-21T12:20:36.8503416Z
User: SIMULATION\yassine.karimi
Image: C:\Users\yassine.karimi\Rubeus.exe
Command: currentluid
Rule: 100412 / level 12
MITRE: none (correct for generic tool execution)
```

Result: **PASS** — every observed `Rubeus.exe` execution alerts at level 12 regardless subcommand.

Technique-specific rule `100413` was then changed to branch directly from generic Process Creation rule `67027`, matching the `asreproast`/`asreproasting` argument independently of executable name. Live renamed-binary validation:

```text
Temporary image: updater.exe
User: SIMULATION\yassine.karimi
Computer: Win01.SIMULATION.LOCAL
Arguments: asreproast targeting hannah.reed
Hash output: discarded
Temporary image: deleted

WorkStation record 14734
UTC: 2026-07-21T12:25:13.8280109Z
Image: updater.exe
Rule: 100413 / level 13 / T1558.004

DC record 20645
UTC: 2026-07-21T12:25:09.2863512Z
Target: hannah.reed
Source: 172.16.2.16
Rule: 100411 / level 10 / T1558.004
```

Result: **PASS** — renaming Rubeus does not bypass AS-REP Roasting detection while the `asreproast` argument remains visible in Event 4688.

The wider renamed-tool policy was then live-validated with the exact previously missed case:

```text
Temporary image: updater.exe
Command: currentluid
User: SIMULATION\yassine.karimi
Computer: Win01.SIMULATION.LOCAL
WorkStation record: 14754
Rule: 100413 / level 13
MITRE: none
Temporary image: deleted
```

Result: **PASS** — known Rubeus verbs are detected from Event 4688 command lines even when the executable is renamed. This argument-only policy is intentionally aggressive and may false-positive on unrelated executables using generic verbs such as `dump`, `hash`, `monitor`, or `renew`.

One fresh AS-REP command was executed as `SIMULATION\yassine.karimi` on `WIN01`; hash output was discarded in memory and not saved.

Exact correlated evidence:

```text
WorkStation record 14676
UTC: 2026-07-21T12:04:57.6289281Z
Computer: Win01.SIMULATION.LOCAL
User: SIMULATION\yassine.karimi
Image: C:\Users\yassine.karimi\rubeus.exe
Rule: 100412 / level 12 / T1558.004

DC record 20626
UTC: 2026-07-21T12:04:48.7289833Z
Target: hannah.reed
Source: 172.16.2.16
Rule: 100411 / level 10 / T1558.004
```

Result: **PASS** — operator, attack workstation, process, command, vulnerable target, and DC source are all evidenced. Wazuh agent ID `002` retains its pre-rename enrollment name `DESKTOP-CAAJENL`, while `win.system.computer` correctly reports `Win01.SIMULATION.LOCAL`.

## Clock and route state

- DC timezone: Morocco Standard Time.
- PDC W32Time source: `time.windows.com,0x8`.
- DC and Pi UTC aligned within approximately one second before final validation.
- Temporary Pi SSH tunnels and AS-REP runner removed.
- VirtualBox NAT loopback forwards remain available on MINE for the active lab route.

## Cleanup and retained lab state

- AS-REP material: deleted.
- Temporary runner: deleted.
- Temporary Pi tunnels: closed.
- Password cracking: not performed.
- Credential use/lateral movement: not performed.
- `hannah.reed` remains pre-authentication-disabled intentionally.
