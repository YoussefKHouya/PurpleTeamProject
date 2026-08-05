# PurpleTeamProject

Private purple-team project for Wazuh command and scripting interpreter detection engineering.

## Scope

- T1059.001 — PowerShell
- T1059.003 — Windows Command Shell
- T1059.004 — Unix Shell
- MITRE ATT&CK mapping
- Live positive/negative validation
- False-positive review and regression evidence
- Versioned diffs for rule modifications

## Rule-to-test mapping

Every versioned rule XML has one command playbook under `tests/`.

| Rule XML | Command playbook |
|---|---|
| `rules/cmd_detection.xml` | `tests/cmdshell_cmd.md` |
| `rules/powershell-detection.xml` | `tests/powershell_cmd.md` |
| `rules/unix_shell_detection.xml` | `tests/unixshell_cmd.md` |
| `rules/kerberoasting_detection.xml` | `tests/kerberoasting_cmd.md` |
| `rules/asrep_roasting_detection.xml` | `tests/asrep_cmd.md` |
| `rules/lsass_credential_dump_detection.xml` | `tests/lsass_cmd.md` |
| `rules/ntds_credential_dump_detection.xml` | `tests/ntds_credential_dump_cmd.md` |
| `rules/tcp_scan_detection.xml` | `tests/tcp_scan_watcher_cmd.md` |
| `rules/adpeas_detection.xml` | `tests/adpeas_cmd.md` |

PowerView, SharpView, and PowerSploit/PowerUp use the proven native Defender
rules `62123`/`62124`, so they have no custom-rule XML. adPEAS uses PowerShell
Operational telemetry plus custom semantic rule `100520`; Seatbelt stopped at
its source-build gate. Their telemetry configuration and playbooks are:

```text
agents/windows/workstation-sysmon-agent.conf
tests/powerview_cmd.md
tests/sharpview_cmd.md
tests/adpeas_cmd.md
tests/seatbelt_cmd.md
tests/powersploit_powerup_cmd.md
tests/masscan_cmd.md
tests/nmap_syn_cmd.md
tests/tcp_scan_watcher_cmd.md
tests/psexec_cmd.md
tests/winrm_cmd.md
tests/gpo_delegated_persistence_cmd.md
```

Each playbook contains prerequisites, bounded attack-trigger commands, expected
Wazuh rule IDs, local telemetry checks, dashboard filters, false-positive
controls where applicable, and cleanup.

Historical validation evidence remains under `tests/results/`; it is separate
from reproducible command playbooks.

## Current status

```text
PowerShell execution:       validated
Windows Command Shell:      validated
Unix Shell execution:       validated
Kerberoasting:              validated
AS-REP Roasting:            validated
LSASS credential dumping:   validated and tuned
NTDS IFM extraction:        validated; stdin limitation documented
PowerView reconnaissance:   detection validated; execution blocked by Defender
SharpView enumeration:      prevention validated; GUI-allowed execution pass, enumeration partial
adPEAS enumeration:         standard WinRM partial; CredSSP retest + LDAP + rule 100520 validated
Seatbelt host recon:        build blocked; no executable produced
PowerSploit PowerUp:        detection validated; execution blocked by Defender
Masscan full-port scan:     execution + packet proof + pktmon/Wazuh detection validated
Nmap SYN scan:              execution + packet proof + pktmon/Wazuh detection validated
PsExec remote execution:    validated as SYSTEM; Wazuh 92650 level 12
WinRM remote execution:     validated; Wazuh 100331 level 12
Delegated GPO persistence:  validated/rolled back; Wazuh 60229, endpoint Sysmon gap
```

## Workflow

1. Preserve deployed rules and create host-side backups.
2. Verify required telemetry before authoring detections.
3. Execute one controlled test at a time.
4. Capture actual host events and Wazuh alerts.
5. Record rule ID, level, MITRE IDs, and cleanup status.
6. Reproduce gaps before modifying rules.
7. Validate syntax and duplicate IDs locally.
8. Deploy with backup and run Wazuh configuration tests.
9. Restart services only after validation passes.
10. Live-retest positive cases and false-positive tests.
11. Commit reviewed rules, telemetry config, and evidence.

## Privacy

Do not commit passwords, tokens, private keys, private-workstation identifiers, or private access-path details. Local access configuration belongs under ignored `.local/` only.
