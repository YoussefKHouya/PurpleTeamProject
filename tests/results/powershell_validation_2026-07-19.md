# PowerShell Detection Validation — 2026-07-19

## Scope

Live validation of Wazuh `powershell-detection.xml` against Windows Security Event ID 4688 from the approved Windows lab workstation, using the approved domain test account.

## Environment

- Wazuh manager: v4.14.6
- Windows agent: v4.14.6
- Data source: Security Event ID 4688
- Parent process during WinRM tests: `wsmprovhost.exe`
- Evidence source: `/var/ossec/logs/alerts/alerts.json`
- Raw archives: not enabled (`archives.json` absent)

## Existing-rule live results

| Test | Behavior | Expected | Actual | Result |
|---|---|---:|---:|---|
| T01 | Baseline PowerShell | Generic only | 67027 / level 3 | PASS |
| T02 | Encoded command | 100110 | 100110 / level 10 | PASS |
| T03 | Remote-content indicator | 100113 | 100113 / level 10 | PASS |
| T04 | Download + IEX syntax | 100130 | 100130 / level 12 | PASS detection; payload quoting failed |
| T05 | Download + Import-Module | 100137 | 100137 / level 12 | PASS |
| T06 | Execution-policy bypass | 100111 | 100111 / level 8 | PASS |
| T07 | Hidden PowerShell | 100115 | 100115 / level 8 | PASS |
| T08 | Base64 + IEX | 100133 | 100133 / level 11 | PASS |
| T09 | NoProfile/NonInteractive + IEX | 100116 | 100116 / level 9 | PASS |
| T10 | Import-Module | 100120 | 100120 / level 9 | PASS |
| T11 | Character-code obfuscation | 100119 | 100119 / level 6 | PASS |
| T12 | Download + IEX + bypass + hidden | 100136 | 100136 / level 13 | PASS |

## Gaps found before tuning

### PowerShell domain discovery

Command line included:

```powershell
nltest.exe /dsgetdc:simulation.local; net.exe user /domain
```

Before tuning:

```text
Rule: 67027
Level: 3
MITRE: none
```

`nltest` successfully discovered the lab domain controller. `net user /domain` returned System error 5 because the WinRM session could not perform the required second-hop access.

### PowerShell registry modification

A dedicated HKCU marker key was created, modified, queried, and deleted.

Before tuning:

```text
Rule: 67027
Level: 3
MITRE: none
```

Cleanup succeeded; the marker key was absent after execution.

## Rules added

| Rule | Level | Purpose | MITRE |
|---:|---:|---|---|
| 100138 | 10 | Combined DC discovery + domain-account enumeration | T1059.001, T1018, T1087.002 |
| 100139 | 10 | Registry Run/RunOnce persistence modification | T1059.001, T1112, T1547.001 |
| 100121 | 9 | Domain-account discovery | T1059.001, T1087.002 |
| 100122 | 8 | Domain/forest/DC discovery | T1059.001, T1018, T1482 |
| 100123 | 8 | Registry modification | T1059.001, T1112 |

## Post-tuning live results

| Test | Before | After | Result |
|---|---:|---:|---|
| Combined DC + account discovery | 67027 / L3 | 100138 / L10 | PASS |
| Registry marker write/modify/delete | 67027 / L3 | 100123 / L8 | PASS |
| Temporary Run-key persistence | Not tested | 100139 / L10 | PASS |
| DC discovery only | Not tested | 100122 / L8 | PASS |
| Domain-user enumeration only | Not tested | 100121 / L9 | PASS detection; command returned access error |

## Negative controls

| Test | Expected | Actual | Result |
|---|---:|---:|---|
| Registry read only | Generic 67027 | 67027 / L3 | PASS |
| Local `net user` without `/domain` | Generic 67027 | 67027 / L3 | PASS |

New rules did not overmatch these controls.

## Deployment verification

- Local XML parse: PASS
- Duplicate rule IDs: none
- Wazuh `wazuh-analysisd -t`: exit 0
- Deployed owner/group: `wazuh:wazuh`
- Deployed mode: `660`
- Wazuh manager restart: PASS
- `wazuh-analysisd`: running
- `wazuh-remoted`: running
- Manager-side backup created before deployment

Agent 002 remained `Pending` after manager restart but continued sending keepalives and live Event 4688 alerts. Live post-tuning events were ingested successfully.

## Cleanup verification

```text
Temporary markers remaining: false
Registry test key present: false
Run-key test value present: false
Manager staging file: removed
```

## Verdict

PowerShell process-execution rules T01–T12 passed live validation. Domain discovery and registry-modification blind spots were reproduced, fixed, and live-retested. Negative controls remained generic and did not trigger the new custom rules.

PowerShell T1059.001 coverage is improved but not declared fully complete until remaining parent-process scenarios and broader false-positive sampling are validated.
