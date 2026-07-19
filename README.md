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

## Current status

PowerShell phase active.

Completed:

- Imported deployed `powershell-detection.xml`
- Validated XML and existing T01–T12 live test matrix
- Reproduced missing domain-discovery and registry-modification coverage
- Added rules 100121–100123 and 100138–100139
- Validated new rules with live Event 4688 alerts
- Ran negative controls
- Verified cleanup and manager health

Evidence:

- `tests/results/powershell_validation_2026-07-19.md`

Remaining before declaring T1059.001 complete:

- Suspicious-parent scenarios
- Service-parent scenario
- Wider benign-administration false-positive sample
- Final regression pass

## Workflow

1. Preserve deployed XML and manager-side backup.
2. Execute one controlled test at a time.
3. Capture actual Event 4688 and Wazuh alert evidence.
4. Record rule ID, level, MITRE IDs, and cleanup status.
5. Reproduce gaps before modifying rules.
6. Validate XML and duplicate IDs locally.
7. Deploy with backup and run `wazuh-analysisd -t`.
8. Restart manager only after validation passes.
9. Live-retest positive cases and negative controls.
10. Commit reviewed rules and evidence.

## Privacy

Do not commit passwords, tokens, private keys, private-workstation identifiers, or private access-path details. Local access configuration belongs under ignored `.local/` only.
