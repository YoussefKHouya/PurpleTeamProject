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

### PowerShell

Core command behavior deployed and validated. Parent-process scenarios and wider benign-administration sampling remain.

Evidence:

- `tests/results/powershell_validation_2026-07-19.md`

### Unix Shell

Core T1059.004 phase deployed and live-validated:

- Installed auditd execution telemetry
- Added tested audit dispatcher for complete decoded command lines
- Added rules 100200–100210 and 100220–100226
- Ran 20 positive tests and 8 negative controls
- Added live-validated BusyBox `sh`/`ash`, wget-to-shell, reverse-shell, and temporary-execution coverage
- Tuned generic network-utility severity from level 10 to level 6
- Verified manager, agent, auditd, parser, cleanup, and zero lost audit events

Evidence and deployment details:

- `tests/results/unix_shell_validation_2026-07-19.md`
- `agents/linux/README.md`

### Next phase

- T1059.003 — Windows Command Shell/MS-DOS

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
10. Live-retest positive cases and negative controls.
11. Commit reviewed rules, telemetry config, and evidence.

## Privacy

Do not commit passwords, tokens, private keys, private-workstation identifiers, or private access-path details. Local access configuration belongs under ignored `.local/` only.
