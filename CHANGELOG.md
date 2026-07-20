# Changelog

## Unreleased

### PowerShell

- Imported deployed `powershell-detection.xml` into version control.
- Live-validated PowerShell tests T01–T12 against Windows Security Event ID 4688.
- Added rules 100121–100123 and 100138–100139 for domain discovery, account discovery, registry modification, and Run/RunOnce persistence.
- Validated XML structure, duplicate IDs, Wazuh manager syntax, live alerts, false-positive tests, and cleanup.
- Added evidence report `tests/results/powershell_validation_2026-07-19.md`.

### Unix Shell

- Installed auditd and enabled real-user `execve`/`execveat` collection on the Linux agent.
- Added a tested audit dispatcher that correlates records and decodes hex EXECVE arguments into normalized JSON.
- Added agent-side audit, Wazuh localfile, plugin, and logrotate configuration under `agents/linux/`.
- Added and deployed `unix_shell_detection.xml` with rules 100200–100210 and 100220–100226.
- Covered shell execution, remote retrieval, download-execute, reverse shells, decode-execute, history clearing, shell-profile persistence, SSH keys, sudoers, cron, permission changes, temporary execution, credential-file access, dual-use network tools, and BusyBox/ash dispatch.
- Live-validated 20 positive tests and 8 false-positive tests.
- Added rule 100210 for BusyBox `sh`/`ash`; extended download-execute, decode-execute, reverse-shell, and temporary-execution patterns for BusyBox applets.
- Reduced generic network-utility rule 100209 from level 10 to level 6 after a benign netcat check proved the original severity excessive.
- Verified zero lost audit events, cleanup, service health, manager syntax, and deployed file ownership.
- Added evidence report `tests/results/unix_shell_validation_2026-07-19.md`.

### Windows Command Shell

- Added full `rules/cmd_detection.xml` with 23 hierarchical rules in collision-free range 100300–100344.
- Expanded domain-account, domain-group, domain-view, DC discovery, and direct SYSVOL/NETLOGON/administrative-share targeting coverage.
- Fixed single-command discovery matching for `whoami`, `hostname`, `ipconfig`, `systeminfo`, session, and network utilities.
- Split LSASS, SAM, and LSA Secrets detections for precise T1003 sub-technique mapping.
- Split PowerShell-parent execution from RunAs/UAC-parent execution.
- Split certutil encode and decode detections with separate severity and ATT&CK mappings.
- Validated XML structure, 23 unique IDs, internal references, 26 regexes, targeted escaped-command samples, and zero collisions with PowerShell/Unix rule files.
- Tightened rule 100311 for quoted and unquoted domain-group names and corrected its description.
- Reordered certutil decode/encode rules ahead of parent-only PowerShell and RunAs/UAC rules so command-specific detections win.
- Documented the Event 4688 limitation: direct tools launched from an already-open CMD require process-specific rules outside the cmd.exe hierarchy.
- Replaced the interactive malicious-command bench script with `tests/cmd_malicious_commands.txt`: 32 independent copy/paste commands, 5 false-positive tests, and cleanup commands.
- This change versions the candidate only; manager deployment and final live regression remain pending.
