# Changelog

## Unreleased

### PowerShell

- Imported deployed `powershell-detection.xml` into version control.
- Live-validated PowerShell tests T01–T12 against Windows Security Event ID 4688.
- Added rules 100121–100123 and 100138–100139 for domain discovery, account discovery, registry modification, and Run/RunOnce persistence.
- Validated XML structure, duplicate IDs, Wazuh manager syntax, live alerts, negative controls, and cleanup.
- Added evidence report `tests/results/powershell_validation_2026-07-19.md`.

### Unix Shell

- Installed auditd and enabled real-user `execve`/`execveat` collection on the Linux agent.
- Added a tested audit dispatcher that correlates records and decodes hex EXECVE arguments into normalized JSON.
- Added agent-side audit, Wazuh localfile, plugin, and logrotate configuration under `agents/linux/`.
- Added and deployed `unix_shell_detection.xml` with rules 100200–100209 and 100220–100226.
- Covered shell execution, remote retrieval, download-execute, reverse shells, decode-execute, history clearing, shell-profile persistence, SSH keys, sudoers, cron, permission changes, temporary execution, credential-file access, and dual-use network tools.
- Live-validated 15 positive tests and 5 negative controls.
- Reduced generic network-utility rule 100209 from level 10 to level 6 after a benign netcat check proved the original severity excessive.
- Verified zero lost audit events, cleanup, service health, manager syntax, and deployed file ownership.
- Added evidence report `tests/results/unix_shell_validation_2026-07-19.md`.
