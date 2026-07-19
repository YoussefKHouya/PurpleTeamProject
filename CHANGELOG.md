# Changelog

## Unreleased

- Imported deployed `powershell-detection.xml` into version control.
- Live-validated PowerShell tests T01–T12 against Windows Security Event ID 4688.
- Added rule 100138 for combined DC discovery and domain-account enumeration.
- Added rule 100139 for Registry Run/RunOnce persistence modification.
- Added rule 100121 for PowerShell domain-account discovery.
- Added rule 100122 for PowerShell domain/forest/DC discovery.
- Added rule 100123 for PowerShell registry modification.
- Validated XML structure, duplicate IDs, Wazuh manager syntax, live alerts, negative controls, and cleanup.
- Added evidence report `tests/results/powershell_validation_2026-07-19.md`.
