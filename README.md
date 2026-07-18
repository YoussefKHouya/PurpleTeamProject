# PurpleTeamProject

Private purple-team project for Wazuh PowerShell detection engineering and validation.

## Scope

- Wazuh custom rules for suspicious PowerShell process execution
- MITRE ATT&CK mapping
- Harmless purple-team test events and commands
- Rule validation, false-positive review, and regression evidence
- Versioned diffs for every rule modification

## Current status

Initial review completed for `powershell_rules_v3.xml` supplied in chat.

The source XML has not yet been copied into this working tree. Add the actual `powershell_detection.xml` before modifying rules. No rule content is fabricated here.

## Initial review findings

- Rules detect post-process creation; they do not prevent execution.
- T1059.001, T1105, T1027, and T1564.003 mappings are broadly applicable.
- `svchost.exe` parent alone does not prove T1543.003 service creation.
- Validate sibling-rule matching behavior with `/var/ossec/bin/wazuh-logtest` on the deployed Wazuh version.
- Test Security 4688 fields against real agent events.

## Workflow

1. Preserve original XML.
2. Create dated/versioned change.
3. Validate XML syntax.
4. Test raw events with `wazuh-logtest`.
5. Verify generated alerts on the agent/manager.
6. Record actual rule IDs, levels, MITRE IDs, and false positives.
7. Commit only reviewed changes.
