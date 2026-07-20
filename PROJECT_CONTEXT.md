# Project Context

Durable handoff for future sessions. Read this file, the linked evidence, and Git history before asking the user to repeat prior work.

## Repository

```text
/home/pi/PurpleTeamProject
```

Secrets, credentials, tunnel settings, and private access details exist only in:

```text
.local/access.env
```

That path is mode 600 and Git-ignored. Never commit or quote its private-workstation values.

## Wazuh rules

### PowerShell — T1059.001

Deployed manager file:

```text
/var/ossec/etc/rules/powershell-detection.xml
```

Versioned source:

```text
rules/powershell-detection.xml
```

Core execution behavior, domain/DC discovery, domain-account discovery, registry modification, and Run/RunOnce persistence were live-tested. Parent-process scenarios and wider benign-administration false-positive sampling remain before final closure.

Evidence:

```text
tests/results/powershell_validation_2026-07-19.md
```

### Unix Shell — T1059.004

Deployed manager file:

```text
/var/ossec/etc/rules/unix_shell_detection.xml
```

Versioned source:

```text
rules/unix_shell_detection.xml
```

Core phase is operational. Rules cover shell execution, retrieval, download-execute, reverse shells, decode-execute, history clearing, profile/SSH-key/sudoers/cron persistence, permission changes, `/tmp` execution, shadow access, network tools, BusyBox, and `ash`.

BusyBox rule:

```text
100210 — BusyBox sh/ash execution, level 5
```

Current validation total:

```text
20 positive tests passed
8 false-positive tests passed
```

Evidence:

```text
tests/results/unix_shell_validation_2026-07-19.md
```

## Linux telemetry architecture

Linux Wazuh agent uses auditd `execve`/`execveat` rules tagged `wazuh_shell_exec`.

Auditd hex-encodes shell payload arguments. Wazuh 4.14.6 omitted those encoded arguments, so a tested dispatcher normalizes them into readable JSON:

```text
/usr/local/sbin/wazuh-audit-exec-json
/var/log/wazuh-audit-exec.json
```

Versioned agent files:

```text
agents/linux/
```

Expected health:

```text
auditd active
wazuh-agent active
normalizer process active
audit lost=0
```

## Windows Command Shell phase

T1059.003 preflight is underway. A prior draft was partially live-tested, but the current fixed candidate has only static validation and was not deployed by this change.

Current rule source:

```text
rules/cmd_detection.xml
```

It contains 23 rules in collision-free range 100300–100344. Domain/DC discovery, single-command discovery, credential mappings, parent mappings, and certutil encode/decode handling were corrected. Certutil rules precede generic parent-only rules. Direct tool execution from an already-open CMD remains outside this cmd.exe hierarchy and requires process-specific Event 4688 rules.

Sanitized runner source and instructions:

```text
tests/windows_command_shell_runner.ps1
tests/windows_command_shell_run_instructions.txt
```

Validated copies were placed on the access workstation Desktop:

```text
Invoke-WazuhMSDOSTests.ps1
RUN-MSDOS-TESTS.txt
```

The runner uses interactive credentials, targets the approved Wazuh Windows agent through WinRM, pauses before every case, writes unique UTC markers, creates a Desktop transcript, and performs cleanup verification.

Next step: user runs the script from an elevated PowerShell window. Execute one case at a time and stop after each marker so raw Event 4688 and Wazuh behavior can be captured before rules are authored.

## Collaboration terms

- Say “false-positive tests,” not “negative controls.”
- Keep evidence strict: exact rule ID, level, MITRE IDs, live alert, cleanup.
- Strong combinations must outrank atomic fallbacks.
- Never declare a rule finished from XML syntax alone; live positive and false-positive tests are required.
