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

Versioned command playbook:

```text
tests/cmdshell_cmd.md
```

The playbook wraps each case in a fresh `cmd.exe /d /c` process so Event 4688
records the tested command on the `cmd.exe` event. It includes bounded positive
commands, false-positive controls, expected custom rule IDs, dashboard filters,
and cleanup.

PowerShell, Windows Command Shell, and Unix Shell Execution phases are complete
for roadmap progression. Current command playbooks are:

```text
tests/powershell_cmd.md
tests/cmdshell_cmd.md
tests/unixshell_cmd.md
```

## Completed phase: Kerberoasting

Technique: T1558.003 Kerberoasting. Lab has controlled SPN accounts.

Required DC telemetry remains:

```text
4769 — A Kerberos service ticket was requested
Audit subcategory: Kerberos Service Ticket Operations
Success: enabled
Failure: enabled
```

DC collection was live-verified on 2026-07-20. The Security channel is collected by the DC Wazuh agent, and the audit subcategory is enabled for Success and Failure.

A selective visibility gap was traced to built-in Wazuh rule `92651`: its level-0 IPv4 condition matched remote Event 4769 records without restricting itself to Event 4624. Loopback requests remained visible while IPv4-mapped remote requests were suppressed.

Versioned rescue rules:

```text
rules/kerberoasting_detection.xml
```

Deployed manager file:

```text
/var/ossec/etc/rules/kerberoasting_detection.xml
```

Rules:

```text
100400 — restore successful Event 4769 visibility, level 3
100401 — non-machine RC4 service ticket, level 9, T1558.003
```

Live targeted positive tests passed. DC record `19850` proved the remote RC4 path, DC record `19872` specifically proved controlled requester `yassine.karimi` requesting `svc_sql`, and DC record `19931` proved alternate controlled requester `omar.rahmani` requesting `svc_backup`. All used encryption `0x17`, status `0x0`, and matched Wazuh rule `100401` at level 9 with MITRE `T1558.003`. Extracted ticket material was deleted; no cracking or credential reuse occurred.

Evidence:

```text
tests/results/kerberoasting_validation_2026-07-20.md
```

Reproducible commands:

```text
tests/kerberoasting_cmd.md
```

Kerberoasting is **complete for roadmap progression**. Generic remote AES visibility is live-proven by DC record `19879` matching rule `100400` at level 3. Targeted RC4 detections are proven for `svc_sql` and `svc_backup` using controlled requesters Yassine and Omar. RC4 machine-account exclusion, wider benign RC4 sampling, and optional burst correlation remain documented non-blocking hardening work.

DC timezone is `Morocco Standard Time`. The DC is the domain PDC emulator and was found approximately four minutes slow while using `Local CMOS Clock`. W32Time was configured to use `time.windows.com,0x8` in manual client mode with the DC marked reliable; NTP reachability and successful synchronization were verified. A one-time correction aligned DC UTC with the synchronized Pi within approximately one second. NTDS, KDC, W32Time, and WazuhSvc remained running.

Wazuh manager clock skew was fixed again during AS-REP dashboard troubleshooting. Chrony had healthy sources and `chronyd` was active, but the system remained approximately 315 seconds slow after its startup-only `makestep 1.0 3` window had expired. `chronyc makestep` corrected the offset to `0.000000000 seconds slow`; timezone is now `Africa/Casablanca`. Chronyd, Wazuh manager, Filebeat, indexer, and dashboard remained active. Alerts were confirmed present in both `/var/ossec/logs/alerts/alerts.json` and index `wazuh-alerts-4.x-2026.07.21`.

Useful supporting events remain 4768, 4770, 4771, 4772, and 4773. Event 4769 is generated on the domain controller issuing the TGS, not on Kali or the Windows workstation.

Wazuh manager SSH access is available through the existing Pi → Tailscale → MINE → Wazuh VM route. No private route details or credentials are stored in version control.

## Completed phase: AS-REP Roasting

Technique T1558.004 AS-REP Roasting uses a dedicated controlled target account with Kerberos pre-authentication disabled; ordinary Yassine/Omar requester roles remain separate and recovered material is not chained.

Required DC telemetry gate before execution:

```text
4768 — A Kerberos authentication ticket (TGT) was requested
Audit subcategory: Kerberos Authentication Service
Success: enabled
Failure: enabled
```

Expected high-signal AS-REP fields include a successful Event 4768 for the controlled target with `PreAuthType=0`; ticket encryption type must be recorded. Verify DC Event 4768 reaches Wazuh before requesting AS-REP material. Capture exact target state, DC record ID, and Wazuh rule/level/MITRE mapping. Keep one dedicated controlled account pre-auth-disabled throughout the active lab phase; do not restore Kerberos pre-authentication unless the user explicitly closes the phase.

After AS-REP, add one shared post-roast credential-use layer correlating Kerberoasting/AS-REP alerts with later Events 4624, 4648, and 4672; offline cracking itself is not visible to Wazuh.

AS-REP core positive detection is now live-proven. Built-in Wazuh 4.14.6 left successful Event 4768 under rule `60103` at level 0 because rule `60106` excludes 4768. Custom rules were created and deployed:

```text
100410 / level 3 — successful Event 4768 visibility
100411 / level 10 — PreAuthType=0 AS-REP Roasting, T1558.004
100414 / level 12 — RC4 PreAuthType=0 AS-REP Roasting, T1558.004
100412 / level 12 — any WorkStation Event 4688 execution of `Rubeus.exe`
100413 / level 13 — renamed executable using the `asreproast` verb
```

Generic Rubeus detection was live-proven with `Rubeus.exe currentluid`.
Renamed AS-REP Roasting was live-proven with `updater.exe asreproast`; endpoint
rule `100413` preserves the technique when the binary name changes, while DC
rules `100411`/`100414` prove successful pre-authentication-free issuance.
Temporary copies and extracted material were deleted. Reproducible commands:

```text
tests/asrep_cmd.md
```

## Completed phase: LSASS Credential Dumping

Technique `T1003.001` is complete on WIN01. The controlled operator was
`WIN01\adam.wilson`, a local administrator. The ordinary domain account
`SIMULATION\yassine.karimi` was not used as the LSASS-dumping identity.

Telemetry:

```text
Security Event 4688 — process creation and command line
Sysmon Event 7      — image load
Sysmon Event 10     — process access to lsass.exe
Sysmon Event 11     — dump-like file creation
WIN01 Wazuh agent   — 004
```

Packaged Wazuh rules `61612` and `61613` keep Sysmon Events 10 and 11 at level
0, so custom children restore high-signal alerting:

```text
100420 / level 12 — known dump-capable process accessed LSASS
100421 / level 10 — dangerous LSASS access mask from unknown process
100423 / level 12 — LSASS/dump-like file creation
100424 / level 10 — rundll32 loaded comsvcs.dll
100425 / level 13 — comsvcs, ProcDump, or Mimikatz command line
100426 / level 0  — suppress erroneous 0x101000 substring match
100427 / level 0  — suppress exact trusted svchost/Defender benign readers
```

Live-positive coverage:

```text
comsvcs.dll MiniDump — command detected; Defender prevented dump
ProcDump              — execution, LSASS access, and dump creation detected
Renamed ProcDump      — command detected; Defender prevented access/dump
Mimikatz              — execution and LSASS access detected
Safe Event 10 probe   — suspicious access control detected
Safe Event 11 marker  — dump-file rule detected
```

Observed primary rules were `100425` for command execution, `100420` for
ProcDump LSASS access, `100423` for dump creation, and packaged rule `92900`
for Mimikatz access `0x1010`. Renaming ProcDump did not bypass command-line
coverage.

False-positive tuning is complete. Exact trusted paths suppress known WMI,
Windows service, Defender, and Wazuh-agent noise without basename-only
whitelisting; low-risk VirtualBox access remains outside dangerous-mask rules.
Live false-positive tests for `wmiprvse.exe` access `0x1410`,
query-only `0x101000`, `VBoxService.exe` access `0x1400`, and `svchost.exe`
access `0x1000` produced no visible alerts; high-risk access remained detected.

Versioned artifacts:

```text
rules/lsass_credential_dump_detection.xml
tests/lsass_cmd.md
tests/results/lsass_rule_tuning_2026-07-22.md
```

No LSASS dump, Mimikatz credential output, NTLM hash, password, or attack binary
is stored in Git. Verdict: **COMPLETE / PASS**.

## Collaboration terms

- Say “false-positive tests,” not “negative controls.”
- Keep evidence strict: exact rule ID, level, MITRE IDs, live alert, cleanup.
- Strong combinations must outrank atomic fallbacks.
- Never declare a rule finished from XML syntax alone; live positive and false-positive tests are required.
