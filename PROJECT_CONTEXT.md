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

The shared post-roast credential-use correlation layer is explicitly deferred. Its future design may correlate Kerberoasting/AS-REP exposure with later Events 4624, 4648, and 4672 using a persistent exposed-account watchlist rather than a short time window; offline cracking itself is not visible to Wazuh. Do not resume this layer unless the user requests it.

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

## Completed RBCD, Shadow Credentials, and CertiGhost validation

Active Directory ACL, Kerberos, and AD CS abuse validation completed in this order:

```text
1. Resource-Based Constrained Delegation (RBCD) — COMPLETE / PASS
2. Shadow Credentials — COMPLETE / PASS; add and Certipy restoration/deletion telemetry captured
3. CertiGhost (CVE-2026-54121) — detection and issuance-success path COMPLETE / PASS
4. Optional later follow-up: DCSync
```

Prepared RBCD target:

```text
Host: OTDC01
Role: SIMULATION.LOCAL member server
Address: 192.168.56.112
OS: Windows Server 2022 Standard Evaluation
File Server feature: installed
SMB service: running
Controlled share: \\OTDC01\RBCD-Target$
Share path: C:\FileServerData\RBCD-Target
Access: BUILTIN\Administrators and SYSTEM only
Computer object: CN=OTDC01,CN=Computers,DC=SIMULATION,DC=LOCAL
Secure channel: healthy
```

The target exposes valid `HOST`, `RestrictedKrbHost`, and `WSMAN` computer SPNs,
and real access to the encrypted administrative SMB share is verified. The Wazuh
agent is installed on OTDC01 from the official Wazuh MSI `4.14.6-1` at:

```text
C:\Tools\Wazuh\wazuh-agent-4.14.6-1.msi
SHA-256: BC1412D6CFD6D82BA8D5D5EC22ECFC80D85990228ADEAC40B809B3B46E745351
Authenticode: Valid, Wazuh, Inc
Installed agent version: v4.14.6
Service: WazuhSvc, Running, Automatic
Configured manager/enrollment server: 192.168.56.110
Configured agent name: OTDC01
```

OTDC01 is currently enrolled with the Wazuh manager as agent `006` and is
Active. Historical target-side RBCD impact alerts were generated under agent
`005`; the agent was re-enrolled after correcting an eight-hour future clock and
the resulting stale future keepalive. The controlled principal
`SIMULATION\sofia.bennett` retains one direct, non-inherited `GenericWrite` allow
ACE on the OTDC01 computer object. No `GenericAll`, privileged group membership,
or password change was added. The exact RBCD attribute SACL remains present.

### RBCD validation completed — 2026-07-23

Final verdict:

```text
Exploitation: PASS
Wazuh native detection: PARTIAL
Custom rules: PASS
False-positive tests: PASS after tuning
Cleanup: PASS
Overall: COMPLETE / PASS
```

Live custom-rule evidence:

```text
4741 / DC record 22312 / rule 100430 level 8
  RBCDCLIENT$ created by sofia.bennett via MachineAccountQuota
5136 / DC record 22320 / rule 100431 level 12
  RBCD attribute value added on OTDC01$ by sofia.bennett
4769 / DC record 22351 / rule 100400 level 3
  S4U2Self for RBCDCLIENT$
4769 / DC record 22352 / rule 100432 level 10
  S4U2Proxy to OTDC01$ with transmitted service
4624 / OTDC01 record 4986 / rule 100434 level 12
  delegated Kerberos network logon as domain RID-500 Administrator
5136 / DC record 22481 / rule 100436 level 6
  final RBCD attribute flush / Value Deleted
```

The protected-share baseline and post-cleanup checks returned
`STATUS_ACCESS_DENIED`; the delegated Administrator CIFS ticket read the
controlled file during exploitation.

False-positive results:

```text
22453 — unrelated description 5136 -> native 60229 only
22458 — ordinary Kerberos 4769 -> visibility 100400 only
4992  — ordinary Sofia Kerberos 4624 -> visibility 100433 only
22470 — Sofia quota machine canary -> 100430 level 8
22477 — Administrator provisioning canary -> native 60121 only
```

Rule `100430` was tuned to require `SeMachineAccountPrivilege`, eliminating the
confirmed legitimate Domain Administrator provisioning false positive. Cleanup
was changed from Impacket `remove`, which rewrites an empty security descriptor,
to `flush`, which leaves the attribute absent. Rule `100431` now describes the
exact observed behavior: an RBCD attribute value was added.

Final cleanup was verified:

```text
msDS-AllowedToActOnBehalfOfOtherIdentity: absent
RBCDCLIENT$ and all canary computer objects: absent
Temporary machine passwords and ccache files: removed
Post-cleanup protected-share read as Sofia: STATUS_ACCESS_DENIED
DC01 agent 001 and OTDC01 agent 006: Active
```

Final local/deployed rule SHA-256:

```text
81a0cc800601459fc12f631335c9959bbb107549566b3fa353ec733447d0723e
```

Authoritative artifacts:

```text
rules/rbcd_detection.xml
tests/RBCD_cmd.md
tests/results/rbcd_validation_2026-07-23.md
```

No passwords, generated machine secrets, Kerberos tickets, hashes, or private
routing details are stored in Git.

Future RBCD reruns should begin with a read-only prerequisite and telemetry gate. Record the
controlled principal that can modify the target computer, the target computer,
MachineAccountQuota/computer-account state, delegation attribute state, and
reachable service. Primary evidence candidates are:

```text
4741 — computer account creation, when used
5136 — msDS-AllowedToActOnBehalfOfOtherIdentity modification
4769 — S4U/service-ticket activity
4624 — resulting authentication
```

## Shadow Credentials validation — 2026-07-29

Technique: `T1098.005` Device Registration (Shadow Credentials). The validated
command is `certipy shadow auto`; it added a controlled Key Credential, obtained
a TGT through PKINIT, and restored the target's original Key Credentials.

Telemetry gate and evidence:

```text
DC Security auditing: Event ID 5136
Target Success SACL: msDS-KeyCredentialLink / WriteProperty
100451 / level 15: 5136 KeyCredential value added (%%14674)
100452 / level 5:  5136 KeyCredential value restored/deleted (%%14675)
```

The deployed Wazuh rule inherits native `60229` for Security Event 5136. The
positive test produced both custom alerts: the Key Credential add and Certipy
`shadow auto` restoration/deletion. Certipy restored the AD attribute and
generated credential-cache artifacts were removed.

Verdict: **COMPLETE / PASS**. A legitimate device-registration false-positive
test remains optional hardening work, not a completion gate for this controlled
attack-and-cleanup validation.

Authoritative artifacts:

```text
rules/shadow_credentials_detection.xml
tests/shadowCredentials_cmd.md
```

## Completed validation: Rogue IPv6/DNS/WPAD capture

The controlled lab scenario used Kali `mitm6` on the dedicated Layer-2 interface to provide scoped rogue IPv6/DHCPv6 DNS behavior for `simulation.local`, with WIN01 as the victim. Responder supplied scoped HTTP/WPAD handling. The completed simulation produced DHCPv6 renewal, `wpad.simulation.local` resolution activity, a `wpad.dat` request, and controlled NTLM challenge-response capture. Attack processes were bounded and Windows network state was restored afterward.

Wazuh archives confirmed WIN01 DNS Client Operational Event `3020` with `win.eventdata.queryName=wpad.simulation.local`. Final rules use native Windows informational parent `60009`: `100460` records DHCPv6 client configuration Event `50093`, while `100461` raises a level-10 alert for the exact controlled WPAD response and maps to MITRE ATT&CK `T1557`. XML parsing, Wazuh syntax validation, manager health, and deployed/local SHA-256 equality passed.

Phase closure carries one explicit limitation: WIN01 agent `004` was disconnected during final review, so a fresh post-fix `100461` alert and final false-positive replay were not live-proven. Historical raw telemetry and the deployed rule artifact are preserved without misrepresenting this as fresh Dashboard proof.

Artifacts:

```text
rules/ipv6_wpad_detection.xml
tests/ipv6_wpad_detection_cmd.md
tests/results/ipv6_wpad_validation_2026-08-04.md
```

## CertiGhost validation — CVE-2026-54121

CertiGhost detection was first validated on 2026-07-27 through the blocked
AD CS request path. A later controlled run with `omar.rahmani` validated the
issuance-success path and PKINIT workflow.

Live evidence:

```text
CA Security 4886: CertificateTemplate:Machine + cdc:<IPv4> + rmd:DC01.SIMULATION.LOCAL
Wazuh 100442 / level 15: IP-literal cdc CertiGhost attempt
CA Security 4888: policy denial 0x800706ba
Wazuh 100443 / level 10: denied CertiGhost request
CA Security 4887: certificate issued after cdc/rmd request
Wazuh 100444 / level 15: CertiGhost probable issuance
CA Sysmon 3: certsrv.exe non-loopback callback
Wazuh 100445 / level 12: AD CS callback connection
PoC: PKINIT and credential-cache indicators present; exit 0
```

Detection coverage is defined in `rules/certighost_detection.xml` and
`tests/certighost_cmd.md`:

```text
100442 — IP-literal cdc chase request
100443 — AD CS denied CertiGhost request
100444 — AD CS certificate issuance after cdc/rmd request
100445 — certsrv.exe non-loopback callback connection
```

Verdict: **DETECTION COMPLETE / PASS**. Both denied-request and issued-certificate
branches were observed live. Generated current-run `GHOST*$` objects were removed
and absence was verified; no recent `.pfx` or `.ccache` artifact remained.

For all phases: execute one atomic test at a time, pause for dashboard
confirmation after each attack command, create custom Wazuh rules only for a
live-proven detection gap, run false-positive tests, restore modified AD
attributes during cleanup unless the user explicitly keeps the lab condition,
and retain no tickets, certificates, private keys, hashes, or credentials in
Git.

DCSync remains a later candidate, not the immediate next phase. If selected,
prepare a dedicated controlled principal with replication rights and validate
Directory Service Access auditing plus Event 4662 before execution.

## Internship report conventions

The French academic internship report is intended for both the school and
recruiters. Its working LaTeX source is `~/S4/main.tex`. Preserve the original
`main.tex` cover-page form: two logos at the top, the large blue subject box
containing level, academic year, and internship dates, followed by author,
supervisor, and cycle fields.

The report must follow an academic progression:

```text
general concept -> security problem -> methodology -> technical work
-> evidence and results -> discussion and limits
```

The conceptual chapter introduces ideas before the technical chapters use
them. Keep treatment proportional across completed phases and avoid recency
bias: LSASS must not receive disproportionate conceptual detail merely because
it was the most recently discussed phase. Later revisions may expand the other
techniques from their validated XML rules, command playbooks, and executed
evidence, but only when the user explicitly requests that expansion.

Keep the report analytical rather than turning its main body into an attack
playbook. Place commands, configurations, raw rule excerpts, and detailed
operational evidence in annexes. Explain results and design reasoning in the
main chapters.

Report privacy requirements are strict:

- Never mention Pi, MINE, bridge hosts, Tailscale, Ligolo, private routes, or
  private infrastructure identifiers.
- Never include credentials, password hashes, Kerberos material, LSASS output,
  secrets, or private access details.
- Use clearly labelled placeholders for missing official logos and attack
  screenshots; never fabricate an image or claim that a screenshot exists.
- When the user asks why a report section exists, explain the reasoning only.
  Do not edit the report unless the user explicitly requests a change.

Current completed technical families available as report sources are
PowerShell, Windows Command Shell, Unix Shell, Kerberoasting, AS-REP Roasting,
LSASS Credential Dumping, RBCD, Shadow Credentials, CertiGhost, WinPEAS,
LinPEAS, LOLBins, process injection, and ARP spoofing. Their
versioned rules, one-to-one command playbooks, and validation reports remain the
authoritative technical sources.

## Completed validation: WinPEAS and LinPEAS

### WinPEAS — Windows local enumeration

WinPEAS was executed as the controlled low-privilege WIN01 user. Initial direct
execution from the user Downloads directory was live-detected; a renamed copy
(`a.exe`) then validated the behavioral coverage. Temporary test output was
removed after execution.

Versioned files:

```text
rules/winpeas_detection.xml
tests/winpeas_cmd.md
tests/results/winpeas_validation_2026-08-03.md
```

Deployed manager file:

```text
/var/ossec/etc/rules/winpeas_detection.xml
```

Live-proven rules:

```text
100470 / level 10 — direct known WinPEAS executable execution
100471 / level 10 — executable from Downloads, AppData, or Temp spawns a
                    discovery child (whoami, systeminfo, tasklist, schtasks,
                    ipconfig, net, netsh, wmic, or reg)
```

Rule `100470` is a high-confidence known-tool indicator and is expected to miss
a renamed executable. Rule `100471` is the rename-resistant layer: it fired for
`Downloads\\a.exe` spawning `systeminfo.exe`; `netsh.exe` was added after live
telemetry showed WinPEAS also queried wireless profiles. Do not add filename
masquerade special cases. The attempted multi-event correlation rule `100472`
was removed because actual WinPEAS telemetry produced only two matching
children, more than two minutes apart; it was not evidence-backed.

### LinPEAS — Linux local enumeration

LinPEAS was executed on Linux agent `003` as the controlled low-privilege user.
The bounded run produced 1,288 lines / 101,270 bytes. Download script and output
were stored temporarily under `/tmp` and removed after the run.

No LinPEAS-specific detection rule is required. Existing generic Unix-shell
rules caught the full rename-resistant chain:

```text
100203 / level 7  — remote content retrieval
100205 / level 7  — executable permission added
100207 / level 8  — script executed from temporary directory
100220 / level 12 — downloaded content passed to a shell for execution
```

Manager `alerts.json` contained the Linux agent alerts. LinPEAS also produced
fresh rule `203` queue-full events, so execution and the observed generic
detection chain passed, but exhaustive telemetry integrity remains constrained.
Do not call the run evidence-clean until a later rerun has no fresh rule `203`.
Use `tests/linpeas_cmd.md` and
`tests/results/linpeas_validation_2026-08-04.md` as the operational record.
LinPEAS exposed false-positive noise in rule `100226`: read-only
cron enumeration (`cat`, `ls`, `grep`, `sed`) was initially classified as cron
persistence. Rule `100226` was tightened and redeployed to match cron write,
removal, and permission-change semantics rather than read-only enumeration. Its
manager syntax validation and reload passed. Live false-positive and controlled
positive validation remain required before declaring that individual rule final.

## Completed validation: LOLBins

Controlled local tests on WIN01 used only signed Windows binaries and harmless
temporary local files. CertUtil encode/decode, MSHTA, Regsvr32 scriptlet proxy,
and Rundll32 `LaunchINFSection` behavior all generated live custom alerts:

```text
100473 / level 8  — CertUtil decode
100474 / level 6  — CertUtil encode
100475 / level 8  — MSHTA execution
100476 / level 10 — Regsvr32 scriptlet proxy
100477 / level 10 — Rundll32 proxy execution
```

Versioned sources:

```text
rules/lolbins_detection.xml
tests/lolbin_cmd.md
tests/results/lolbins_validation_2026-08-04.md
```

Verdict: **PASS**. Temporary HTA, SCT, INF, encoded, decoded, and marker files
were removed. No remote payload was used.

## Completed validation: Process injection

The controlled script injected the path of signed local `version.dll` into a
temporary Notepad process and invoked `LoadLibraryW` through
`CreateRemoteThread`. It created no callback or persistence and closed/freed
resources before terminating Notepad.

Correct live Wazuh chain:

```text
60000 -> 60004 -> 61600 -> 61610 -> 100478 -> 100479
```

The final live alert was `100479` / level 12 at
`2026-08-04T12:56:43.894+0000` on WIN01 agent `004`. Archive JSON replay is
not equivalent to the live EventChannel chain.

Versioned sources:

```text
rules/process_injection_detection.xml
tests/process_injection_cmd.md
tests/process_injection_event8.ps1
tests/results/process_injection_validation_2026-08-04.md
```

Verdict: **PASS** for trigger, Sysmon Event 8, manager alert, delivery path, and
cleanup.

## Completed validation: ARP spoofing

A bounded one-way ARP poison on the direct `172.16.2.0/24` Layer-2 segment
remapped watched peer `172.16.2.17` from approved MAC
`08-00-27-0C-FE-D8` to Kali MAC `08-00-27-D3-7C-3B`. WIN01 watcher
`WazuhArpNeighborWatcher` emitted native Windows Application events through
provider `WazuhArpWatcher`; Wazuh uses native parent `60600`.

Live alerts:

```text
100491 / level 12 / T1557.002 — poisoning detected
2026-08-04T14:48:20.517+0000
100493 / level 5 — approved mapping restored
2026-08-04T14:48:20.523+0000
```

Versioned sources:

```text
agents/windows/arp_neighbor_watcher.ps1
rules/arp_spoofing_detection.xml
tests/arp_spoofing_cmd.md
tests/results/arp_spoofing_validation_2026-08-04.md
```

Verdict: **PASS** for direct-L2 simulation, watcher collection, live Wazuh
alerting, and verified restoration.

## Completed validation: NTDS IFM extraction

Technique `T1003.003` was completed on DC01 using built-in `ntdsutil.exe` Install
From Media. Commands were delivered over stdin; the successful Security Event
4688 therefore contained only the executable path and omitted IFM subcommands.
No NTDS database, registry-hive contents, credential material, hashes, or
passwords were opened, transferred, or committed.

The first bounded attempt was blocked by Microsoft Defender as
`Trojan:Win32/Commando.A!ml`. Defender Events `1116` and `1117` confirmed
prevention, native Wazuh rule `67027` recorded generic process telemetry at level
3, and no IFM output was created. This blocked attempt is separate from the later
successful run.

The successful stdin-driven run completed from `2026-08-05 09:50:59 UTC` to
`09:51:07 UTC` with exit `0`. Four expected IFM files were verified by filename,
size, and timestamp only. Original Wazuh records `29775`, `29777`, and `29779`
showed the launcher, `ntdsutil.exe`, and `VSSVC.exe`; native coverage remained
generic and insufficient.

Final rules:

```text
100480 / level 12 — sensitive ntdsutil.exe execution
100481 / level 14 — explicit visible IFM creation arguments
MITRE: T1003.003
```

Final indexed proof:

```text
Timestamp: 2026-08-05T10:25:27.950Z
Agent: DC01 / 001
Rule: 100480 / level 12
Event: Security 4688 / record 29838
Process: C:\Windows\System32\ntdsutil.exe
MITRE: T1003.003 — NTDS
```

The operator captured the Dashboard screenshot with
`agent.id:"001" AND rule.id:"100480"`. Experimental VSS/ESENT correlation rule
`100482` was removed because no reliable custom alert was proven. `100481` is
supplemental and cannot see stdin-delivered arguments.

Cleanup passed: IFM output absent, temporary Defender test allowance removed,
Defender and real-time protection enabled, NTDS running, VSS stopped, shadow-copy
count zero, Wazuh agent/manager running, and `dcdiag` exit `0`.

Known limitation: rule `100480` also alerts on legitimate `ntdsutil.exe`
administration. No standalone benign false-positive run was preserved, so that
control remains future hardening work rather than an invented PASS.

Versioned sources:

```text
rules/ntds_credential_dump_detection.xml
tests/ntds_credential_dump_cmd.md
tests/results/ntds_credential_dump_validation_2026-08-05.md
```

Verdict: **COMPLETE / PASS** for simulation, telemetry, custom alert,
Dashboard/index delivery, and cleanup/recovery.

## Active/incomplete validation: BlueHammer CVE-2026-33825

BlueHammer is separate from NTDS and is **not complete**. WIN01 was version-
applicable after snapshot rollback (`4.18.1909.6`, below fixed boundary
`4.18.26030.3011`). Defender blocked the official release before process
creation. A later bounded manual launch with `--no-spawn --log-steps` started but
failed during Windows Update search with `0x800B0109` before exploit execution.
Live TLS inspection showed FortiGate captive interception presenting its appliance
certificate for Microsoft Update, with both untrusted-root and hostname-mismatch
errors. No successful protected-file copy, privilege escalation, or final Wazuh
impact evidence is claimed. Resume only after Microsoft Update trust/connectivity
works without interception; keep bounded flags and clean any protected-file copy
without inspecting it.

## Collaboration terms

- Say “false-positive tests,” not “negative controls.”
- Keep evidence strict: exact rule ID, level, MITRE IDs, live alert, cleanup.
- Strong combinations must outrank atomic fallbacks.
- Never declare a rule finished from XML syntax alone; live positive and false-positive tests are required.
