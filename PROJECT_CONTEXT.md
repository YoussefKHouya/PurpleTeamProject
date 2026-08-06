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

## Closed partial validation: BlueHammer CVE-2026-33825

BlueHammer is separate from NTDS and is **closed as PARTIAL / exploit not
proven**. WIN01 was repeatedly restored to Defender platform `4.18.1909.6`, below
the fixed boundary `4.18.26030.3011`. Microsoft Update trust/connectivity was
repaired after an earlier `0x800B0109` failure caused by FortiGate TLS
interception. All later attempts used the source-reviewed bounded flags
`--no-spawn --log-steps`; no SYSTEM shell, password change, credential parsing,
or persistence branch was permitted.

The final controlled launch ran through an interactive, limited task as
`SIMULATION\yassine.karimi`. Security Event 4688 record `34029` at
`2026-08-05T14:01:43.1017096Z` preserves the exact executable and command line:

```text
SNEK_BlueWarHammer.exe --no-spawn --log-steps
```

Validated gates:

```text
Defender vulnerable-version applicability: PASS
Low-privilege interactive process start:   PASS
Windows Update search/download/install:    PASS
EICAR and oplock trigger stage:             PASS
New VSS path acquisition:                  FAIL / HANG
Protected-file access result:               NOT PROVEN
Privilege escalation:                       NOT PROVEN
```

One run failed immediately with `Failed to get new volume shadow copy path`.
The final run entered a high-CPU finder loop with VSS stopped and zero shadow
copies; the bounded task was terminated and the process was verified absent.
Source comparison against both the SNEK v1.0.1 tree and the older Church of
Malware `Nightmare_Eclipse/BlueHammer` tree confirmed the same defects: an
unbounded `goto scanagain` shadow-object loop and an immediate
`GetExitCodeThread` check that can misclassify `STILL_ACTIVE (259)`. The older
repository explicitly warns that PoC bugs may prevent execution and is not a
fixed replacement.

Final observed safety state after termination:

```text
BlueHammer process: absent
Protected-file result: absent
VSS service: stopped
Shadow copies: 0
Defender platform after update: 4.18.26070.9 (patched)
Real-time / behavior / IOAV / tamper protection: enabled
WazuhSvc: running
```

At the user's explicit request, the prepared BlueHammer lab is intentionally
retained rather than cleaned. Retained state includes the `BlueHammerLab`
directory and helper scripts, exact Defender threat-ID allowance `2147966615`
(action `6`), one-shot task `WazuhLab-BlueHammer-OneShot` in Ready state,
temporary RDP enablement, and Yassine membership in local Remote Desktop Users.
These retained controls can contaminate later telemetry and must not be described
as cleanup PASS. Final indexed Wazuh evidence for record `34029` was not
retrieved; endpoint evidence is authoritative for the final process execution.
Do not perform further blind rollback/rerun attempts. Revisit only as a separate
source-patching exercise with bounded thread waits, cancellation, backoff, and a
verified VSS trigger.

## Completed detection validation: PowerView reconnaissance

Tier 3 medium-high PowerView reconnaissance (`T1069.002`) was tested from WIN01
as ordinary domain user `SIMULATION\yassine.karimi`. The token was medium
integrity and not administrative; LDAP RootDSE reads passed. Official PowerView
was pinned to PowerSploit commit `d943001a7defb5e0d1657085a77a0e78609be58f`,
with `PowerView.ps1` SHA-256
`507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87`.
Selected domain, user, group, trust, and exact-object ACL functions were reviewed
as read-only; mutating functions were not invoked.

The initial attempt was blocked before the script remained on disk and classified
as `Trojan:PowerShell/Powersploit.G`. Security 4688 record `34415` proved the
Yassine launch under `wsmprovhost.exe`; Wazuh rule `100110`, level 10, was indexed
and the operator confirmed it in Dashboard. On the final screenshot rerun, staging
and pinned hash verification passed. The default execution policy first blocked
import; a process-scope-only `Bypass` retry then let Defender inspect the script.
Defender blocked import as `HackTool:PowerShell/PowerView` before any selected
`Get-*` function ran, so no AD reconnaissance output was produced.

A real telemetry gap was fixed: WIN01 did not collect
`Microsoft-Windows-Windows Defender/Operational`. That channel was added to the
dedicated `workstation-sysmon` group and endpoint `ossec.log` confirmed event
`1951` analysis. One bounded replay produced Defender records `1235`/`1236`
(Event 1116) and `1237` (Event 1117), all received in manager archives. Native
Wazuh rules handled them as:

```text
62123 / level 12 — PowerSploit-class Defender detection
62124 / level 3  — Defender remediation / Remove
```

The final screenshot event was Defender 1116 record `1245`, indexed at
`2026-08-05T15:08:58.251Z` under native Wazuh rule `62123`, level 12, with exact
decoded threat name `HackTool:PowerShell/PowerView`. The operator confirmed and
captured it using:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1245"
```

Candidate custom children `100494`/`100495` passed XML and `analysisd -t`, but
caused manager startup to exceed its timeout. They were immediately removed;
manager health and agent `004` Active state were restored. The repository retains
no unvalidated custom PowerView rule. Native `62123`/`62124` are the proven
baseline. A harmless Yassine string containing `PowerView` generated zero
Defender `1116`/`1117` and zero Wazuh `62123`/`62124`, passing the false-positive
test.

Cleanup passed for PowerView artifacts and tasks. BlueHammer retained state was
not touched. Verdict: **DETECTION VALIDATION COMPLETE / RECONNAISSANCE EXECUTION
BLOCKED**. Authoritative artifacts:

```text
agents/windows/workstation-sysmon-agent.conf
tests/powerview_cmd.md
tests/results/powerview_validation_2026-08-05.md
```

A separate approved CredSSP behavioral retest on 2026-08-06 removed the WinRM
LDAP double-hop. The session proved medium-integrity, non-admin
`SIMULATION\\yassine.karimi`, Kerberos authentication, and LDAP RootDSE access.
Pinned PowerView imported successfully and all 20 selected read-only checks passed,
including domain, forest, controller, user, group, computer, OU, GPO, trust, site,
subnet, exact-object ACL, policy, file-server, DFS, managed-security-group, and
foreign-principal discovery. No mutating, ticket, roasting, credential, or remote-
action function ran. PowerShell 4104 record `99403` reached native Wazuh rule
`91823`, level 14, and the operator confirmed it in Dashboard. Target artifacts
and processes were removed. The original Defender prevention verdict remains
preserved. Evidence: `tests/results/powerview_credssp_retest_2026-08-06.md`.

## Tier 3 enumeration batch — 2026-08-05

Four additional medium-high tests were processed atomically after PowerView. The
initial prevention tests kept Defender enabled. A later GUI-controlled SharpView
behavioral retest changed this condition; that retest and unresolved Defender
restoration are documented separately below.

### SharpView

Official `tevora-threat/SharpView` commit
`b60456286b41bb055ee7bc2a14d645410cca9b74` was pinned; compiled artifact
SHA-256 was `c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93`.
Defender blocked the file write before low-privilege execution as
`VirTool:MSIL/Menace.C!MTB`. Defender 1116 record `1270` reached Wazuh rule
`62123`, level 12. Harmless string control produced zero matching Defender
events. Initial cleanup and endpoint health passed. Original verdict:
**DETECTION COMPLETE / ENUMERATION BLOCKED**. During the later GUI-allowed retest,
the pinned binary executed twice as medium-integrity `SIMULATION\\yassine.karimi`.
The corrected explicit-domain invocation returned forest `SIMULATION.LOCAL`, then
hit WinRM's non-delegable credential boundary. Security records `35684/35689`,
Sysmon records `42164/42175`, and Wazuh `67027` level 3 prove process execution.
Retest verdict: **EXECUTION PASS / ENUMERATION PARTIAL / GENERIC VISIBILITY PASS**.

Interactive closure on 2026-08-06 superseded that partial enumeration verdict.
From a genuine medium-integrity `SIMULATION\\yassine.karimi` shell, the explicit
DC invocation `Get-NetUser -PreauthNotRequired -Domain simulation.local -Server
DC01.simulation.local` bound to
`LDAP://DC01.simulation.local/DC=simulation,DC=local` and returned
`hannah.reed` with `DONT_REQ_PREAUTH`. Security record `39160` and Sysmon record
`50410` reached native rule `67027`, level 3. Custom rule `100522`, level 12,
provides named SharpView semantic coverage. Custom rule `100523`, level 10,
provides filename-independent coverage for shell-launched executables using the
same exact discovery semantics. Its first path-anchored version failed on live
record `39194` because Wazuh preserved doubled separators; that failure is
retained. After removing separator dependence, real renamed `survey.exe`
execution fired `100523` on Security record `39237`. Paired Sysmon record `50599`
proved `OriginalFileName=SharpView.exe`, product/description `SharpView`, the
pinned SHA-256, Yassine identity, and Medium integrity. Documentation-only
PowerShell record `139332` fired neither custom rule. Evidence:
`tests/results/sharpview_interactive_detection_validation_2026-08-06.md`.
Final verdict: **EXECUTION PASS / LDAP ENUMERATION PASS / DETECTION PASS**.
Artifacts remain intentionally retained for reproduction.

### adPEAS

`61106960/adPEAS` commit `1ea06f1d2dc92152b5aaeca6eacff24dd096d82e`
was pinned. `adPEAS_min.ps1` SHA-256 was
`7d7c1535ef4d33f24b738509af3962500453070ae94b0cbb23927c6e65d0a10b`.
The module imported under ordinary user `SIMULATION\\yassine.karimi`, but its
Windows-auth LDAP session hit the WinRM delegation boundary. No credentials were
embedded into command or script-block telemetry to force the bind. Security 4688
record `35217` reached Wazuh rule `100134`, level 11. No queue-loss rule `203`
appeared; false-positive test and cleanup passed. Verdict: **PARTIAL**.

A separate approved CredSSP retest preserved that original verdict and solved
the double hop. A native CredSSP session on WIN01 authenticated as
`SIMULATION\\yassine.karimi` with Kerberos and read LDAP RootDSE
`DC=SIMULATION,DC=LOCAL`. The bounded `-UseWindowsAuth -OPSEC -Module Domain`
run connected to `DC01.SIMULATION.LOCAL`, found one domain controller, and
analyzed LDAP-signing/channel-binding GPO data. Actual PowerShell record `96416`
reached native rule `91823`, level 14. New semantic rule `100520`, level 14,
was validated by live no-LDAP synthetic positive record `96942`; the
documentation-only control stayed quiet. Client/server CredSSP, exact fresh-
credential delegation policy, adPEAS files, output, and ephemeral Kali tooling
were removed. Full evidence is in
`tests/results/adpeas_credssp_retest_2026-08-05.md`. Retest verdict: **PASS**.

### Seatbelt

`GhostPack/Seatbelt` commit `392171df84472591d4eae7ebd5b1cdc96ba91377`
was first built directly on WIN01 against its original .NET Framework 3.5 target.
That attempt failed with `MSB3645/MSB3644`: enabling the `NetFx3` runtime did not
supply the absent .NET Framework 3.5 SP1 developer reference assemblies. The
historical result remains in `tests/results/seatbelt_validation_2026-08-05.md`.

Interactive closure on 2026-08-06 preserved the original project, minimally
retargeted the pinned source copy to .NET Framework 4.8, and compiled it with
official `Microsoft.Net.Compilers.Toolset` 4.8.0 and
`Microsoft.NETFramework.ReferenceAssemblies.net48` 1.0.3 packages. The resulting
593408-byte `Seatbelt.exe` had SHA-256
`bc17d0107c34fb6f67e85d9c37a9b606e1f3c6a48bc8de4d710cd6d6b1695fff`.
A local medium-integrity `SIMULATION\\yassine.karimi` shell ran only `OSInfo`,
`TokenGroups`, and `PowerShell`; retained output proved hostname `Win01`, domain
`SIMULATION.LOCAL`, the Yassine identity, Domain Users membership, and PowerShell
posture output. Security record `39393` and Sysmon records `51067`/`51075`
correlated the initial run.

Custom Sysmon rule `100524`, level 12, matches rename-resistant Seatbelt PE
metadata plus an anchored command grammar containing exactly the three approved
modules. Initial positive record `51193` passed with Security record `39423`.
After independent review hardened the argument boundary, positive record `51536`
passed; a genuine Seatbelt run with appended invalid token
`NotASeatbeltCommand` produced Sysmon record `51546` and Security record `39533`
but no `100524`. A copied `whoami.exe` named `Seatbelt.exe` and launched with the
same approved arguments produced Sysmon record `51243` and Security record
`39433` but no `100524`, proving both metadata and argument-boundary false-positive
resistance.
Defender was already inactive except tamper protection and was not modified; no
Seatbelt Defender 1116/1117 event occurred. Source, build tools/products, output,
and controls remain retained. Full evidence:
`tests/results/seatbelt_interactive_detection_validation_2026-08-06.md`. Verdict:
**PASS**.

### PowerSploit PowerUp

`PowerShellMafia/PowerSploit` commit
`d943001a7defb5e0d1657085a77a0e78609be58f` was pinned; `Privesc/PowerUp.ps1`
SHA-256 was `9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22`.
Defender blocked staging before import as `HackTool:PowerShell/EventVwrBypass`.
Defender 1116 record `1284` reached Wazuh rule `62123`, level 12. Native
registry/service false-positive tests produced zero matching Defender events;
no queue-loss rule `203` appeared. Cleanup passed. Verdict: **DETECTION COMPLETE
/ EXECUTION BLOCKED**.

A separate approved CredSSP behavioral retest on 2026-08-06 imported the pinned
PowerUp script successfully as medium-integrity `SIMULATION\\yassine.karimi` with
Kerberos. `Get-RegistryAlwaysInstallElevated` executed; direct HKLM/HKCU reads
confirmed both values absent and no exploitable condition. `Get-UnquotedService`
and `Get-ModifiableService` reached execution but were denied by the remote low
token/Service Control Manager. This is **EXECUTION PASS / HOST CHECKS PARTIAL**,
not Defender prevention. PowerShell 4104 record `100167` reached native Wazuh rule
`91823`, level 14; manager `alerts.json` proof passed and Dashboard confirmation
remains pending. Cleanup passed. Evidence:
`tests/results/powerup_credssp_retest_2026-08-06.md`.

Interactive closure then ran `Invoke-AllChecks` from a genuine local
medium-integrity `SIMULATION\\yassine.karimi` shell. PowerShell records `104573`
(`Invoke-AllChecks`), `104676` (`Get-UnquotedService`), `104681`
(`Get-ModifiableServiceFile`), and `126085` (`Get-ModifiableService`) reached
manager archives but initially selected no alert, proving a detection gap.
Custom filename-independent rule `100521`, level 12, now detects exact
`Invoke-AllChecks`/`Invoke-PrivescAudit` invocation under native PowerShell
script-block parent `91802`. Harmless positive record `131587` fired; benign
documentation record `131678` did not. Manager alert and exact index document
both passed. PowerUp's `edgeupdate`/`edgeupdatem` results referenced permissions
on `C:\`, not proven writes to their quoted Program Files executable, and are
not classified as exploitable. The user-owned WindowsApps PATH result does not
prove a privileged DLL load. Evidence:
`tests/results/powerup_interactive_detection_validation_2026-08-06.md`.

The first separate behavioral gate attempted only
`Set-MpPreference -DisableRealtimeMonitoring $true`. Tamper Protection was active
and live protection stayed enabled. Later, the operator changed Defender controls
through the GUI for SharpView. The pinned binary then executed and returned forest
`SIMULATION.LOCAL`, but WinRM credential delegation blocked full controller
expansion. The GUI state also disabled real-time, behavior, and IOAV protection.
The exact SharpView exclusion and artifacts were removed; remote restoration was
rejected by Tamper Protection. Final read-only status at
`2026-08-05T19:17:50.9927163Z` was Antivirus enabled, Tamper Protection enabled,
but real-time, behavior monitoring, and IOAV protection still disabled. The attack
batch is complete; those three controls require later restoration through the
WIN01 GUI before the lab returns to its protected baseline. PowerUp was not rerun
in this later window.

Live verification on 2026-08-06 superseded that stale protection checkpoint:
Defender real-time, behavior, IOAV, and tamper protections were all enabled during
the PowerView/PowerUp CredSSP retests. CredSSP client/server roles remain enabled
by explicit operator direction for reproducible later lab work, restricted to
delegation target `wsman/WIN01.SIMULATION.LOCAL`. Current lab policy retains
useful tools, artifacts, vulnerable configuration, and access posture by default;
cleanup or rollback occurs only on explicit operator request or when required for
test validity or containment outside the isolated lab.

## Bounded network scans — 2026-08-05

Masscan `1.3.2` scanned TCP ports `1-65535` against one explicit WIN01 `/32` at
100 packets/second from `2026-08-05T18:03:12.347240800Z` through
`2026-08-05T18:14:12.564640737Z`. A direct-link retry required the target's
neighbor-table MAC via `--router-mac`; the first attempt had failed before sending
scan traffic while trying router `0.0.0.0`. The successful JSON reported ports
`135`, `3389`, `5040`, `5985`, and `7680` open. Packet capture proved exactly
65,535 outbound SYNs, 65,535 unique ports, and one destination host.

Nmap `7.98` then ran an isolated `-sS -Pn -n --top-ports 1000` scan with max rate
50 and one retry. It completed in 40.89 seconds and reported ports `135`, `3389`,
and `5985` open. Packet capture proved 2,027 SYNs, 1,000 unique ports, and one host.
A one-port TCP/445 SYN false-positive control produced no scan alert.

Both Filtering Platform audit subcategories were `No Auditing`; the original scan
windows therefore exposed a real endpoint/Wazuh telemetry gap. A later closure
phase deployed a temporary SYSTEM watcher over Windows built-in `pktmon`, filtered
to the exact Kali/WIN01 pair and correlated by distinct inbound SYN destination
ports in a ten-second window.

A representative Masscan `1-100` trigger produced Application 1101 record `4469`
and Wazuh `100511`, level 12, T1046; 47 distinct ports and 48 packets were present
at threshold crossing, with 99 matching SYNs total. Nmap's top-1,000 profile reran
in 40.84 seconds and produced Application 1101 record `4471`, Wazuh `100511`, 54
distinct ports and 104 packets at threshold crossing, and 2,017 matching SYNs
total. Recovery events `4470/4472` reached Wazuh `100513`. A one-port TCP/445
false-positive test produced zero scan alerts and zero new watcher errors.

Final verdict for both: **EXECUTION PASS / PACKET PROOF PASS / ENDPOINT-WAZUH
DETECTION PASS**. Scanner artifacts and temporary watcher task/script/pktmon
session/filter/output files were removed. Manager rule remains deployed.

## PsExec service execution — 2026-08-05

WIN01 SMB listened on TCP/445 but its baseline firewall blocked Kali. One temporary
inbound rule allowed only Kali's lab address to WIN01 TCP/445. Impacket
`psexec` authenticated through an in-memory password prompt, wrote a randomized
service binary through `ADMIN$`, created/started/stopped/removed service `auAA`,
and removed the binary. The bounded marker proved execution as
`NT AUTHORITY\\SYSTEM` at `2026-08-05T17:50:40.0728833Z`.

System `7045` record `5066`, Security `4688` records `35750/35751`, and Sysmon
records `42334/42335` established the service/process chain. Native Wazuh rule
`92650`, level 12, mapped it to `T1021.002` and `T1569.002`; supporting rules
`67027`, `92052`, and `100313` also fired. An authenticated SMB share-listing
false-positive test created no `7045` or `92650`. Marker, service, binary, matching
WER report, and temporary firewall rule were removed; TCP/445 returned to timeout
baseline. Verdict: **COMPLETE / PASS**, with Defender prevention untested because
protection was intentionally disabled.

## WinRM remote execution — 2026-08-05

Direct WinRM executed one encoded PowerShell marker command as
`SIMULATION\\Administrator` at `2026-08-05T18:20:12.2934714Z`. Endpoint evidence
proved `WinrsHost.exe -> cmd.exe -> powershell.exe`: Security `4688` records
`35871/35873/35874` and Sysmon records `42711/42712`. Wazuh rule `100331`, level
12, detected CMD launching encoded PowerShell; rule `100110`, level 10, detected
the encoded PowerShell child. Supporting rules `67027` and `92052` preserved
WinRM host-process context.

The false-positive test authenticated and opened/closed a WinRM shell without
running a command. It produced only generic `67027` process visibility and zero
`100331/100110` alerts. Marker and empty directory were removed; Wazuh and firewall
services remained healthy. Verdict: **COMPLETE / PASS**, with Defender prevention
untested because protection remained intentionally disabled.

## Delegated GPO persistence — 2026-08-05

The operational `Wazuh - Windows Auditing` GPO was not overwritten. Its final
fingerprint remained GUID `0738bd22-e453-4f0b-89a7-950cba627004`, modification
`2026-07-27T14:42:44Z`, user version `0`, and computer version `17`.

A disposable `Workstation Software Update` GPO
(`270b30fc-4a68-41a2-96ef-d44d6f2dc265`) was linked at the domain root, not
enforced. Authenticated Users had read only, WIN01 alone had Apply, and
low-privilege `SIMULATION\\yassine.karimi` had GPO edit rights. Yassine changed
the computer version `0 -> 1` and configured HKLM Run `WindowsUpdateHealth` to a
benign WIN01-local updater script. WIN01 applied the exact value after `gpupdate`;
no interactive logon occurred, so payload execution was not claimed.

DC Security 5136 records `30586-30588` identify Yassine, the exact GPO DN,
version change, and Registry extension. Wazuh agent 001 ingested all three as
native rule `60229`, level 4, MITRE T1484. WIN01 GroupPolicy records `6714`,
`6719`, and `6725`, plus System record `5073`, prove policy application. No
matching Sysmon Event 13 appeared, leaving a documented endpoint registry
telemetry gap.

Read-only `Get-GPO` by the same user created zero 5136 and zero Wazuh 60229.
Yassine then removed the registry policy, increasing computer version `1 -> 2`.
Policy withdrawal tattooed the arbitrary Run value, so cleanup removed only that
value explicitly. The link, GPO, SYSVOL directory, updater script, marker, and Run
value were removed; final `gpresult` excluded the test GPO. Verdict:
**PASS WITH ENDPOINT SYSMON GAP**.

## Dashboard queries — 2026-08-05 batch

Use Wazuh Dashboard Discover / Threat Hunting with the relevant UTC window:

```text
# Masscan and Nmap target-side watcher alerts
agent.id:004 AND rule.id:100511

# Exact Masscan and Nmap watcher records
agent.id:004 AND rule.id:100511 AND data.win.system.eventRecordID:(4469 OR 4471)

# Watcher recovery/reset
agent.id:004 AND rule.id:100513 AND data.win.system.eventRecordID:(4470 OR 4472)

# Delegated GPO modification
agent.id:001 AND rule.id:60229 AND data.win.eventdata.subjectUserName:"yassine.karimi"

# Exact GPO mutation records
agent.id:001 AND rule.id:60229 AND data.win.system.eventRecordID:(30586 OR 30587 OR 30588)

# Exact disposable GPO object
agent.id:001 AND rule.id:60229 AND data.win.eventdata.objectDN:*270B30FC-4A68-41A2-96EF-D44D6F2DC265*

# PsExec service execution
agent.id:004 AND rule.id:92650

# WinRM encoded command chain
agent.id:004 AND (rule.id:100331 OR rule.id:100110)
```

Manager `alerts.json` proved delivery. Dashboard/index API verification was not
available; an empty Dashboard result must be treated as an indexing/time-range
issue until checked manually, not as evidence that endpoint events did not exist.

Authoritative artifacts:

```text
tests/sharpview_cmd.md
tests/results/sharpview_validation_2026-08-05.md
tests/adpeas_cmd.md
tests/results/adpeas_validation_2026-08-05.md
tests/seatbelt_cmd.md
tests/results/seatbelt_validation_2026-08-05.md
tests/results/seatbelt_interactive_detection_validation_2026-08-06.md
rules/seatbelt_detection.xml
tests/powersploit_powerup_cmd.md
tests/results/powersploit_powerup_validation_2026-08-05.md
tests/masscan_cmd.md
tests/results/masscan_validation_2026-08-05.md
tests/nmap_syn_cmd.md
tests/results/nmap_syn_validation_2026-08-05.md
agents/windows/tcp_scan_watcher.ps1
rules/tcp_scan_detection.xml
tests/tcp_scan_watcher_cmd.md
tests/results/tcp_scan_watcher_validation_2026-08-05.md
tests/psexec_cmd.md
tests/results/psexec_validation_2026-08-05.md
tests/winrm_cmd.md
tests/results/winrm_validation_2026-08-05.md
tests/gpo_delegated_persistence_cmd.md
tests/results/gpo_delegated_persistence_validation_2026-08-05.md
tests/chisel_cmd.md
tests/results/chisel_reverse_tunnel_validation_2026-08-06.md
rules/chisel_detection.xml
```

Dashboard/index API verification remains unavailable for these new events because
the available dashboard credential was rejected by the indexer API. Manager
`alerts.json` evidence is proven. Do not report this as indexed Dashboard proof.

## Chisel reverse tunnel — 2026-08-06

Official `jpillora/chisel` v1.11.8 commit
`310eec3696e82ef14048268d1d12f1cd99d6dbe9` passed `go test ./...` and was
cross-compiled for Windows AMD64 and Kali Linux AMD64. The Windows SHA-256 was
`333e76e0f05b84035396f62990c8e84a31e23a5a43e99766f8d922c634f512e3`.
Medium-integrity `SIMULATION\\yassine.karimi` connected the genuine client to a
Kali reverse-enabled server and exposed Kali loopback `18089` to WIN01 loopback
RDP. A bounded RDP negotiation returned the expected 19-byte response; no RDP
session, SOCKS proxy, subnet route, persistence, or credential capture occurred.

Sysmon record `53901` and Security record `40614` preserve the real tunnel.
Rule `100525`, level 10, detects the pinned build by SHA-256 independent of
filename; renamed `relay-service.exe --version` fired on record `53962`. Child
rule `100526`, level 12, requires client plus port-forward/reverse syntax and
fired on renamed record `53950`. A `whoami.exe` process with identical-looking
arguments produced record `53952` but no custom alert. Both rules map T1572.
Processes and the tracked Kali server were stopped. The operator-created Defender
exclusion remains pending administrator rollback. Verdict: **PASS WITH DEFENDER
EXCLUSION ROLLBACK PENDING**.

## Chisel reverse SOCKS / ProxyChains — 2026-08-06

The retained pinned Chisel client ran locally as medium-integrity
`SIMULATION\\yassine.karimi` with `R:socks`. The Kali server exposed loopback
SOCKS TCP/1080, and a temporary strict ProxyChains configuration completed one
bounded TCP connection through the tunnel to the known domain controller LDAP
service. No subnet scan, LDAP authentication, or directory query occurred.

After recovering failed Wazuh manager daemons, the clean rerun reached custom
rule `100526`, level 12, T1572, on Sysmon record `55794`; the pinned SHA-256 and
Yassine identity matched. Existing rules already covered this behavior, so no new
rule was added. Server and temporary forwards/configuration were stopped. Evidence:
`tests/results/chisel_socks_proxychains_validation_2026-08-06.md`. Verdict:
**COMPLETE / PASS**.

## HTTP credential-file exfiltration — 2026-08-06

A medium-integrity `SIMULATION\\yassine.karimi` PowerShell session staged a
controlled confidential-looking file with canary service credentials and uploaded
it through Windows `curl.exe` using HTTP POST and `--data-binary`. The bounded Kali
receiver returned HTTP 201 and received 187 bytes; source and receiver SHA-256 both
equaled `d3968bd4920f24b83f12f872edff1461d6ecb26d96a88021d60759a99cbf0296`.
No real lab credential was transmitted or committed.

Baseline records `156042` (PowerShell 4104), `41593` (Security 4688), and `56013`
(Sysmon Event 1) proved the complete attack but selected only native rule `67027`.
`rules/http_exfiltration_detection.xml` now provides `100530` for direct curl file
uploads, high-confidence user-profile child `100531`, and PowerShell credential-
staging rule `100532`, all mapped to T1041. Live positives reached `100532` on
record `156563` and `100531` on records `41681` and `41689`; the final transfer
returned HTTP 201 with exact byte/hash integrity. False-positive records `41691`,
`41692`, and `41693` covered version output, retrieval-only traffic, and an inline
benign POST without triggering any custom exfiltration rule. Dashboard confirmation
passed. Evidence: `tests/http_exfiltration_cmd.md` and
`tests/results/http_exfiltration_validation_2026-08-06.md`. Verdict:
**COMPLETE / PASS**.

## DNS credential-file exfiltration — 2026-08-06

The controlled 187-byte credential file was hex-encoded and sent from the
medium-integrity Yassine PowerShell session as eight ordered DNS labels to Kali.
Kali reconstructed the exact source SHA-256
`d3968bd4920f24b83f12f872edff1461d6ecb26d96a88021d60759a99cbf0296`.
Wazuh rule `100534` fired at level 12 on all eight DNS Client 3006 records
`261665`, `261674`, `261683`, `261692`, `261701`, `261710`, `261719`, and
`261728`; PowerShell rule `100535` fired on 4104 record `159612`. A normal
`dc01.simulation.local` lookup generated records `261737` through `261745`
without a custom DNS-exfiltration alert. The receiver was stopped. Evidence:
`tests/results/dns_exfiltration_validation_2026-08-06.md`. Verdict:
**COMPLETE / PASS**.

## Microsoft Defender preference tampering — 2026-08-06

An Administrator PowerShell session successfully added the controlled exclusion
`C:\ProgramData\DefenderTamperLab`; Defender was not disabled globally. Custom
rule `100536`, level 10, T1562.001, fired on PowerShell 4104 records `161611` and
`162758`. The read-only `(Get-MpPreference).DisableRealtimeMonitoring` test
produced record `161641` and no custom tampering alert.

A proposed 4103 high-confidence rule was removed rather than versioning dead
coverage after two bounded refinements failed against the live escaped payload and
parent shape. The proven 4104 rule remains deployed, manager health passed, and the
deployed/repository hashes match. The operator removed the exclusion and controlled
directory; the endpoint returned `DEFENDER_CLEANUP=PASS`. Evidence:
`tests/results/defender_tampering_validation_2026-08-06.md`. Verdict: **COMPLETE /
PASS**.

## AMSI bypass prevention and detection — 2026-08-06

WIN01 PowerShell 5.1 ran in Full Language Mode as `WIN01\adam.wilson` with
Defender antivirus, real-time protection, AMSI, Tamper Protection, and Wazuh
active. A bounded process-local `AmsiUtils.amsiInitFailed` reflection attempt used
only the harmless EICAR test string. Defender rejected it at parse time with
`ScriptContainedMaliciousContent`; no bypass, payload execution, persistence, or
memory modification occurred.

The first block produced PowerShell 4103 record `163861`. After deriving the live
parent and payload, final rule `100538`, level 14, T1562.001, fired on record
`164327`. A harmless `AmsiScanBuffer documentation review` command produced records
`164363` through `164365` without rules `100537` or `100538`. Manager health and
deployed/repository hash equality passed; cleanup was unnecessary because execution
was blocked. Evidence: `tests/results/amsi_bypass_validation_2026-08-06.md`.
Verdict: **PREVENTION PASS / DETECTION PASS**.

## Collaboration terms

- Say “false-positive tests,” not “negative controls.”
- Keep evidence strict: exact rule ID, level, MITRE IDs, live alert, cleanup.
- Strong combinations must outrank atomic fallbacks.
- Never declare a rule finished from XML syntax alone; live positive and false-positive tests are required.
