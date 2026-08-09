# Unix Shell Detection Validation — 2026-07-19

## Scope

Live validation of `unix_shell_detection.xml` against normalized Linux auditd EXECVE telemetry from the approved Ubuntu lab agent.

## Environment

- Ubuntu 22.04, x86_64
- Linux kernel 5.15.0-185-generic
- Wazuh manager and agent v4.14.6
- Wazuh agent ID 003
- auditd 3.0.7
- Data sources: `/var/log/audit/audit.log` and `/var/log/wazuh-audit-exec.json`

## Telemetry engineering

Initial state had an active Wazuh agent but no auditd package or process-execution telemetry. The following were deployed:

```text
/etc/audit/rules.d/50-wazuh-shell.rules
/etc/audit/plugins.d/wazuh-exec.conf
/usr/local/sbin/wazuh-audit-exec-json
/etc/logrotate.d/wazuh-audit-exec
```

Audit scope:

```text
execve and execveat
auid >= 1000
auid != unset
key = wazuh_shell_exec
```

Wazuh's audit decoder omitted hex-encoded shell payload arguments. A tested audit dispatcher now correlates SYSCALL, EXECVE, CWD, and EOE records, decodes arguments, and emits normalized JSON with a readable `command_line` field.

## Deployed rule hierarchy

| Rule | Level | Detection | MITRE |
|---:|---:|---|---|
| 100200 | 0 | Raw tagged audit base; suppresses raw exec noise | — |
| 100201 | 0 | Normalized JSON parent | — |
| 100202 | 3 | Shell interpreter with command/stdin flags | T1059.004 |
| 100203 | 7 | curl/wget remote retrieval | T1105 |
| 100204 | 8 | Shell-history clearing | T1070.003 |
| 100205 | 7 | Executable permission addition | T1222.002 |
| 100206 | 6 | Base64/xxd/OpenSSL decoding | T1140 |
| 100207 | 8 | Shell execution from `/tmp` | T1059.004 |
| 100208 | 9 | `/etc/shadow` or `/etc/gshadow` access | T1003.008 |
| 100209 | 6 | Dual-use nc/ncat/netcat/socat execution | T1095 |
| 100210 | 5 | BusyBox `sh`/`ash` command execution | T1059.004 |
| 100220 | 12 | Download piped/chained to shell | T1059.004, T1105 |
| 100221 | 12 | Reverse-shell command pattern | T1059.004 |
| 100222 | 11 | Decode then execute through shell | T1059.004, T1140 |
| 100223 | 10 | Shell-profile persistence modification | T1546.004 |
| 100224 | 10 | SSH authorized-keys modification | T1098.004 |
| 100225 | 10 | Sudoers modification | T1548.003 |
| 100226 | 9 | Crontab/cron persistence modification | T1053.003 |

Historical note: rule `100200` existed during this validation but had no children. The 2026-08-09 robustness pass removed it; the validated normalized JSON chain remains rooted at `100201`.

## Positive live tests

| Test | Behavior | Expected | Actual | Result |
|---|---|---:|---:|---|
| U01 | `bash -c` baseline | 100202/L3 | 100202/L3 | PASS |
| U02 | curl retrieval attempt | 100203/L7 | 100203/L7 | PASS |
| U03 | curl piped to shell | 100220/L12 | 100220/L12 | PASS |
| U04 | bounded `/dev/tcp` reverse-shell attempt | 100221/L12 | 100221/L12 | PASS |
| U05 | Base64 decode piped to shell | 100222/L11 | 100222/L11 | PASS |
| U06 | Ephemeral `history -c` | 100204/L8 | 100204/L8 | PASS |
| U07 | Temporary `.bashrc` modification marker | 100223/L10 | 100223/L10 | PASS |
| U08 | Temporary `authorized_keys` modification marker | 100224/L10 | 100224/L10 | PASS |
| U09 | Temporary `sudoers` modification marker | 100225/L10 | 100225/L10 | PASS |
| U10 | Failed crontab-file installation attempt | 100226/L9 | 100226/L9 | PASS |
| U11 | Add executable permission to temporary file | 100205/L7 | 100205/L7 | PASS |
| U12 | Base64 decode without execution | 100206/L6 | 100206/L6 | PASS |
| U13 | Execute temporary shell script | 100207/L8 | 100207/L8 | PASS |
| U14 | Quiet `/etc/shadow` root-record query | 100208/L9 | 100208/L9 | PASS |
| U15 | Netcat connection check | 100209/L6 | 100209/L6 | PASS |

Reverse-shell and network-utility rules were retested after tuning:

```text
Generic nc -z: 100209 level 6
/dev/tcp reverse shell: 100221 level 12
```

## BusyBox extension

BusyBox v1.30.1 was present with `sh`, `ash`, `wget`, `nc`, `chmod`, `crond`, and `crontab` applets.

Pre-fix proof showed the parent Bash process firing rule 100202 while the actual `/usr/bin/busybox` child event received no alert. Rule 100210 and BusyBox-aware chain patterns closed that gap.

| Test | Behavior | Expected | Actual | Result |
|---|---|---:|---:|---|
| BB01 | `busybox sh -c` | 100210/L5 | 100210/L5 | PASS |
| BB02 | `busybox ash -c` | 100210/L5 | 100210/L5 | PASS |
| BB03 | BusyBox wget piped to BusyBox sh | 100220/L12 | 100220/L12 | PASS |
| BB04 | BusyBox nc reverse-shell pattern | 100221/L12 | 100221/L12 | PASS |
| BB05 | BusyBox sh execution from `/tmp` | 100207/L8 | 100207/L8 | PASS |

BusyBox negative controls:

| Test | Must not fire | Actual | Result |
|---|---|---|---|
| BBN1 `busybox echo` | 100210 | Baseline parent only | PASS |
| BBN2 `busybox wget --help` | 100203/100220 | Baseline parent only | PASS |
| BBN3 `busybox chmod 0644` | 100205 | Baseline parent only | PASS |

Shell-family expressions now include `ash`, and download/decode/temp-execution chains accept optional `busybox` dispatch.

## Negative controls

| Test | Must not fire | Actual | Result |
|---|---|---|---|
| N01 `crontab -l` | 100226 | Baseline 100202 only | PASS |
| N02 `base64 --version` | 100206/100222 | Baseline 100202 only | PASS |
| N03 `chmod 0644` | 100205 | Baseline 100202 only | PASS |
| N04 `curl --version` | 100203/100220 | Baseline 100202 only | PASS |
| N05 `.bashrc` read check | 100223 | Baseline 100202 only | PASS |

## Tuning and test corrections

- Generic netcat execution initially used level 10. A benign `nc -z` control proved that severity excessive. Rule 100209 was reduced to level 6 while reverse-shell rule 100221 remained level 12.
- Initial U08/U09 fake filenames prefixed the target basename with an underscore, defeating intentional regex word boundaries. Tests were corrected to isolated realistic basenames under `/tmp`.
- Initial U13 used a shell variable for the temporary path, so the parent command line did not expose the literal path. Retest isolated `/bin/sh /tmp/...` and passed.

## Final verification

```text
Local XML parse: PASS
Duplicate IDs: none
wazuh-analysisd -t: exit 0
Wazuh manager: active
Linux agent 003: active
Auditd: active
Wazuh agent: active
Normalizer plugin: active
Logrotate configuration debug: PASS
Audit lost events: 0
Audit backlog: 0
Deployed rule ownership: wazuh:wazuh
Deployed rule mode: 660
Temporary artifacts remaining: none
```

## Known behavior

SSH-driven tests create nested shell processes, so parent and child events can produce duplicate alerts for one test action. Rule severity and IDs were validated despite duplication. Raw audit execution events are level 0 to avoid alert floods; only normalized behavior rules alert.

## Verdict

Core Unix Shell T1059.004 telemetry and behavior rules are deployed and live-validated. Download-execute, reverse shell, decode-execute, history clearing, persistence, credential access, permission modification, temporary execution, BusyBox/ash dispatch, and dual-use networking coverage all passed positive and negative controls.
