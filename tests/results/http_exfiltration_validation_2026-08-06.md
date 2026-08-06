# HTTP credential-file exfiltration validation — 2026-08-06

## Verdict

```text
Controlled sensitive fixture: PASS
HTTP POST exfiltration: PASS
Receiver integrity: PASS
Security/Sysmon/PowerShell telemetry: PASS
Custom rule 100531: PASS
Custom rule 100532: PASS
False-positive tests: PASS
Dashboard confirmation: PASS
Overall: COMPLETE / PASS
```

## Attack proof

A local medium-integrity `SIMULATION\yassine.karimi` PowerShell session created a controlled confidential-looking file containing a canary service account, password, and recovery token. Windows `curl.exe` uploaded the file with `POST /upload` and `--data-binary` to a bounded receiver on Kali.

The receiver accepted only the expected endpoint and a maximum two-megabyte body. It returned HTTP 201 and recorded:

```text
Bytes:   187
SHA-256: d3968bd4920f24b83f12f872edff1461d6ecb26d96a88021d60759a99cbf0296
Content gates: classification, account, password field, and recovery-token field all present
```

The locally calculated CRLF-encoded source was also 187 bytes with the same SHA-256. No real lab credential was transmitted or committed.

## Baseline telemetry

The first successful attack produced:

```text
PowerShell 4104 record: 156042 — credential staging and upload script
Security 4688 record:   41593 — curl.exe file-upload command
Sysmon Event 1 record:  56013 — curl.exe, Yassine, medium integrity
Native alert:           67027 / level 3
```

This proved the attack but exposed a detection gap: only generic process creation alerted.

## Detection engineering

`rules/http_exfiltration_detection.xml` adds:

```text
100530 / level 10 — direct Windows curl local-file upload over HTTP/S
100531 / level 12 — user-profile document/archive upload child
100532 / level 12 — PowerShell stages credential-like material and uploads it
MITRE T1041
```

The rules use observed decoded fields. The direct process path inherits native Security 4688 parent `67027`; the PowerShell script-block path inherits native 4104 parent `91802`. No destination IP, canary account, password value, filename, or receiver path is hardcoded into the rules.

Manager XML validation passed, the manager restarted successfully, and `wazuh-analysisd`, `wazuh-remoted`, `wazuh-logcollector`, `wazuh-monitord`, and `wazuh-modulesd` were running.

## Live positives

The first post-deployment trigger reached both detectors even though a receiver restart race caused the network transfer to return an empty reply:

```text
100532 / level 12 / PowerShell record 156563
100531 / level 12 / Security record 41681
```

The receiver was repaired with address reuse, verified listening, and the transfer was repeated successfully. Final live evidence:

```text
HTTP response:       201 / RECEIVED
Received bytes:      187
Received SHA-256:    exact match
Rule:                100531
Level:               12
Security record:     41689
Execution identity:  yassine.karimi
```

A live `100531` child proves its `100530` parent path matched. The separate live `100532` alert proves the 4104 credential-staging path.

## False-positive evidence

The same interactive user ran three benign controls:

| Security record | Control | Custom exfiltration alert |
|---:|---|---|
| 41691 | `curl.exe --version` | None |
| 41692 | Retrieval-only GET to loopback | None |
| 41693 | Inline `status=ok` POST without a file | None |
| 41945 | Inline `--data-binary status=ok` POST without a file | None |

After the raw 4688 controls arrived, the only custom exfiltration alert at or after the positive window remained rule `100531` on positive record `41689`. Record `41945` specifically proved that inline `--data-binary` content without an `@file` reference did not match the tightened rule. Rules `100530`, `100531`, and `100532` therefore passed the tested false-positive boundary.

## Dashboard and final state

Dashboard confirmation passed using the custom rule and exact-record queries. The bounded receiver and temporary SSH forwards were stopped. The receiver script and controlled received artifact remain on Kali for reproducibility; no credential material was placed in Git.
