# HTTP and DNS exfiltration rule hardening — 2026-08-09

## Verdict

```text
Historical attack/receiver integrity evidence: PRESERVED / PASS
Rule redesign:                              LOCAL PASS
Regression fixtures:                        PASS (17 tests)
XML parse and duplicate-ID check:            PASS (26 files / 139 unique IDs)
Previous manager parser and restart health:  PASS
Previous live HTTP/DNS closure:               PASS
Current HTTP --next fix native parser/deploy: PASS
Current HTTP --next live boundary retest:     PASS
Overall hardening status:                     PASS
```

This pass strengthens the detectors without rewriting the original 2026-08-06 attack evidence. The historical reports remain authoritative for successful receiver byte/hash proof. The initial redesign and subsequent endpoint closure are preserved below. A later independent review found that the PowerShell curl branches rejected legitimate HTTP uploads whenever the command also contained `--next`; the segment-aware correction is now locally regression-tested, natively parsed and deployed, and live-proven on both PowerShell parent paths with a cross-transfer false-positive control.

## Branch review

Work was already on `hardening/wazuh-rule-robustness`, tracking the same remote branch. Before this pass, the remote hardening branch was two commits ahead of `origin/main` and zero commits behind.

The branch is broader than only Chisel and Seatbelt. Its existing two commits also change ADPEAS, CertiGhost, process-injection severity/claims, dashboard queries, README/context, and add `tests/test_rule_hardening.py`. Chisel and Seatbelt are the largest structural changes:

- Chisel adds hash-independent tunnel-behavior visibility while keeping named-tool attribution under pinned-hash children.
- Seatbelt separates module-independent authentic PE metadata from the exact bounded module classifier.
- Regression tests enforce both attribution boundaries.

No merge to `main` was performed.

## HTTP redesign

`rules/http_exfiltration_detection.xml` now contains seven layers:

```text
100530 / level 10 — Security 4688 curl local-file upload syntax
100531 / level 12 — sensitive immediate source-file argument
100532 / level 10 — PowerShell curl/IWR/IRM/WebClient/BITS/HttpClient upload behavior
100544 / level 10 — rename-resistant curl OriginalFileName metadata plus upload syntax
100545 / level 11 — credential-like staging on the environment-variable PowerShell path
100547 / level 10 — base-parent PowerShell upload behavior without environment-variable child selection
100548 / level 11 — credential-like staging on the base-parent PowerShell path
```

Key corrections:

- `--data-binary` requires an immediate `@file` value.
- `--upload-file` and `-T` accept quoted/unquoted local source arguments.
- Source matching is argument-bound; a sensitive extension in the destination URL cannot satisfy `100531`.
- Curl upload syntax and HTTP/S destination must occur in the same transfer segment and cannot cross a transfer reset.
- Each PowerShell API alternative binds a literal HTTP/S destination to the same upload call or command segment.
- PowerShell coverage no longer depends on literal canary fields plus curl in one exact script shape.
- Curl remains attributable after ordinary executable renaming through Sysmon `OriginalFileName`; this PE metadata is forgeable and not cryptographic identity proof.
- Alert descriptions claim upload syntax/attempt, not completed transfer.

## DNS redesign

`rules/dns_exfiltration_detection.xml` now contains four layers:

```text
100533 / level 5  — atomic long hex or RFC 4648 Base32-compatible label
100534 / level 12 — sequenced framed encoded transport
100535 / level 11 — PowerShell acquisition + encoding + chunking + DNS combined behavior
100546 / level 12 — nine encoded-label events from one process in 15 seconds
```

The retained 2026-08-06 DNS corpus was measured before selecting the burst threshold:

```text
DNS Client Event 3006 records examined: 6,901
Unique query names:                    193
Atomic encoded-label candidates:       26 events / 21 unique names
Validated exfiltration bursts:          8 matching labels in under 3 seconds
Closest observed benign burst:          4 matching events in 15 seconds
```

The benign long-hex examples were Microsoft footprint DNS labels. That evidence is why `100533` was reduced to low-severity atomic visibility. Fresh WIN01 telemetry later showed two Event 3006 records per query, so `100546` now requires nine same-process events in fifteen seconds: four queries/eight records stay below threshold, while the ninth record occurs during the fifth query. The high-confidence burst no longer depends on the original session/sequence/total grammar. Rule `100534` remains as an additional high-confidence classifier for explicitly framed transports.

PowerShell rule `100535` now requires all of the following in one script block:

- `ReadAllBytes` or byte-oriented `Get-Content`;
- hexadecimal, Base64, `ToHexString`, or `BitConverter` encoding behavior;
- explicit `Substring` or range-based chunking followed by `Resolve-DnsName`, `nslookup`, or a .NET DNS API.

It is level 11 and described as combined behavior, not dataflow proof. Framed DNS and same-process bursts remain the level-12 layers.

## Independent-review remediation

An independent reviewer initially failed the change set on four blocking cases. All four were reproduced as regression fixtures and corrected:

```text
FTP upload + curl transfer reset/statement boundary + unrelated HTTPS GET -> no HTTP upload match
FTP WebClient upload + unrelated HTTPS PowerShell GET      -> no HTTP upload match
session.seq.total.normal.<encoded-label>.suffix             -> no framed DNS match
file backup encoding + unrelated normal DNS resolution      -> no 100535 match
alphabet-only RFC 4648 Base32-compatible label              -> atomic visibility supported
```

HTTP rules now bind the destination to the same curl transfer segment or PowerShell upload call. DNS `100534` validates the complete frame, and `100535` requires chunking before DNS behavior while making only a combined-behavior claim.

The frequency primitive was tested natively on the deployed Wazuh 4.14.6 manager with a temporary JSON rule pair: four matching same-field events selected only the base rule, and the fifth selected the correlation child with `frequency: 5`. That fixture established Wazuh's counting semantics before the production threshold was recalibrated to nine for duplicated live Event 3006 telemetry. The temporary rules file was removed automatically. The corpus calculation is now reproducible with:

```text
python3 tests/analyze_dns_exfiltration_corpus.py /path/to/ossec-archive.json
```

## Regression evidence

`tests/test_rule_hardening.py` was extended before XML edits. The new tests failed against the old rules, then passed after the redesign.

Final local result:

```text
17 tests run
17 passed
```

Coverage includes:

- quoted paths containing spaces;
- curl long-option `=` syntax;
- `--upload-file` and `-T`;
- inline `--data-binary` exclusion;
- destination-extension and cross-transfer URL drift exclusions;
- PowerShell IWR, WebClient, BITS, and HttpClient upload APIs, including unrelated-URL exclusions;
- rename-resistant curl metadata structure;
- hex and RFC 4648 Base32-compatible DNS labels;
- complete framed-label positioning;
- nine-event DNS burst structure and same-process correlation;
- legitimate HTTP uploads before and after curl `--next` boundaries;
- normal DNS, unrelated backup/DNS behavior, and HTTP GET/inline-body boundaries.

The deployed Wazuh 4.14.6 PCRE2 engine passed eleven temporary native fixtures for the pre-review candidate: five positives and six matched adversarial negatives covering curl transfer resets and PowerShell statement boundaries, unrelated PowerShell URLs, displaced DNS frame labels, and unrelated backup encoding/DNS behavior. The temporary rules files were removed after the parser/logtest runs. The final segment-aware HTTP regex passed `wazuh-analysisd -t`, deployed with rollback protection, and then passed focused live endpoint positives and a cross-transfer negative.

All 26 versioned XML files parsed successfully and all 139 rule IDs were unique.

## Deployment evidence

The two previous deployed files were backed up before replacement. The first candidate write retained `root:root` ownership while changing mode to `0640`, which made the files unreadable to analysisd. This was detected by `wazuh-analysisd -t` warnings before restart. Ownership was corrected to the manager's standard `root:wazuh` with mode `0640`, then parser validation passed.

Initial redesign deployed/repository SHA-256 values before live-telemetry corrections:

```text
http_exfiltration_detection.xml 40087d25e01012f70a6c4b2be76a632303ceba2c03cdd58fa22b720942d712e4
dns_exfiltration_detection.xml  e5927a27583ee33c67baf07e46e848f5ad8f11d2acf4bd390ad7820f3bc56f37
```

Current repository SHA-256 values after live corrections and the post-review HTTP boundary fix:

```text
http_exfiltration_detection.xml d8b4589151822c93be48e169a7dd1971e0a165c3ca58d9d995ffb91373711258
dns_exfiltration_detection.xml  57b862127e68863d492d4290002660f98addef2d154f8451aa6708686fd2653d
```

Repository and manager hashes are equal for both files. All four final HTTP/DNS/CMD/LSASS rule files are `root:wazuh:0640`, and the final manager parser check passed.

After restart:

```text
wazuh-manager:   active
analysisd:       running
remoted:         running
logcollector:    running
monitord:        running
modulesd:        running
WIN01 agent 004: Active
```

## Fresh live closure

Authenticated endpoint execution subsequently closed the earlier transport limitation.

### HTTP

- A controlled receiver accepted both test files with matching byte counts and SHA-256 values.
- Live Security 4688 used parent `67027`; live PowerShell 4104 used both `91816` and base `91802` paths.
- `100545` selected the environment-variable/staging upload block; `100547` selected the base-parent literal IWR upload block. Split base-path staging rule `100548` preserves the corresponding higher-severity path.
- Pure GET/version/inline-body and cross-transfer FTP/`--next` controls produced telemetry without custom HTTP alerts.
- Escaped quote serialization (`\"http://...\"`) was incorporated without broadening statement or transfer boundaries.

Focused post-review curl `--next` closure used direct authenticated WinRM execution on WIN01 and the controlled Kali receiver:

```text
Upload before --next / environment-variable path:
  source and receiver: 19 bytes / 1ac669752234ffcfc0f4698ef52507324694fc9d847a9d5be7663f5a30deac81
  PowerShell 4104:     record 200129 -> rule 100532 level 10
  Security 4688:       record 47265  -> rule 100531 level 12
  Sysmon Event 1:      record 69875  -> rule 100544 level 10

Upload after --next / base-parent path:
  source and receiver: 20 bytes / 88f5c93ca9eb2cf593f77e543b9c5897532bd96f82f71700dba75ee5abb08970
  PowerShell 4104:     record 200146 -> rule 100547 level 10
  Security 4688:       record 47270  -> rule 100531 level 12
  Sysmon Event 1:      record 69886  -> rule 100544 level 10

FTP upload before --next plus unrelated HTTPS GET:
  PowerShell 4104:     record 200162 -> built-in rule 91816 only
  custom HTTP rules:   none
  receiver upload:     none
```

All three endpoint source files were removed by their test commands. The first native-parser candidate was rejected before restart and automatically rolled back; the corrected candidate then passed parser validation, manager restart, agent-health, ownership/mode, and hash-equality gates. A final independent review added PowerShell 7 `&&`, `||`, and pipeline boundaries to the same curl segment grammar. Those boundaries have explicit negative regressions; semantic candidate `c694eb8fc9f168fef0aeb07598a1a39cf6549c3e0d5de3bdcc8fdd7701fe073c` passed the native parser, deployment, restart, hash, and agent-health gates. The repository hash above differs only by a follow-up XML comment documenting the remaining `--next` token-boundary focus. WIN01 runs PowerShell 5.1, so the preserved live records exercise the unchanged curl `--next` positive behavior while the PowerShell 7-only separators are covered by deterministic regex fixtures.

### DNS

- Fresh combined PowerShell behavior selected `100535` (record `198313`).
- Framed DNS Client events selected `100534`, including records `323757`–`323839`.
- The correct live Windows informational parent is `60009`; `64100` is an unrelated File Replication parent and was removed.
- WIN01 emitted duplicate Event 3006 records per query. Rule `100546` was recalibrated to nine events: four unique queries/eight records produced zero burst alerts; five unique queries/ten records produced one `100546` alert at record `324413`.
- Ordinary DNS and displaced framing produced no high-confidence framed/combined alert; isolated encoded labels remain intentionally visible only through atomic level-5 `100533`.

The prior endpoint closure remains valid evidence for the rules exercised at that time. The post-review HTTP segment fix is now closed by native parser/deployment checks, two focused positives, receiver byte/hash equality, and a cross-transfer false-positive boundary. DNS required no further rule change from this review.
