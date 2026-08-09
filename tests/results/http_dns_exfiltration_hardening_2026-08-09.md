# HTTP and DNS exfiltration rule hardening — 2026-08-09

## Verdict

```text
Historical attack/receiver integrity evidence: PRESERVED / PASS
Rule redesign:                              PASS
Regression fixtures:                        PASS (12 tests)
XML parse and duplicate-ID check:            PASS
Manager parser and restart health:           PASS
Deployed/repository hash equality:            PASS
Fresh local-endpoint positive retest:         PENDING / management transport unavailable
Fresh false-positive retest:                  PENDING / management transport unavailable
Overall hardening status:                     DEPLOYED / LIVE RETEST PENDING
```

This pass strengthens the detectors without rewriting the original 2026-08-06 attack evidence. The historical reports remain authoritative for successful receiver byte/hash proof. New rule behavior is not called live-proven until the updated playbook is executed from the genuine local low-user Windows shell.

## Branch review

Work was already on `hardening/wazuh-rule-robustness`, tracking the same remote branch. Before this pass, the remote hardening branch was two commits ahead of `origin/main` and zero commits behind.

The branch is broader than only Chisel and Seatbelt. Its existing two commits also change ADPEAS, CertiGhost, process-injection severity/claims, dashboard queries, README/context, and add `tests/test_rule_hardening.py`. Chisel and Seatbelt are the largest structural changes:

- Chisel adds hash-independent tunnel-behavior visibility while keeping named-tool attribution under pinned-hash children.
- Seatbelt separates module-independent authentic PE metadata from the exact bounded module classifier.
- Regression tests enforce both attribution boundaries.

No merge to `main` was performed.

## HTTP redesign

`rules/http_exfiltration_detection.xml` now contains five layers:

```text
100530 / level 10 — Security 4688 curl local-file upload syntax
100531 / level 12 — sensitive immediate source-file argument
100532 / level 10 — PowerShell curl/IWR/IRM/WebClient/BITS/HttpClient upload behavior
100544 / level 10 — rename-resistant curl OriginalFileName metadata plus upload syntax
100545 / level 11 — credential-like staging and an HTTP/S upload call co-occur in one script block
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
100546 / level 12 — five encoded labels from one process in 15 seconds
```

The retained 2026-08-06 DNS corpus was measured before selecting the burst threshold:

```text
DNS Client Event 3006 records examined: 6,901
Unique query names:                    193
Atomic encoded-label candidates:       26 events / 21 unique names
Validated exfiltration bursts:          8 matching labels in under 3 seconds
Closest observed benign burst:          4 matching events in 15 seconds
```

The benign long-hex examples were Microsoft footprint DNS labels. That evidence is why `100533` was reduced to low-severity atomic visibility and why `100546` requires five same-process events in fifteen seconds. The high-confidence burst no longer depends on the original session/sequence/total grammar. Rule `100534` remains as an additional high-confidence classifier for explicitly framed transports.

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

The frequency semantics were also tested natively on the deployed Wazuh 4.14.6 manager with a temporary JSON rule pair: four matching same-field events selected only the base rule, and the fifth selected the correlation child with `frequency: 5`. The temporary rules file was removed automatically. The corpus calculation is now reproducible with:

```text
python3 tests/analyze_dns_exfiltration_corpus.py /path/to/ossec-archive.json
```

## Regression evidence

`tests/test_rule_hardening.py` was extended before XML edits. The new tests failed against the old rules, then passed after the redesign.

Final local result:

```text
12 tests run
12 passed
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
- five-event DNS burst structure and same-process correlation;
- normal DNS, unrelated backup/DNS behavior, and HTTP GET/inline-body boundaries.

The deployed Wazuh 4.14.6 PCRE2 engine also passed eleven temporary native fixtures: five positives and six matched adversarial negatives covering curl transfer resets and PowerShell statement boundaries, unrelated PowerShell URLs, displaced DNS frame labels, and unrelated backup encoding/DNS behavior. The temporary rules files were removed after the parser/logtest runs.

All 26 versioned XML files parsed successfully and no duplicate rule IDs were found.

## Deployment evidence

The two previous deployed files were backed up before replacement. The first candidate write retained `root:root` ownership while changing mode to `0640`, which made the files unreadable to analysisd. This was detected by `wazuh-analysisd -t` warnings before restart. Ownership was corrected to the manager's standard `root:wazuh` with mode `0640`, then parser validation passed.

Final deployed/repository SHA-256 values:

```text
http_exfiltration_detection.xml 40087d25e01012f70a6c4b2be76a632303ceba2c03cdd58fa22b720942d712e4
dns_exfiltration_detection.xml  e5927a27583ee33c67baf07e46e848f5ad8f11d2acf4bd390ad7820f3bc56f37
```

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

## Live-retest limitation

The endpoint agent is active, but the available unattended management transports were closed from the manager-side route. RDP remained reachable, but this pass did not hijack an interactive desktop session or weaken endpoint firewall policy merely to force a test.

A historical EventChannel `full_log` replay was also rejected as completion evidence: `wazuh-logtest` decoded the archived JSON as generic `json`, not the live Windows EventChannel parent chain. It was not counted as a rule PASS.

Fresh positives and false-positive tests therefore remain explicit pending gates. Run the updated one-line controls in:

```text
tests/http_exfiltration_cmd.md
tests/dns_exfiltration_cmd.md
```

Required closure order:

```text
local endpoint trigger -> archives.json -> updated custom alert -> indexed document -> false-positive tests
```
