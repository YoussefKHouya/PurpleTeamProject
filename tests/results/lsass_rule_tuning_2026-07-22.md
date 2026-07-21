# LSASS Detection Rule Tuning Validation — 2026-07-22

## Scope

Tune Wazuh LSASS-memory detections for WIN01 without weakening ATT&CK T1003.001 coverage.

Rule source:

```text
rules/lsass_credential_dump_detection.xml
```

Deployed manager path:

```text
/var/ossec/etc/rules/lsass_credential_dump_detection.xml
```

## Baseline noise

Historical alerts for agent `004` showed:

| Rule | Source / access | Count |
|---|---|---:|
| 100422 | svchost.exe / 0x1000 | 639 |
| 100422 | VBoxService.exe / 0x1400 | 416 |
| 100422 | MsMpEng.exe / 0x1000 | 122 |
| 92900 | MsMpEng.exe / 0x101000 | 15 |
| 92900 | svchost.exe / 0x101000 | 10 |
| 100421 | wmiprvse.exe / 0x1410 | 6 |
| 100421 | wazuh-agent.exe / 0x1fffff or 0x1410 | 4 |

Built-in rule `92900` uses an unanchored `0x1010` expression, causing `0x101000` to match as a substring.

## Changes

1. Removed generic rule `100422` level-5 alerting. Built-in Sysmon Event 10 handling remains available at level 0.
2. Added exact full-path exclusions to rule `100421` for observed trusted system readers only.
3. Added rule `100426` level 0 to suppress built-in rule `92900` when `GrantedAccess` is exactly `0x101000`.
4. Added rule `100427` level 0 for exact-path `svchost.exe` and Defender `MsMpEng.exe` with exact `0x1010` or `0x40` access.
5. Preserved rules `100420`, `100423`, `100424`, and `100425` unchanged.
6. Used anchored full paths so a renamed process outside the trusted location does not inherit an exclusion.

## Validation

```text
XML parse: PASS
Duplicate repository rule IDs: none
wazuh-analysisd syntax test: PASS
wazuh-manager service: active
Repository/deployed SHA-256:
5049bb2aea4b1c47f9068be9f1c2eae7b6d3122f4cdbda385ffd55a33529fc8e
```

### False-positive tests

| Sysmon record | Source | Access | Wazuh result |
|---:|---|---|---|
| 5377 | `C:\Windows\system32\wbem\wmiprvse.exe` | `0x1410` | no alert |
| 5405 | `C:\Windows\system32\wsmprovhost.exe` | `0x101000` | no alert; substring false positive removed |
| 5446 | `C:\Windows\System32\VBoxService.exe` | `0x1400` | no alert |
| 5454 | `C:\Windows\system32\svchost.exe` | `0x1000` | no alert |

### Positive control

A handle was opened to LSASS with `0x1010` and immediately closed. No memory was read and no dump was created.

```text
Sysmon Event 10 record: 5384
Source: C:\Windows\system32\wsmprovhost.exe
Target: C:\Windows\system32\lsass.exe
GrantedAccess: 0x1010
Wazuh rule: 92900
Level: 12
MITRE: T1003.001
Result: PASS
```

### Existing Mimikatz evidence

Before tuning, Mimikatz generated confirmed process and LSASS-access evidence:

```text
Security 4688 records: 17965, 18001, 18022
Rule: 100425
Level: 13

Sysmon Event 10 records: 5017, 5020, 5055
Rule: 92900
Level: 12
GrantedAccess: 0x1010
```

## Residual limitation

No new exact-path `MsMpEng.exe` or `svchost.exe` event with access `0x1010` occurred after final deployment, so rule `100427` received syntax/deployment validation but not a fresh live matching event. Rule `100426`, generic-noise removal, trusted WMI exclusion, and suspicious `0x1010` retention were all live-tested.

## Verdict

PASS. High-confidence Mimikatz, ProcDump, renamed-tool command, suspicious LSASS access, dump-file, and comsvcs coverage remains. Observed high-volume benign LSASS-access alerts are removed.
