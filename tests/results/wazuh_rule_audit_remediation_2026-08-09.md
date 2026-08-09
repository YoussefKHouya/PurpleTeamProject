# Wazuh rule audit remediation — 2026-08-09

## Scope

This pass implements only the seven approved Claude-audit corrections:

1. repair LSASS allowlist/suppression escaping in rules `100421` and `100427`;
2. repair the UNC-share branch in CMD rule `100312`;
3. restore deployed AS-REP RC4 rule `100414` to version control;
4. remove stale WinPEAS `100472` claims and lower single-child candidate rule `100471` from level 10 to level 8;
5. remove dead Unix raw-audit parent `100200`, retaining normalized JSON parent `100201`.

MSSQL rule `100541` and adPEAS parent `91823` were deliberately not changed because retained live evidence disproved those audit recommendations.

## Test-driven proof

Five new regression tests failed before the rule edits for the expected reasons:

- real single-backslash benign LSASS paths did not match the `100421`/`100427` expressions;
- real `\\host\share` syntax did not match rule `100312`;
- repository rule `100414` was absent;
- `100471` remained level 10 and its header referenced `100472`;
- dead rule `100200` remained defined.

After remediation:

```text
python3 -m unittest -v tests.test_rule_hardening
Ran 17 tests
OK

XML_PARSE=PASS 26
DUPLICATE_IDS=PASS 137
git diff --check: PASS
```

The CMD regression also exposed a second boundary defect in the approved UNC branch: `\b` cannot terminate `IPC$` or `ADMIN$`. The final expression uses `(?=\\|\s|$)`, preserving subpaths and matching dollar-suffixed share names without accepting unrelated shares.

## Native Wazuh PCRE2 fixtures

Temporary rules were loaded on Wazuh `4.14.6`; `wazuh-analysisd -t` passed. The temporary file was removed automatically.

```text
100421 wmiprvse benign path         PASS / match
100427 svchost benign path          PASS / match
100312 \\dc01\SYSVOL                PASS / match
100312 \\dc01\ADMIN$                PASS / match
100312 \\fileserver\Public          PASS / no match
100414 ticketEncryptionType 0x17   PASS / match
100414 ticketEncryptionType 0x12   PASS / no match
```

Historical manager alerts also preserve three genuine RC4 child selections for rule `100414`: Event 4768 records `20682`, `20683`, and `20689`, all level 12 with `ticketEncryptionType=0x17`.

## Deployment

The five corrected rule files were backed up and deployed to `/var/ossec/etc/rules/` with owner/group `root:wazuh` and mode `0640`:

```text
backup suffix: .bak.auditfix.20260809T131833Z

lsass_credential_dump_detection.xml bf32d706b93f69404e839cfdcb64e8da5a1df61efb2a8f55df961e75c2a1b6f9
cmd_detection.xml                  78f8fed97cd2e93a1405757ff73d806037c27b807a46287c50d67c36eeab0c1c
asrep_roasting_detection.xml       42253ac32e3ed1b9188ab7713ab9a23ac2e508900f479a979f4c72dd12018aa2
winpeas_detection.xml              db06d7aeae5fd80d5810adf8267ee1363f695555904becd85146dcb61b681fbd
unix_shell_detection.xml           22c3a421b343125a7b41158993354e2c537ca3f0d6e6d335862698cbd9c6e4fc
```

Manager parser, restart, service state, permissions, and deployed hashes passed.

## Limitation

WIN01 agent `004` was Active, but unattended endpoint execution was not proven: the existing lab wrapper returned no command output and the direct helper lacked the local `winrm` module. Therefore this pass claims native matcher and deployment validation, not a fresh endpoint alert replay. DC01 and the Linux agent were disconnected, so no new AS-REP or Unix-shell endpoint event was generated.
