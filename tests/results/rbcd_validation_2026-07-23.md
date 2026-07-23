# RBCD Wazuh Validation — 2026-07-23

## Final verdict

```text
Exploitation: PASS
Wazuh native detection: PARTIAL
Custom rules: PASS
False-positive tests: PASS after tuning
Cleanup: PASS
Overall: COMPLETE / PASS
```

## Scope

```text
Domain: SIMULATION.LOCAL
Operator: sofia.bennett
Controlled machine: RBCDCLIENT$
Target computer: OTDC01$
Target service: cifs/OTDC01.SIMULATION.LOCAL
Protected resource: \\OTDC01\RBCD-Target$
DC Wazuh agent: 001
OTDC01 Wazuh agent during impact proof: 005
Current OTDC01 Wazuh agent after clock repair/re-enrollment: 006
```

Sofia had one direct, non-inherited `GenericWrite` ACE on the OTDC01 computer
object. Sofia was not a Domain Admin, Enterprise Admin, built-in Administrator,
or OTDC01 local Administrator. The target share granted access only to local
Administrators.

## Preflight and fixes

Verified before rerun:

```text
Directory Service Changes auditing: Success
Computer Account Management auditing: Success
Kerberos Service Ticket Operations: Success and Failure
OTDC01 Logon auditing: initially disabled, corrected to Success and Failure
MachineAccountQuota: 10
RBCD attribute SACL: present for the exact attribute GUID
Wazuh manager: Active
DC01 agent 001: Active
OTDC01 agent: Active before attack
```

OTDC01 initially used `Local CMOS Clock` and was eight hours ahead. Its Windows
Time configuration was returned to the domain hierarchy, resynchronized with
DC01, and verified with leap indicator `0`. The stale future keepalive left old
agent `005` Pending after a manager restart. OTDC01 was re-enrolled as agent
`006`, which was Active at final verification. Historical indexed alerts from
agent `005` remain valid.

## Baseline impact gate

The same operation later used for impact proof was attempted as Sofia before
RBCD:

```text
Operation: list \\OTDC01\RBCD-Target$
Result: STATUS_ACCESS_DENIED
```

A successful SMB tree connection was not treated as access. Directory listing
was required.

## Positive attack validation

### 1. Controlled machine-account creation

```text
Event: 4741
DC record: 22312
Subject: sofia.bennett
Machine: RBCDCLIENT$
PrivilegeList: SeMachineAccountPrivilege
Wazuh rule: 100430
Level: 8
Result: PASS
```

The machine object's CreatorSID resolved to Sofia.

### 2. RBCD attribute write

```text
Event: 5136
DC record: 22320
Subject: sofia.bennett
Object: CN=OTDC01,CN=Computers,DC=SIMULATION,DC=LOCAL
Attribute: msDS-AllowedToActOnBehalfOfOtherIdentity
Operation: %%14674 / Value Added
Wazuh rule: 100431
Level: 12
Result: PASS
```

### 3. S4U2Self and S4U2Proxy

```text
S4U2Self:
  Event: 4769
  DC record: 22351
  Service: RBCDCLIENT$
  TicketOptions: 0x40810000
  Wazuh rule: 100400
  Level: 3

S4U2Proxy:
  Event: 4769
  DC record: 22352
  Service: OTDC01$
  TicketOptions: 0x40830000
  TransmittedServices: RBCDCLIENT$@SIMULATION.LOCAL
  Wazuh rule: 100432
  Level: 10
  Result: PASS
```

### 4. Protected-resource impact

The delegated CIFS ticket impersonated the domain RID-500 Administrator and
read the controlled protected file:

```text
RBCD_ACCESS=SUCCESS
File: readme.txt
Content: Administrative file-server target for the controlled RBCD detection lab.
```

Target telemetry:

```text
Event: 4624
OTDC01 record: 4986
Target SID: domain SID ending -500
Target user: SIMULATION.LOCAL\Administrator
Logon type: 3
Authentication package: Kerberos
TransmittedServices: RBCDCLIENT$@SIMULATION.LOCAL
Wazuh rule: 100434
Level: 12
Result: PASS
```

## False-positive tests

### Normal computer-object attribute modification

A temporary audit ACE captured a bounded change to OTDC01's `description`
attribute. The original value and SACL were restored.

```text
Event: 5136
Record: 22453
Attribute: description
Wazuh result: rule 60229 level 4
RBCD rules 100431/100436: no match
Result: PASS
```

### Legitimate computer provisioning

Before tuning, a Domain Administrator-created disabled computer account produced
record `22430` and incorrectly matched `100430` level 8. The rule was tuned to
require `PrivilegeList=SeMachineAccountPrivilege`.

Post-tuning retest:

```text
Low-privilege quota canary:
  Record: 22470
  Subject: sofia.bennett
  PrivilegeList: SeMachineAccountPrivilege
  Rule: 100430 level 8
  Expected alert: PASS

Administrative provisioning canary:
  Record: 22477
  Subject: Administrator
  PrivilegeList: absent / '-'
  Rule: 60121 level 5
  Rule 100430: no match
  False-positive test: PASS
```

### Ordinary Kerberos service ticket

```text
Event: 4769
Record: 22458
Requester: sofia.bennett
Service: OTDC01$
TicketOptions: 0x40810010
TransmittedServices: '-'
Wazuh rule: 100400 level 3
Rule 100432: no match
Result: PASS
```

### Normal Kerberos SMB logon

```text
Event: 4624
OTDC01 record: 4992
User: sofia.bennett
Logon type: 3
Authentication package: Kerberos
Target SID: domain SID ending -1118
TransmittedServices: '-'
Wazuh rule: 100433 level 3
Rule 100434: no match
Protected-share read: STATUS_ACCESS_DENIED
Result: PASS
```

Rule `100433` is intentional low-level visibility for remote 4624 events that
would otherwise be suppressed by built-in rule `92651`. It is not a high-severity
RBCD verdict.

## Cleanup behavior and tuning

Impacket `-action remove` removed the delegate ACE but rewrote an empty security
descriptor, generating a Value Deleted/Value Added pair:

```text
Record 22284: rule 100436 level 6
Record 22285: rule 100431 level 12
```

Because a real value was added back, this was not suppressed in rule logic.
Operational cleanup was changed to `-action flush`, which removes the attribute
instead of re-adding an empty descriptor. Rule `100431` wording was also changed
to the precise statement "RBCD attribute value added."

Final cleanup:

```text
Event: 5136
Record: 22481
Operation: %%14675 / Value Deleted
Wazuh rule: 100436
Level: 6
Result: PASS
```

Final state verification:

```text
msDS-AllowedToActOnBehalfOfOtherIdentity: absent
RBCDCLIENT$: absent
RBCD-CANARY$: absent
RBCD-FP-ADMIN2$: absent
Temporary tickets and generated passwords: removed
Post-cleanup Sofia protected-share read: STATUS_ACCESS_DENIED
Wazuh manager: Active
DC01 agent 001: Active
OTDC01 agent 006: Active
```

## Final deployed rules

```text
100430 level 8  — quota-based human-created computer-account precursor
100431 level 12 — RBCD attribute value added
100432 level 10 — S4U2Proxy ticket pattern
100433 level 3  — remote 4624 visibility rescue
100434 level 12 — delegated RID-500 Kerberos network logon
100436 level 6  — RBCD attribute value removed
```

Rule file:

```text
rules/rbcd_detection.xml
```

Final local/manager SHA-256:

```text
81a0cc800601459fc12f631335c9959bbb107549566b3fa353ec733447d0723e
```

Wazuh configuration validation passed, the manager remained Active, and local
and deployed checksums matched.

## Artifacts

```text
rules/rbcd_detection.xml
tests/RBCD_cmd.md
tests/results/rbcd_validation_2026-07-23.md
PROJECT_CONTEXT.md
```

No passwords, machine secrets, Kerberos tickets, hashes, or private routing
details are stored in these artifacts.
