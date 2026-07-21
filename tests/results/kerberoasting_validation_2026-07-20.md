# Kerberoasting Detection Validation — 2026-07-20

## Scope

Evidence-first validation of Domain Controller Event ID 4769 collection and targeted T1558.003 Kerberoasting detection. No password cracking or credential reuse was performed.

## Environment

- Domain controller: Windows Server 2022, Wazuh agent v4.14.6
- Wazuh manager: v4.14.6
- Required audit subcategory: `Kerberos Service Ticket Operations`
- Audit state: Success and Failure
- DC Security channel collector: `eventchannel`; Event ID 4769 is not excluded
- Raw Wazuh archives: disabled (`logall_json=no`)

## Collection-gap diagnosis

Historical DC sequence:

| Record | Requester class | Source class | Encryption | Wazuh result |
|---:|---|---|---:|---|
| 19619 | DC machine account | IPv6 loopback | 0x12 | 60106 / level 3 |
| 19620 | DC machine account | IPv6 loopback | 0x12 | 60106 / level 3 |
| 19621 | ordinary domain user | IPv4-mapped remote | 0x12 | missing |
| 19622 | ordinary domain user | IPv4-mapped remote | 0x17 | missing |

Manager queues showed `discarded_count=0` and `events_dropped=0`.

Root cause: built-in Wazuh rule `92651` is a level-0 child of `60106`. It matches a non-loopback IPv4 value in `win.eventdata.ipAddress` but does not restrict the event to Event ID 4624. IPv4-mapped remote Event 4769 requests therefore entered rule `92651` and were silently suppressed. Loopback requests remained visible through rule `60106`.

## Rules deployed

Versioned source:

```text
rules/kerberoasting_detection.xml
```

Deployed manager file:

```text
/var/ossec/etc/rules/kerberoasting_detection.xml
```

Rules:

| Rule | Level | Purpose | MITRE |
|---:|---:|---|---|
| 100400 | 3 | Rescue successful Event 4769 from either 60106 or 92651 | none |
| 100401 | 9 | RC4 (`0x17`) service ticket for a non-machine, non-krbtgt service | T1558.003 |

The vendor rule file was not edited or overwritten. The prior typo-named manager file was backed up and removed from active rule loading.

## Deployment validation

- Local XML parse: PASS
- Local rule-ID collision check: PASS
- Manager `wazuh-analysisd -t`: PASS
- Deployed owner/group: `wazuh:wazuh`
- Deployed mode: `660`
- Manager backup created: YES
- Manager restart: PASS
- Manager active after restart: PASS

## Live positive test

One targeted TGS request was made for the controlled `svc_sql` account through a remote IPv4 path.

Attack-side result:

```text
targeted_ticket_obtained=true
ticket_material_deleted=true
```

DC evidence:

```text
Event ID: 4769
Record ID: 19850
ServiceName: svc_sql
TicketEncryptionType: 0x17
Status: 0x0
Source: IPv4-mapped remote address
```

Wazuh evidence:

```text
Record ID: 19850
Rule ID: 100401
Level: 9
MITRE: T1558.003
ServiceName: svc_sql
TicketEncryptionType: 0x17
Status: 0x0
```

Result: **PASS** — remote RC4 Event 4769 was collected and produced the intended T1558.003 alert. Rule 100401 can only fire as a child of rule 100400, proving the rescue path matched.

### Controlled requester confirmation

A second targeted request used the controlled ordinary domain account `yassine.karimi` against `svc_sql`. Its stored lab credential was read from the ignored mode-600 access file. A process-local clock offset corrected the Pi/DC Kerberos skew without changing either system clock.

Attack-side result:

```text
requester=yassine.karimi
target=svc_sql
targeted_ticket_obtained=true
ticket_material_deleted=true
```

DC evidence:

```text
Event ID: 4769
Record ID: 19872
Requester: yassine.karimi@SIMULATION.LOCAL
ServiceName: svc_sql
TicketEncryptionType: 0x17
Status: 0x0
Source: IPv4-mapped remote address
```

Wazuh evidence:

```text
Record ID: 19872
Rule ID: 100401
Level: 9
MITRE: T1558.003
Requester: yassine.karimi@SIMULATION.LOCAL
ServiceName: svc_sql
TicketEncryptionType: 0x17
Status: 0x0
```

Result: **PASS** — the original requester-specific visibility problem is fixed and live-proven.

### Manual follow-up visibility

Subsequent manual requests from the Windows client were also present in both the DC Security log and Wazuh alerts:

| DC record | Service | Encryption | Wazuh rule | Result |
|---:|---|---:|---:|---|
| 19879 | WIN01$ | 0x12 | 100400 / level 3 | PASS generic remote AES visibility |
| 19880 | svc_sql | 0x17 | 100401 / level 9 | PASS T1558.003 detection |
| 19881 | svc_sql | 0x17 | 100401 / level 9 | PASS T1558.003 detection |
| 19931 | svc_backup | 0x17 | 100401 / level 9 | PASS Omar requester / alternate SPN detection |

A bounded alternate-user test used `omar.rahmani` to request exactly one ticket for controlled account `svc_backup` (`HTTP/web.SIMULATION.LOCAL:80`). Ticket extraction returned RC4 marker `23`; material was deleted immediately. DC record `19931` contained requester `omar.rahmani@SIMULATION.LOCAL`, service `svc_backup`, encryption `0x17`, status `0x0`, and an IPv4-mapped remote source. Wazuh matched rule `100401`, level 9, MITRE `T1558.003`.

A deliberate two-request level split then used `yassine.karimi`:

| Order | DC record | Target | Encryption | Wazuh result |
|---:|---:|---|---:|---|
| 1 | 19952 | DC01$ via `HOST/DC01.SIMULATION.LOCAL` | 0x12 | 100400 / level 3 / no MITRE |
| 2 | 19953 | svc_sql | 0x17 | 100401 / level 9 / T1558.003 |

Exactly two Event 4769 records were generated. This live test proves the intended distinction: normal AES machine-service visibility remains low severity, while an RC4 user-backed service ticket escalates to the Kerberoasting rule. Both ticket artifacts and the temporary runner were deleted.

At `2026-07-20T15:45:29Z`, no newer Yassine Event 4769 existed on the DC after record 19881 at `15:39:22Z`. A repeated client action therefore did not contact the KDC, likely because an existing service ticket was reused from cache. This is not a Wazuh miss.

### Clock correction

The DC used `Pacific Standard Time`, causing its local display to differ from the Casablanca lab by eight hours. Its timezone was changed to `Morocco Standard Time`. Because the DC uses `Local CMOS Clock`, the timezone change initially preserved the old wall-clock value and shifted UTC; this was immediately corrected against the synchronized Pi clock. Final verification:

```text
DC zone: Morocco Standard Time
DC local: 17:03 +01:00
DC UTC: 16:03:14Z
Pi UTC: matched within one second
NTDS: Running
KDC: Running
W32Time: Running
WazuhSvc: Running
DC time source: Local CMOS Clock (unchanged)
```

Wazuh manager clock was initially roughly eight minutes slow despite healthy chrony sources. `chronyc tracking` reported approximately 470 seconds slow; startup-only `makestep 1.0 3` had expired, so chrony was slewing the large offset. A controlled `chronyc makestep` corrected it. Final manager time matched the synchronized Pi within approximately 0.22 seconds; chrony reported `0.000000000 seconds slow`, normal leap status, and active healthy sources. Wazuh manager, Filebeat, indexer, dashboard, and chronyd remained active.

## Non-blocking residual validation

Kerberoasting is complete for roadmap progression. Remaining hardening work:

1. Live RC4 machine-account ticket expected not to trigger rule 100401.
2. Wider benign RC4 service-account sampling to measure false positives.
3. Optional burst/correlation rule for one requester targeting several SPNs in a short window.

## Cleanup

- Extracted TGS material: deleted
- Temporary Kerberos cache: absent
- Temporary local test scripts: deleted
- Temporary SSH tunnel: closed after peer timeout
- Password cracking: not performed
- Credential reuse/lateral movement: not performed

## Current verdict

**COMPLETE FOR ROADMAP PROGRESSION**

DC Event 4769 collection, generic remote AES visibility, targeted RC4 Kerberoasting detection, two controlled requesters, two controlled service accounts, MITRE mapping, and cleanup are live-proven. RC4 machine-account exclusion, wider benign RC4 sampling, and burst correlation remain documented non-blocking hardening work.
