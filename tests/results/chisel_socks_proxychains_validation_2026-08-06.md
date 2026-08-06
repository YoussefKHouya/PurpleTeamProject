# Chisel reverse SOCKS and ProxyChains validation — 2026-08-06

## Verdict

```text
Pinned Chisel client: PASS
Low-user execution: PASS
Reverse SOCKS listener: PASS
ProxyChains through SOCKS: PASS
Bounded LDAP TCP connection: PASS
Wazuh rule 100526: PASS
Overall: COMPLETE / PASS
```

## Execution

The retained official Chisel v1.11.8 Windows artifact ran from a local medium-integrity `SIMULATION\\yassine.karimi` PowerShell session. Its SHA-256 remained `333e76e0f05b84035396f62990c8e84a31e23a5a43e99766f8d922c634f512e3`.

The client requested only `R:socks`. The pinned-source Kali server reported a reverse SOCKS listener on loopback TCP/1080. A temporary strict ProxyChains configuration then made one TCP connection through that SOCKS listener to the already-known domain controller LDAP service. ProxyChains reported the chain as `OK`, and the LDAP port accepted the TCP connection. No subnet scan, LDAP bind, credential use, or directory query occurred.

## Detection

The first execution coincided with a failed Wazuh manager state: `wazuh-remoted`, `wazuh-analysisd`, and `wazuh-logcollector` were not running. The manager was restarted and all required daemons returned active. A clean post-recovery rerun produced:

```text
Agent:          004 / WIN01
Identity:       SIMULATION\\yassine.karimi
Sysmon record:  55794
Rule:           100526
Level:          12
MITRE:          T1572
Client hash:    exact pinned SHA-256
Command shape:  client ... R:socks
alerts.json:    PASS
```

Rule `100526` already covered `R:socks` under the pinned-hash parent `100525`; no new custom rule was necessary. Its previous misleading-native-binary false-positive test remains authoritative for the hash gate.

Dashboard filter:

```text
agent.id:"004" AND rule.id:"100526" AND data.win.system.eventRecordID:"55794"
```

## Final state

The tracked Kali Chisel server and temporary SSH forwards were stopped. The temporary ProxyChains configuration was removed. Source/build artifacts and the WIN01 Chisel fixture remain retained for reproduction. The previously documented Defender exclusion rollback remains pending administrator action.