# Chisel reverse port-forward validation — 2026-08-06

## Verdict

```text
Pinned official source/build: PASS
Low-user genuine execution: PASS
Reverse tunnel connected: PASS
End-to-end RDP negotiation: PASS
Rule 100525 known-build execution: PASS
Rule 100526 client tunnel syntax: PASS
Misleading native-binary negative: PASS
Process/server shutdown: PASS
Defender exclusion rollback: PENDING ADMINISTRATOR
Overall: PASS WITH EXCLUSION ROLLBACK PENDING
```

## Provenance

```text
Release: v1.11.8
Commit: 310eec3696e82ef14048268d1d12f1cd99d6dbe9
Windows SHA-256: 333e76e0f05b84035396f62990c8e84a31e23a5a43e99766f8d922c634f512e3
Kali Linux AMD64 SHA-256: 292820f6188ddaba744c36042c3139f8c090902f175e6098075f7c3014844c7f
Go tests: PASS
```

## Behavior proof

Genuine Chisel ran as medium-integrity `SIMULATION\yassine.karimi`. Client connected to the Kali server and requested a loopback-only reverse mapping from Kali `127.0.0.1:18089` to WIN01 `127.0.0.1:3389`. A bounded RDP negotiation through the forwarded port returned 19 bytes:

```text
030000130ed00000123400021f080002000000
```

Sysmon Event 1 record `53901` and Security 4688 record `40614` preserve the genuine client command and pinned hash. No SOCKS proxy, subnet routing, persistence, credential capture, or interactive RDP session occurred.

## Rules

```text
100525 / level 10: pinned Chisel SHA-256, filename independent
100526 / level 12: child rule requiring Chisel client plus forward/reverse syntax
MITRE: T1572
Rule file SHA-256: ed58a1c23a9bf3d4e476ba5dbbabab610678eaff5766998c16277a2e486ba6d7
```

Live retests:

```text
100526: Sysmon record 53950, renamed relay-service.exe client tunnel syntax
100525: Sysmon record 53962, renamed relay-service.exe --version
Negative: Sysmon record 53952, whoami.exe with identical-looking syntax, no custom alert
```

Manager syntax test, restart, deployed/repository hash comparison, and agent health passed.

## Final state

Endpoint Chisel processes and tracked Kali server were stopped and verified absent locally where observable. Source and build artifacts remain on Pi/Kali. The operator-added Defender exclusion remains pending removal because the low-user WinRM context cannot modify Defender preferences.
