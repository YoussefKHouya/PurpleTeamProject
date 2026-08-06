# DNS credential-file exfiltration — 2026-08-06

## Verdict

```text
Eight DNS chunks: PASS
Reconstructed bytes: 187
SHA-256 integrity: PASS
Rule 100534: PASS
Rule 100535: PASS
Normal DNS false-positive test: PASS
Overall: COMPLETE / PASS
```

The Yassine PowerShell session hex-encoded the controlled credential file and sent eight ordered DNS queries directly to the bounded Kali receiver. Kali reconstructed 187 bytes with SHA-256 `d3968bd4920f24b83f12f872edff1461d6ecb26d96a88021d60759a99cbf0296`, exactly matching the HTTP/source artifact.

Wazuh rule `100534` fired at level 12 on all eight DNS Client 3006 chunk queries, records `261665`, `261674`, `261683`, `261692`, `261701`, `261710`, `261719`, and `261728`. PowerShell rule `100535` fired at level 12 on 4104 record `159612`. Both map to T1048.003.

A normal `dc01.simulation.local` lookup produced DNS Client records `261737` through `261745` and no custom DNS-exfiltration alert. The receiver was stopped after validation.
