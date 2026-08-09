# WinPEAS validation result — 2026-08-03

## Verdict

**PASS** — direct known-name detection and rename-resistant discovery behavior both fired.

## Execution

- Endpoint: WIN01 / Wazuh agent `004`
- Identity: controlled low-privilege `SIMULATION\yassine.karimi`
- Direct binary: `winPEASx64.exe`
- Renamed binary: `Downloads\a.exe`
- Temporary output: removed

## Live evidence

```text
100470 / level 10 — known WinPEAS executable execution
100471 / level 10 — user-writable executable spawned discovery child
```

These are the historical alert levels observed during the 2026-08-03 run. The 2026-08-09 robustness pass lowered `100471` to level 8 because one discovery child is candidate behavior, and retained telemetry did not support a frequency child.

Renamed behavior proof:

```text
Parent: Downloads\a.exe
Child:  C:\Windows\System32\systeminfo.exe
Security Event: 4688
Native parent rule: 67027
Record: 25346
Timestamp: 2026-08-03T15:39:50.8969855Z
```

Rule `100471` also includes `netsh.exe` after live telemetry showed wireless-profile discovery. Filename-specific masquerade exceptions were not added.

## Artifacts

```text
rules/winpeas_detection.xml
tests/winpeas_cmd.md
```
