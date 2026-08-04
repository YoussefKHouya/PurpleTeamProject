# WinPEAS Detection Validation

## Scope

Run on `WIN01` with the controlled low-privilege test account. The Wazuh agent must be Active and the manager must load:

```text
rules/winpeas_detection.xml
```

## Execute

Run the downloaded executable from the current user Downloads directory:

```powershell
& "$env:USERPROFILE\Downloads\winPEASx64.exe"
```

## Expected Wazuh evidence

```text
100470 / level 10 — named WinPEAS executable execution
100471 / level 10 — user-writable executable spawned a Windows discovery binary
```

A renamed executable is expected to bypass `100470` but still produce `100471` when it spawns a monitored discovery binary.

Verified evidence is recorded in:

```text
tests/results/winpeas_validation_2026-08-03.md
```

## Cleanup

Remove temporary WinPEAS output files created for the test. Keep or remove the downloaded executable according to the lab operator's decision.
