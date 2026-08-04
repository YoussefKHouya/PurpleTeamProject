# Process injection validation result — 2026-08-04

## Verdict

**PASS** — bounded LoadLibraryW injection, Sysmon Event 8 collection, custom alert, and cleanup were live-proven.

## Controlled behavior

```text
Source: powershell.exe
Target: temporary notepad.exe
DLL: C:\Windows\System32\version.dll
Mechanism: CreateRemoteThread -> LoadLibraryW
Callback/persistence: none
```

Successful trigger:

```text
WAZUH_PROCESS_INJECTION_PASS
PID: 1520
Thread: 3408
```

## Live evidence

```text
Sysmon Event ID: 8
Native chain: 60000 -> 60004 -> 61600 -> 61610
Custom final alert: 100479 / level 12
Timestamp: 2026-08-04T12:56:43.894+0000
Agent: 004 / WIN01
```

The generic parent `100478` is superseded by final child `100479` when `StartFunction=LoadLibraryA/W`. Archived JSON replay is not valid evidence for the live Windows event-channel parent chain.

## Cleanup

Remote memory was freed, handles were closed, and temporary Notepad was terminated by the test script.

## Artifacts

```text
rules/process_injection_detection.xml
tests/process_injection_cmd.md
tests/process_injection_event8.ps1
```
