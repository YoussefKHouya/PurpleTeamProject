# Process Injection — Sysmon Event 8 validation

## Detection

- XML: `rules/process_injection_detection.xml`
- `100478` / level 10: any live Sysmon Event 8 inherited from native rule `61610`
- `100479` / level 12: Event 8 where `StartFunction` is `LoadLibraryA` or `LoadLibraryW`
- MITRE ATT&CK: `T1055`, `T1055.001`

## Prerequisites

WIN01 Sysmon active config must contain:

```xml
<CreateRemoteThread onmatch="exclude" />
```

WIN01 Wazuh agent must collect:

```xml
<localfile>
  <location>Microsoft-Windows-Sysmon/Operational</location>
  <log_format>eventchannel</log_format>
  <query>Event/System[EventID = 1 or EventID = 7 or EventID = 8 or EventID = 10 or EventID = 11]</query>
</localfile>
```

## Trigger

Run elevated PowerShell on disposable WIN01:

```powershell
& 'C:\Path\To\process_injection_event8.ps1'
```

The script creates temporary Notepad, writes the path of signed Windows `version.dll` into its memory, starts `LoadLibraryW` through `CreateRemoteThread`, closes handles, and terminates Notepad. No callback or persistence.

## Expected evidence

```text
Sysmon Event ID: 8
Native Wazuh parent: 61610
Custom selected alert: 100479 / level 12
SourceImage: powershell.exe
TargetImage: notepad.exe
StartModule: KERNEL32.DLL
StartFunction: LoadLibraryW
```

Dashboard filter:

```text
agent.id:004 AND rule.id:100479
```

Use a time range covering the trigger in UTC.

## Verified live result — 2026-08-04

```text
Trigger: WAZUH_PROCESS_INJECTION_PASS PID=1520 TID=3408
Agent: 004 / WIN01
Custom alert: 100479
Alert timestamp: 2026-08-04T12:56:43.894+0000
Manager alerts.json: PASS
Filebeat output/TLS/indexer connection: PASS
Cleanup: temporary Notepad terminated by script
```

## Root cause fixed

The archived `full_log` fixture decodes as generic `json` under `wazuh-logtest`, but the live endpoint event follows the Windows event-channel chain:

```text
60000 → 60004 → 61600 → 61610 → 100478 → 100479
```

Using `<decoded_as>json</decoded_as>` was valid only for the replay fixture and never matched the live chain. Searching only for `100478` also misses the final selected child alert: the higher-confidence event is emitted as `100479`.

Full result: `tests/results/process_injection_validation_2026-08-04.md`.
