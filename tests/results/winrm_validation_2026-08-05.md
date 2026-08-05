# WinRM validation — 2026-08-05

## Verdict

```text
Admin authentication/transport:      PASS
Atomic remote command execution:     PASS
Identity/marker proof:                PASS
Security/Sysmon process chain:        PASS
Wazuh high-signal detection:         PASS
Authentication-only false positive:  PASS
Cleanup:                              PASS
Defender prevention coverage:        NOT TESTED — operator left protection disabled
Overall: COMPLETE / PASS
```

## Preflight

At `2026-08-05T18:20:02.2172274Z`:

```text
Identity: SIMULATION\Administrator
Marker: absent
WazuhSvc: Running
Security Process Creation auditing: Success
```

Credentials were read from an ignored fixture and passed in memory to encrypted
WinRM transport. No password appeared in argv, files, Git, reports, or endpoint
process telemetry.

## Atomic execution

The WinRM command produced:

```text
UTC: 2026-08-05T18:20:12.2934714Z
Identity: SIMULATION\Administrator
Hostname: WIN01
PowerShell PID: 9100
Image: WindowsPowerShell\v1.0\powershell.exe
Transport marker: WinRM
Marker: C:\ProgramData\WazuhLab\winrm_20260805T1820Z.json
```

The one command wrote execution proof and exited. It made no account, service,
policy, firewall, registry, scheduled-task, payload-download, or persistence change.

## Endpoint evidence

```text
Security 4688 record 35871 — WinrsHost.exe -Embedding
Security 4688 record 35873 — WinrsHost.exe -> cmd.exe /C PowerShell
Security 4688 record 35874 — cmd.exe -> PowerShell -EncodedCommand
Sysmon Event 1 record 42711 — WinrsHost.exe -> cmd.exe
Sysmon Event 1 record 42712 — cmd.exe -> PowerShell
```

The marker's immediate PowerShell parent was `cmd.exe`; endpoint events prove
`WinrsHost.exe` was the upstream remote-management parent.

## Wazuh evidence

```text
2026-08-05T18:20:13.021+0000
  Rule 100331, level 12
  Security 4688 record 35873
  CMD launched PowerShell with an encoded command
  MITRE T1059.003, T1059.001, T1027

2026-08-05T18:20:13.052+0000
  Rule 100110, level 10
  Security 4688 record 35874
  PowerShell encoded command execution
  MITRE T1059.001, T1027
```

Supporting Wazuh evidence included rule `67027` for WinrsHost/conhost process
creation and rule `92052` for cmd.exe from abnormal parent `WinrsHost.exe`.
Existing rules detected the behavior at high severity; no custom rule was needed.

## False-positive test

From `2026-08-05T18:21:16.715920959Z` through
`2026-08-05T18:21:17.472615616Z`, the same credential performed only WinRM
authentication plus shell open/close. No command ran.

```text
67027: fired for WinrsHost.exe/conhost.exe — expected generic visibility
100331: 0
100110: 0
Marker: none
```

Thus normal authentication/shell establishment did not trigger encoded-command
rules.

## Cleanup and health

At `2026-08-05T18:21:58.6215465Z`:

```text
Marker: absent
WazuhLab directory: absent
WazuhSvc: Running
MpsSvc: Running
Defender real-time protection: disabled by explicit operator choice
```

Defender restoration remains a mandatory final batch-close gate and is not claimed
as healthy here.
