# Microsoft Defender preference tampering validation

## Rule file

`rules/defender_tampering_detection.xml`

## Prerequisites

- Run in an Administrator PowerShell session on WIN01.
- WIN01 agent `004` must collect PowerShell Operational 4104 events.
- Use only the dedicated controlled path below.

## Positive test

```powershell
$p='C:\ProgramData\DefenderTamperLab';New-Item -ItemType Directory -Path $p -Force|Out-Null;Add-MpPreference -ExclusionPath $p;if((Get-MpPreference).ExclusionPath -contains $p){"DEFENDER_TAMPER=SUCCESS exclusion=$p"}else{"DEFENDER_TAMPER=BLOCKED"}
```

Expected when the security-reducing change succeeds: custom rule `100536`, level 10, MITRE `T1562.001`.

## False-positive test

```powershell
(Get-MpPreference).DisableRealtimeMonitoring;'DEFENDER_READONLY_FP_DONE'
```

Expected: PowerShell telemetry but no rule `100536`, because the command only reads Defender state.

## Dashboard

```text
agent.id:"004" AND rule.id:"100536"
```

## Cleanup

```powershell
$p='C:\ProgramData\DefenderTamperLab';Remove-MpPreference -ExclusionPath $p;Remove-Item $p -Recurse -Force -ErrorAction SilentlyContinue;if((Get-MpPreference).ExclusionPath -contains $p){'DEFENDER_CLEANUP=FAILED'}else{'DEFENDER_CLEANUP=PASS'}
```
