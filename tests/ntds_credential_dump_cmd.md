# NTDS IFM Detection Validation Commands

## Scope and identity

Run from an elevated PowerShell session on the controlled domain controller.
The validated host was `DC01`; Wazuh agent ID was `001`.

```powershell
$ExpectedHost = 'DC01'
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

## Preflight

```powershell
$Start = Get-Date
$OutputRoot = 'C:\ProgramData\WazuhLab\NTDS_IFM_CONTROLLED'

Get-Service NTDS, VSS, WazuhSvc |
    Select-Object Name, Status, StartType

Get-MpComputerStatus |
    Select-Object AMServiceEnabled,
                  AntivirusEnabled,
                  RealTimeProtectionEnabled,
                  IsTamperProtected

$ExistingShadows = @(Get-CimInstance Win32_ShadowCopy)
[pscustomobject]@{
    OutputAlreadyExists = Test-Path $OutputRoot
    ShadowCopyCount     = $ExistingShadows.Count
}

if (Test-Path $OutputRoot) {
    throw "Refusing to overwrite existing output: $OutputRoot"
}
```

Required gate:

```text
NTDS: Running
WazuhSvc: Running
Defender service/antivirus/real-time protection: enabled
Output root: absent
Existing shadow-copy state: recorded before execution
```

## Bounded IFM trigger over stdin

Commands are written to `ntdsutil.exe` standard input. This is the live-validated
path. Event 4688 may therefore contain only the executable path and omit all IFM
subcommands.

```powershell
$InputLines = @(
    'activate instance ntds'
    'ifm'
    "create full $OutputRoot"
    'quit'
    'quit'
)

$Start = Get-Date
$StdOut = @(
    $InputLines |
        & "$env:SystemRoot\System32\ntdsutil.exe" 2>&1
)
$ExitCode = $LASTEXITCODE
$End = Get-Date

[pscustomobject]@{
    StartedUtc = $Start.ToUniversalTime()
    EndedUtc   = $End.ToUniversalTime()
    ExitCode   = $ExitCode
    OutputRoot = $OutputRoot
    OutputMade = Test-Path $OutputRoot
}

if ($ExitCode -ne 0 -or -not (Test-Path $OutputRoot)) {
    Write-Warning 'IFM did not complete. Review Defender and NTDSUtil output.'
}
```

Do not save `$StdOut` in Git. Do not parse, transfer, or inspect NTDS database
or registry-hive contents.

## Metadata-only local verification

```powershell
Get-ChildItem $OutputRoot -Recurse -File |
    Select-Object FullName, Length, CreationTimeUtc

Get-Service NTDS, VSS, WazuhSvc |
    Select-Object Name, Status
```

Expected IFM filenames include:

```text
Active Directory\ntds.dit
Active Directory\ntds.jfm
registry\SECURITY
registry\SYSTEM
```

Names, sizes, and timestamps are sufficient evidence. Never open or hash-dump
these files.

## Local telemetry verification

### Security Event 4688

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $Start
} | Where-Object {
    $_.Message -match '(?i)ntdsutil\.exe|VSSVC\.exe'
} | Select-Object TimeCreated, Id, RecordId, Message
```

### Defender prevention evidence

```powershell
Get-WinEvent -FilterHashtable @{
    LogName   = 'Microsoft-Windows-Windows Defender/Operational'
    Id        = 1116, 1117
    StartTime = $Start
} | Select-Object TimeCreated, Id, RecordId, Message
```

A Defender block and a successful IFM run are separate outcomes. Do not report a
blocked run as successful extraction.

## Expected Wazuh rules

Rule source:

```text
rules/ntds_credential_dump_detection.xml
```

Expected coverage:

```text
100480 / level 12 / T1003.003 — any ntdsutil.exe execution
100481 / level 14 / T1003.003 — explicit visible IFM creation arguments
```

Native rule `67027` at level 3 provides only generic process telemetry. Encoded
PowerShell rule `100110` identifies a launcher, not NTDS extraction itself.

The stdin-driven path is expected to select `100480`, because Event 4688 can show
only:

```text
"C:\Windows\System32\ntdsutil.exe"
```

Rule `100481` is supplemental for launchers that expose IFM arguments in the
process command line.

## Dashboard filters

Final custom NTDS execution alert:

```text
agent.id:"001" AND rule.id:"100480"
```

All dedicated NTDS rules:

```text
agent.id:"001" AND rule.id:("100480" OR "100481")
```

## False-positive test

`ntdsutil.exe` is a legitimate dual-use administrative utility. A benign
standalone launch still matches rule `100480` by design:

```powershell
$ControlStart = Get-Date
'quit' | & "$env:SystemRoot\System32\ntdsutil.exe" | Out-Null
```

Expected result: rule `100480` at level 12. This test measures the known
administrative false-positive boundary; it is not expected to suppress the
alert. A standalone live control was not preserved during the 2026-08-05
validation and remains future hardening work.

## Cleanup and recovery validation

```powershell
Remove-Item $OutputRoot -Recurse -Force -ErrorAction SilentlyContinue

$RemainingFiles = @(
    Get-ChildItem $OutputRoot -Recurse -File -ErrorAction SilentlyContinue
)
$Shadows = @(Get-CimInstance Win32_ShadowCopy)

[pscustomobject]@{
    IFMRootAbsent  = -not (Test-Path $OutputRoot)
    RemainingFiles = $RemainingFiles.Count
    ShadowCopies   = $Shadows.Count
}

Get-Service NTDS, VSS, WazuhSvc |
    Select-Object Name, Status

Get-MpComputerStatus |
    Select-Object AMServiceEnabled,
                  AntivirusEnabled,
                  RealTimeProtectionEnabled,
                  IsTamperProtected

dcdiag.exe /q
"DCDIAG_EXIT=$LASTEXITCODE"
```

Remove only temporary Defender test exceptions recorded for this run. Do not
blindly delete existing exclusions or unrelated shadow copies. If VSS was stopped
at baseline, no shadow copies remain, and no dependent operation is active, return
VSS to that stopped baseline.

Final gate:

```text
IFM output absent
No test-created protected hive/database copies retained
Defender running with real-time protection enabled
NTDS running
VSS returned to baseline
No test-created shadow copies
Wazuh agent and manager healthy
dcdiag exit 0
```
