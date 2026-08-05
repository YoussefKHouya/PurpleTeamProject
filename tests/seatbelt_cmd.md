# Seatbelt host-recon playbook

## Scope

- Techniques: `T1082`, `T1069.001`
- Endpoint: WIN01 / Wazuh agent `004`
- Intended operator: `SIMULATION\\yassine.karimi`
- Repository: `GhostPack/Seatbelt`
- Commit: `392171df84472591d4eae7ebd5b1cdc96ba91377`
- Source archive SHA-256 observed live: `c0a1fd1bdf747f7f9c47d9bf5d15ac582de6df76f192295e8b0395ace9c2b0d1`
- Project target: .NET Framework 3.5 / Release / AnyCPU

GhostPack publishes source, not official binaries. Build pinned source on intended disposable endpoint. Never substitute an untracked third-party executable.

## Build gate

```powershell
$msbuild = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
& $msbuild .\Seatbelt.sln /t:Rebuild /p:Configuration=Release /p:Platform="Any CPU"
```

Require successful exit, a new `bin\Release\Seatbelt.exe`, and recorded SHA-256. If the .NET 3.5 SP1 targeting pack/toolset is absent, classify `BUILD BLOCKED`; do not install old SDK components merely to force this test.

## Bounded trigger

Only after successful source build:

```powershell
& "$env:TEMP\SeatbeltLab\Seatbelt.exe" OSInfo TokenGroups PowerShell
```

Prohibited: `-group=all`, credential/vault/DPAPI/browser/Wi-Fi collection, file searches, event-log harvesting, remote targets, and output files.

## Expected evidence

```text
Security 4688 / Wazuh 67027
Sysmon Event 1 where policy includes it
Defender 1116/1117 / Wazuh 62123/62124 if prevented
```

Do not expect WinPEAS behavior rule `100471`; selected Seatbelt checks are primarily in-process.

## False-positive control

```powershell
whoami /groups
Get-ExecutionPolicy -List
```

Native equivalents may create generic discovery telemetry but must not be called Seatbelt execution.

## Cleanup

```powershell
Remove-Item "$env:TEMP\SeatbeltLab" -Recurse -Force -ErrorAction SilentlyContinue
```

Verify no executable/process, directory absent, Wazuh running, Defender enabled.
