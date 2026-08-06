# Seatbelt host-recon playbook

## Scope

- Techniques: `T1082`, `T1069.002`
- Endpoint: WIN01 / Wazuh agent `004`
- Intended operator: `SIMULATION\yassine.karimi`, Medium integrity
- Repository: `GhostPack/Seatbelt`
- Commit: `392171df84472591d4eae7ebd5b1cdc96ba91377`
- Source archive SHA-256: `c0a1fd1bdf747f7f9c47d9bf5d15ac582de6df76f192295e8b0395ace9c2b0d1`
- Detection XML: `rules/seatbelt_detection.xml`
- Expected custom rule: `100524`, level 12

GhostPack publishes source, not official binaries. Build pinned source on the disposable endpoint. Never substitute an untracked third-party executable.

## Build root cause and supported workaround

The pinned project targets .NET Framework 3.5 and uses C# 8/9 features. On the validated WIN01:

```text
NetFx3 runtime feature:    Enabled
.NET 3.5 reference pack:   Absent
Inbox MSBuild:             4.8.9037.0
Original failure:          MSB3644 / MSB3645
```

`NetFx3` runtime enablement does not install developer reference assemblies. Retarget the retained source copy to installed .NET Framework 4.8, preserve the original project, and use official Microsoft Roslyn/reference packages.

Pinned package hashes:

```text
Microsoft.Net.Compilers.Toolset 4.8.0
37333f4f1e2ce55e621355d6da651dc23d4cb5f94a8f76b9478816e87f110ad9

Microsoft.NETFramework.ReferenceAssemblies.net48 1.0.3
8a7e348538e7eb91351696911689f49e3d4f63f8bab517432bbe159b8b1104a2
```

## Build commands — Administrator PowerShell

```powershell
$ErrorActionPreference = "Stop"
$root = "C:\Users\yassine.karimi\AppData\Local\Temp\SeatbeltLab"
$tools = Join-Path $root "build-tools"
New-Item $tools -ItemType Directory -Force | Out-Null

$roslynPkg = Join-Path $tools "microsoft.net.compilers.toolset.4.8.0.nupkg"
$refsPkg = Join-Path $tools "microsoft.netframework.referenceassemblies.net48.1.0.3.nupkg"

Invoke-WebRequest -UseBasicParsing "https://api.nuget.org/v3-flatcontainer/microsoft.net.compilers.toolset/4.8.0/microsoft.net.compilers.toolset.4.8.0.nupkg" -OutFile $roslynPkg
Invoke-WebRequest -UseBasicParsing "https://api.nuget.org/v3-flatcontainer/microsoft.netframework.referenceassemblies.net48/1.0.3/microsoft.netframework.referenceassemblies.net48.1.0.3.nupkg" -OutFile $refsPkg

if ((Get-FileHash $roslynPkg -Algorithm SHA256).Hash -ne "37333F4F1E2CE55E621355D6DA651DC23D4CB5F94A8F76B9478816E87F110AD9") { throw "Roslyn hash mismatch" }
if ((Get-FileHash $refsPkg -Algorithm SHA256).Hash -ne "8A7E348538E7EB91351696911689F49E3D4F63F8BAB517432BBE159B8B1104A2") { throw ".NET 4.8 reference-pack hash mismatch" }

Copy-Item $roslynPkg "$roslynPkg.zip" -Force
Copy-Item $refsPkg "$refsPkg.zip" -Force
$roslyn = Join-Path $tools "roslyn-4.8.0"
$refs = Join-Path $tools "net48-refs-1.0.3"
Remove-Item $roslyn,$refs -Recurse -Force -ErrorAction SilentlyContinue
Expand-Archive "$roslynPkg.zip" $roslyn -Force
Expand-Archive "$refsPkg.zip" $refs -Force

$project = Get-ChildItem "$root\src" -Filter Seatbelt.csproj -Recurse | Select-Object -First 1
if (-not $project) { throw "Seatbelt.csproj not found" }
Copy-Item $project.FullName "$($project.FullName).v35.original" -Force
$xml = (Get-Content $project.FullName -Raw).Replace("<TargetFrameworkVersion>v3.5</TargetFrameworkVersion>","<TargetFrameworkVersion>v4.8</TargetFrameworkVersion>")
Set-Content $project.FullName $xml -Encoding UTF8

$msbuild = "$env:WINDIR\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe"
$refRoot = "$refs\build\"
$cscRoot = "$roslyn\tasks\net472"
$buildLog = Join-Path $root "seatbelt-build.log"

& $msbuild $project.FullName /t:Rebuild /p:Configuration=Release /p:Platform=AnyCPU "/p:TargetFrameworkRootPath=$refRoot" "/p:CscToolPath=$cscRoot" /p:CscToolExe=csc.exe /v:minimal "/flp:LogFile=$buildLog;Verbosity=normal"
if ($LASTEXITCODE -ne 0) { throw "Seatbelt build failed" }

$builtExe = Join-Path $project.Directory.FullName "bin\Release\Seatbelt.exe"
$exe = Join-Path $root "Seatbelt.exe"
Copy-Item $builtExe $exe -Force
Get-Item $exe | Select-Object FullName,Length,LastWriteTimeUtc
Get-FileHash $exe -Algorithm SHA256
```

Validated artifact:

```text
Size:    593408 bytes
SHA-256: bc17d0107c34fb6f67e85d9c37a9b606e1f3c6a48bc8de4d710cd6d6b1695fff
```

## Bounded trigger — local Yassine PowerShell

```powershell
whoami
$exe = "C:\Users\yassine.karimi\AppData\Local\Temp\SeatbeltLab\Seatbelt.exe"
$log = "C:\Users\yassine.karimi\AppData\Local\Temp\SeatbeltLab\seatbelt-host-recon.txt"
Get-FileHash $exe -Algorithm SHA256
& $exe OSInfo TokenGroups PowerShell 2>&1 | Set-Content $log -Encoding UTF8
```

Require output headings `OSInfo`, `TokenGroups`, and `PowerShell`, plus `Hostname=Win01`, `Domain Name=SIMULATION.LOCAL`, and `Username=SIMULATION\yassine.karimi`.

Prohibited for this case: `-group=all`, credential/vault/DPAPI/browser/Wi-Fi collection, file searches, event-log harvesting, and remote targets.

## Expected evidence

```text
Security 4688 / native Wazuh 67027
Sysmon Event 1 with OriginalFileName=Seatbelt.exe and Product=Seatbelt
Custom Wazuh 100524, level 12
Defender 1116/1117 only if prevention occurs
```

Dashboard filter:

```text
agent.id:"004" AND rule.id:"100524"
```

## False-positive control

This is intentionally an unrelated benign binary. It validates rule resistance; it is not Seatbelt execution.

```powershell
New-Item "$env:TEMP\SeatbeltNegative" -ItemType Directory -Force | Out-Null
Copy-Item "$env:WINDIR\System32\whoami.exe" "$env:TEMP\SeatbeltNegative\Seatbelt.exe" -Force
& "$env:TEMP\SeatbeltNegative\Seatbelt.exe" OSInfo TokenGroups PowerShell
```

Require Sysmon `OriginalFileName=whoami.exe`, Microsoft product metadata, generic process telemetry, and no rule `100524`.

Boundary control using genuine Seatbelt metadata but an invalid extra token:

```powershell
& "$env:TEMP\SeatbeltLab\Seatbelt.exe" OSInfo TokenGroups PowerShell NotASeatbeltCommand
```

Require genuine `OriginalFileName=Seatbelt.exe` and `Product=Seatbelt` telemetry, native process visibility, and no rule `100524`. This proves the command matcher accepts exactly one executable token followed by the three approved modules and end-of-string; extra tokens before, between, or after the modules remain outside this bounded rule.

## Retained lab state

Keep source archive/tree, original and retargeted projects, official compiler/reference packages, build outputs/logs, Seatbelt binary/output logs, negative control, CredSSP, and existing Defender posture unless cleanup is explicitly requested or a safety/test-validity exception applies.

Historical and closure evidence:

```text
tests/results/seatbelt_validation_2026-08-05.md
tests/results/seatbelt_interactive_detection_validation_2026-08-06.md
```
