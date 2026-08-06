# Seatbelt interactive host-recon and detection validation — 2026-08-06

## Verdict

```text
Pinned source/archive verification:         PASS
Original .NET 3.5 build blocker explained:  PASS
Retargeted .NET 4.8 source build:            PASS
Low-privilege interactive execution:         PASS
Semantic OSInfo output:                      PASS
Semantic TokenGroups output:                 PASS
Semantic PowerShell output:                  PASS
Native Wazuh process visibility:             PASS
Custom Seatbelt rule 100524:                 PASS
Exact-argument negative control:             PASS
Defender prevention during run:              NONE OBSERVED
Artifact retention:                          INTENTIONAL
Overall:                                     PASS
```

This closure supersedes the `BUILD BLOCKED / EXECUTION NOT REACHED` operational verdict in `seatbelt_validation_2026-08-05.md`. That older file remains historical evidence of the original build environment.

## Source and build root cause

```text
Repository:                 GhostPack/Seatbelt
Pinned commit:              392171df84472591d4eae7ebd5b1cdc96ba91377
Source archive SHA-256:     c0a1fd1bdf747f7f9c47d9bf5d15ac582de6df76f192295e8b0395ace9c2b0d1
Original project target:    .NET Framework 3.5
Original errors:            MSB3644 / MSB3645
NetFx3 runtime feature:     Enabled
.NET 3.5 reference pack:    Absent
Installed inbox MSBuild:    4.8.9037.0
```

Enabling `NetFx3` had supplied runtime support but not developer reference assemblies. Re-enabling the feature would not fix MSBuild. The pinned project also declares C# 8/9 language features, while the inbox Framework compiler is legacy.

The retained source was minimally retargeted from `v3.5` to `v4.8`. Compilation used two official Microsoft NuGet packages downloaded directly on WIN01:

```text
Microsoft.Net.Compilers.Toolset 4.8.0
SHA-256: 37333f4f1e2ce55e621355d6da651dc23d4cb5f94a8f76b9478816e87f110ad9

Microsoft.NETFramework.ReferenceAssemblies.net48 1.0.3
SHA-256: 8a7e348538e7eb91351696911689f49e3d4f63f8bab517432bbe159b8b1104a2
```

No unofficial Seatbelt binary, legacy .NET 3.5 SDK, or broad Visual Studio installation was introduced. Wazuh Security 4688 recorded the build:

```text
MSBuild record: 39344
Roslyn csc record: 39345
Configuration: Release / AnyCPU / .NET Framework 4.8
```

Produced artifact:

```text
Path: C:\Users\yassine.karimi\AppData\Local\Temp\SeatbeltLab\Seatbelt.exe
Size: 593408 bytes
SHA-256: bc17d0107c34fb6f67e85d9c37a9b606e1f3c6a48bc8de4d710cd6d6b1695fff
```

## Low-privilege Host Recon

A genuine local PowerShell session executed:

```powershell
& "C:\Users\yassine.karimi\AppData\Local\Temp\SeatbeltLab\Seatbelt.exe" OSInfo TokenGroups PowerShell
```

Sysmon Event 1 proved:

```text
User:                 SIMULATION\yassine.karimi
IntegrityLevel:       Medium
ParentImage:          powershell.exe
OriginalFileName:     Seatbelt.exe
Product/Description:  Seatbelt
SHA-256:              bc17d0107c34fb6f67e85d9c37a9b606e1f3c6a48bc8de4d710cd6d6b1695fff
Security 4688 record: 39393
Sysmon start record:  51067
Sysmon stop record:   51075
Native Wazuh rule:    67027, level 3
```

Retained output `seatbelt-host-recon.txt` contained:

```text
====== OSInfo ======
Hostname:    Win01
Domain Name: SIMULATION.LOCAL
Username:    SIMULATION\yassine.karimi

====== TokenGroups ======
SIMULATION\Domain Users

====== PowerShell ======
Installed PowerShell Versions
PowerShell logging/downgrade and AMSI posture observations
```

This proves semantic execution of all three selected read-only modules. No `-group=all`, browser/vault/DPAPI/Wi-Fi collection, event-log harvesting, remote target, or credential collection was requested.

## Defender posture

Preflight returned:

```text
RealTimeProtectionEnabled: false
BehaviorMonitorEnabled:    false
IoavProtectionEnabled:     false
IsTamperProtected:         true
```

This posture pre-existed the Seatbelt run and was not changed during this validation. No Defender 1116/1117 event mentioning Seatbelt appeared during execution. Therefore this result proves allowed execution and Wazuh detection, not Defender prevention.

## Custom detection

`rules/seatbelt_detection.xml` adds rule `100524`, level 12, under the installed Sysmon Event 1 parent `61603`.

The rule requires live PE metadata and exact bounded Host Recon semantics:

```text
OriginalFileName = Seatbelt.exe
Product          = Seatbelt
CommandLine      = OSInfo ... TokenGroups ... PowerShell
```

Ordinary executable renaming does not change `OriginalFileName` or `Product`, avoiding a basename-only rule.

Positive retest:

```text
Custom rule:          100524
Level:                12
Sysmon record:        51193
Security 4688 record: 39423
Sysmon stop record:   51199
User:                 SIMULATION\yassine.karimi
Integrity:            Medium
SHA-256:              bc17d0107c34fb6f67e85d9c37a9b606e1f3c6a48bc8de4d710cd6d6b1695fff
Manager alerts.json:  PASS
```

## False-positive resistance

A harmless copy of Microsoft `whoami.exe` was named `Seatbelt.exe` and launched with the same arguments:

```powershell
& "$env:TEMP\SeatbeltNegative\Seatbelt.exe" OSInfo TokenGroups PowerShell
```

Observed evidence:

```text
Image basename:        Seatbelt.exe
OriginalFileName:      whoami.exe
Product:               Microsoft Windows Operating System
SHA-256:               1d4902a04d99e8ccbfe7085e63155955fee397449d386453f6c452ae407b8743
Latest Sysmon record:  51243
Security 4688 record:  39433
Native rule:           67027, level 3
Custom rule 100524:    ABSENT — PASS
```

This is a negative detector control only. It is not represented as Seatbelt execution.

## Pipeline and health

```text
Wazuh XML parse:               PASS
Duplicate custom rule IDs:     PASS
wazuh-analysisd -t:            PASS
Repository/deployed rule hash: 33dcba20bac42574fdfc83b7ad982a6433e7f809a4ff280a3af9ddab5da42790
wazuh-manager:                 active
WIN01 agent 004:               Active
Manager alerts.json positive:  PASS
Manager alerts.json negative:  PASS
```

Exact indexer API confirmation was unavailable because existing dashboard/indexer credentials were previously rejected. Manager alert delivery is proven; Dashboard filter:

```text
agent.id:"004" AND rule.id:"100524"
```

## Retained state

Retained intentionally for reproduction:

```text
Pinned Seatbelt archive and source
Original v3.5 project backup
Retargeted v4.8 project
Official Roslyn/reference packages and extracted build tools
Release build products and Seatbelt.exe
seatbelt-build.log
seatbelt-host-recon.txt
seatbelt-host-recon-retest.txt
SeatbeltNegative control directory
CredSSP and existing endpoint protection posture
```

No cleanup or rollback was requested. Retention remains confined to the isolated lab.