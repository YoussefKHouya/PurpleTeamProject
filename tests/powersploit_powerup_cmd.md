# PowerSploit PowerUp read-only playbook

## Scope

- Techniques: `T1059.001`, `T1012`, `T1007`
- Endpoint: WIN01 / Wazuh agent `004`
- Intended operator: `SIMULATION\\yassine.karimi`
- Repository: `PowerShellMafia/PowerSploit`
- Commit: `d943001a7defb5e0d1657085a77a0e78609be58f`
- Artifact: `Privesc/PowerUp.ps1`
- SHA-256: `9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22`

Default scope permits only the three named read-only checks below. A full
`Invoke-AllChecks` audit requires explicit operator approval and a genuine local
low-privilege session. Never invoke `Invoke-ServiceAbuse`,
`Set-ServiceBinaryPath`, `Write-*`, `Install-*`, `Enable-Privilege`, UAC
bypasses, credential checks, or `Get-System`.

## Preflight

```powershell
whoami /all
Get-Service WazuhSvc
Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected
```

Require low-privilege Yassine, Wazuh agent `004` Active, and Defender enabled.

## Bounded trigger

```powershell
. "$env:TEMP\PowerSploitLab\PowerUp.ps1"
Get-RegistryAlwaysInstallElevated
Get-UnquotedService
Get-ModifiableService
```

Hard stop when Defender prevents staging/import. Do not add exclusions, obfuscate, restore the detection, or disable protection.

## Expected evidence

```text
Defender Operational 1116/1117
Wazuh native 62123/62124 when prevented
Security 4688 and PowerShell 4104 only if script reaches import/execution
Custom rule 100521 / level 12 for exact Invoke-AllChecks or Invoke-PrivescAudit invocation
```

Validated Dashboard filter:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1284"
```

Interactive full-audit detection filter:

```text
agent.id:"004" AND rule.id:"100521"
```

## False-positive control

```powershell
Get-ItemProperty "HKLM:\Software\Policies\Microsoft\Windows\Installer" -ErrorAction SilentlyContinue
Get-CimInstance Win32_Service -ErrorAction SilentlyContinue | Select-Object -First 3 Name,PathName
Write-Output 'PowerSploit PowerUp documentation reference only'
```

Access denied or empty output is valid low-token behavior. Expected: no matching Defender `1116/1117` after control timestamp.

## Validated CredSSP behavioral retest

A separate operator-approved retest on 2026-08-06 imported the pinned PowerUp script under medium-integrity `SIMULATION\yassine.karimi` through narrowly scoped CredSSP. `Get-RegistryAlwaysInstallElevated` executed; direct registry verification showed both policy values absent and no exploitable condition. `Get-UnquotedService` and `Get-ModifiableService` reached their checks but were denied by the remote low token/Service Control Manager, not Defender.

The original Defender prevention verdict remains valid. Retest evidence:

```text
tests/results/powerup_credssp_retest_2026-08-06.md
Wazuh rule 91823 / level 14 / PowerShell record 100167
```

The interactive closure completed on 2026-08-06. `Invoke-AllChecks` ran from a
local medium-integrity Yassine shell; service-check records `104676`, `104681`,
and `126085` reached Wazuh. Exact invocation record `104573` exposed an alerting
gap. Custom rule `100521` was then validated with harmless positive record
`131587`, level 12. Documentation-string record `131678` stayed quiet. Exact
index proof returned one document. Evidence:

```text
tests/results/powerup_interactive_detection_validation_2026-08-06.md
```

Reported `edgeupdate`/`edgeupdatem` paths are not classified as exploitable:
PowerUp identified permissions on `C:\`, not proven write access to the quoted
binary under Program Files. The user-owned WindowsApps PATH result likewise
does not prove a privileged DLL load.

## Retention and optional cleanup

Retain `power.ps1`, supporting tools, and useful vulnerable configuration by
default for reproduction. Run cleanup only when explicitly requested or needed
for test validity or containment outside the isolated lab.

```powershell
Remove-Item "$env:TEMP\PowerSploitLab" -Recurse -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\power.ps1" -Force -ErrorAction SilentlyContinue
```
