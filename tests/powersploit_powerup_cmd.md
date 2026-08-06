# PowerSploit PowerUp read-only playbook

## Scope

- Techniques: `T1059.001`, `T1012`, `T1007`
- Endpoint: WIN01 / Wazuh agent `004`
- Intended operator: `SIMULATION\\yassine.karimi`
- Repository: `PowerShellMafia/PowerSploit`
- Commit: `d943001a7defb5e0d1657085a77a0e78609be58f`
- Artifact: `Privesc/PowerUp.ps1`
- SHA-256: `9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22`

Only three read-only checks are allowed. Never invoke `Invoke-PrivescAudit`, `Invoke-AllChecks`, `Invoke-ServiceAbuse`, `Set-ServiceBinaryPath`, `Write-*`, `Install-*`, `Enable-Privilege`, UAC bypasses, credential checks, or `Get-System`.

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
```

Validated Dashboard filter:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1284"
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

Full closure of the two denied host checks requires a proven interactive low-privilege Yassine session. Do not grant administrative rights merely to force them.

## Cleanup

```powershell
Remove-Item "$env:TEMP\PowerSploitLab" -Recurse -Force -ErrorAction SilentlyContinue
```

Verify directory/process absence, Defender enabled, Wazuh running, and no rule `203` queue loss.
