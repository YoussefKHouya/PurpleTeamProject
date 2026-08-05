# adPEAS domain-enumeration playbook

## Scope

- Techniques: `T1059.001`, `T1201`, `T1482`
- Endpoint: WIN01 / Wazuh agent `004`
- Operator: `SIMULATION\\yassine.karimi` (ordinary domain user)
- Repository: `61106960/adPEAS`
- Commit: `1ea06f1d2dc92152b5aaeca6eacff24dd096d82e`
- Artifact: `adPEAS_min.ps1`
- SHA-256: `7d7c1535ef4d33f24b738509af3962500453070ae94b0cbb23927c6e65d0a10b`

The project includes offensive helpers. This test allows only OPSEC domain checks. Never invoke credential, roast, ticket, password-spray, DCSync, RBCD, Shadow Credentials, ADCS abuse, BloodHound, `New-*`, or `Set-*` operations.

## Preflight

```powershell
whoami /all
Get-Service WazuhSvc
Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected
```

Require Yassine at medium integrity, Wazuh running, Defender enabled, agent `004` Active.

## Bounded trigger

```powershell
Import-Module "$env:TEMP\ADPeasLab\adPEAS_min.ps1" -Force
Invoke-adPEAS -Domain "SIMULATION.LOCAL" -UseWindowsAuth -OPSEC -Module Domain
Disconnect-adPEAS
```

Remote WinRM may hit the credential-delegation/double-hop boundary. If authenticated LDAP bind fails, record `PARTIAL`; do not embed credentials into command-line or script-block evidence.

## Expected evidence

```text
Security 4688 / PowerShell under Yassine
PowerShell Operational 4104 where available
Wazuh generic PowerShell/process rules
Defender 1116/1117 and Wazuh 62123/62124 only if prevention occurs
```

Validated Dashboard filter for this run:

```text
agent.id:"004" AND rule.id:"100134" AND data.win.system.eventRecordID:"35217"
```

## False-positive control

```powershell
Write-Output 'ADPeas documentation reference only'
```

Expected: no Defender `1116/1117` attributable to adPEAS. Generic encoded-PowerShell telemetry from management wrappers is not tool attribution.

## Cleanup

```powershell
Remove-Module adPEAS -Force -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\ADPeasLab" -Recurse -Force -ErrorAction SilentlyContinue
```

Verify directory/process absence, Wazuh running, Defender protections enabled, and no fresh Wazuh queue-loss rule `203`.
