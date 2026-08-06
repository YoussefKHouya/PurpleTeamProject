# SharpView account-enumeration command playbook

## Scope

- Techniques: `T1087.002` — Domain Account Discovery; `T1558.004` — AS-REP Roasting discovery
- Endpoint: WIN01 / Wazuh agent `004`
- Operator: `SIMULATION\yassine.karimi` (ordinary domain user, Medium integrity)
- Source: `tevora-threat/SharpView`, commit `b60456286b41bb055ee7bc2a14d645410cca9b74`
- Pinned SHA-256: `c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93`

SharpView includes mutating methods. This playbook permits only read-only `Get-*`
enumeration. Do not invoke `Add-*`, `Remove-*`, `Set-*`, password changes,
impersonation, Kerberoasting, or remote connection methods.

## Preflight

```powershell
whoami
```

```powershell
Get-Service WazuhSvc
```

```powershell
(Get-FileHash "$env:TEMP\sharpview.exe" -Algorithm SHA256).Hash.ToLower()
```

Expected: `SIMULATION\yassine.karimi`, Wazuh running, pinned hash above.

## Bounded trigger

Use explicit domain and DC. This avoids ambiguous default DirectoryServices
resolution and produced the validated LDAP bind.

```powershell
Set-Location "$env:TEMP"
```

```powershell
.\sharpview.exe Get-NetUser -PreauthNotRequired -Domain simulation.local -Server DC01.simulation.local
```

Expected LDAP base:

```text
LDAP://DC01.simulation.local/DC=simulation,DC=local
```

## Expected telemetry

```text
Windows Security 4688
Sysmon Event 1
Native Wazuh 67027 / level 3
Custom 100522 / level 12 for sharpview.exe semantic invocation
Custom 100523 / level 10 for filename-independent semantic invocation
```

Named-tool Dashboard filter:

```text
agent.id:"004" AND rule.id:"100522"
```

Rename-resistant Dashboard filter:

```text
agent.id:"004" AND rule.id:"100523"
```

## Real renamed-tool validation

Copy the actual pinned SharpView binary; do not use an unrelated executable as
final behavior proof.

```powershell
Copy-Item .\sharpview.exe .\survey.exe -Force
```

```powershell
(Get-FileHash .\survey.exe -Algorithm SHA256).Hash.ToLower()
```

```powershell
.\survey.exe Get-NetUser -PreauthNotRequired -Domain simulation.local -Server DC01.simulation.local
```

Expected: identical pinned hash, successful LDAP output, `100523` fires, and
Sysmon reports `OriginalFileName=SharpView.exe` despite image name `survey.exe`.

## False-positive control

```powershell
Write-Output 'Get-NetUser -PreauthNotRequired documentation only'
```

Expected: neither `100522` nor `100523` fires.

## Retention

Keep `sharpview.exe`, `survey.exe`, CredSSP posture, and useful lab configuration
for reproduction. Do not clean up or restore state unless explicitly requested
or required for safety/test validity.

Validated evidence:

```text
tests/results/sharpview_interactive_detection_validation_2026-08-06.md
```
