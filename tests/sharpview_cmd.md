# SharpView enumeration command playbook

## Scope

- Technique: `T1069.002` — Permission Groups Discovery: Domain Groups
- Endpoint: WIN01 / Wazuh agent `004`
- Intended operator: `SIMULATION\\yassine.karimi` (ordinary domain user)
- Source: `tevora-threat/SharpView`, commit `b60456286b41bb055ee7bc2a14d645410cca9b74`
- Pinned compiled SHA-256: `c0621954bd329b5cabe45e92b31053627c27fa40853beb2cce2734fa677ffd93`

SharpView includes mutating methods. This test permits only read-only `Get-*` enumeration. Never invoke `Add-*`, `Remove-*`, `Set-*`, user/group creation, password changes, impersonation, Kerberoasting, or remote connection methods.

## Preflight

```powershell
whoami /all
Get-Service WazuhSvc
Get-MpComputerStatus | Select RealTimeProtectionEnabled,BehaviorMonitorEnabled,IoavProtectionEnabled,IsTamperProtected
```

Expected: ordinary Yassine token, Wazuh running, Defender protections enabled.

## Bounded trigger

Transfer the pinned binary directly to WIN01 without retaining it on the bridge, verify its hash, then run only:

```powershell
& "$env:TEMP\\SharpViewLab\\SharpView.exe" Get-Domain
```

Hard stop if Defender blocks staging or execution. Do not add an exclusion, restore the detection, obfuscate the binary, or disable protection.

## Expected evidence

```text
Defender Operational 1116/1117
Security 4688 and/or Sysmon Event 1 only if SharpView actually starts
Native Wazuh Defender rules 62123/62124
```

Validated Dashboard filter:

```text
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1270"
```

Do not claim SharpView enumeration executed unless a low-privilege SharpView process and returned domain data are both proven.

## False-positive test

```powershell
Write-Output 'SharpView documentation reference only'
```

Expected: no new Defender `1116/1117` and no Wazuh `62123/62124` attributable to the harmless string.

## Cleanup

```powershell
Remove-Item "$env:TEMP\\SharpViewLab" -Recurse -Force -ErrorAction SilentlyContinue
```

Verify directory absent, no SharpView process, Wazuh running, and Defender protections enabled.
