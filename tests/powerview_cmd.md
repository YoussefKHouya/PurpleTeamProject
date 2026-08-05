# PowerView reconnaissance — bounded validation playbook

## Scope

- Inventory entry: Tier 3 medium-high — PowerView Reconnaissance
- MITRE ATT&CK: `T1069.002` — Permission Groups Discovery: Domain Groups
- Endpoint: WIN01 / Wazuh agent `004`
- Operator: ordinary domain user `SIMULATION\yassine.karimi`
- Allowed behavior: read-only domain, user, group, trust, and exact-object ACL discovery
- Forbidden behavior: AD writes, alternate credentials, ticket requests, credential access, persistence, or chaining

## Pinned source

```text
Repository: https://github.com/PowerShellMafia/PowerSploit
Commit: d943001a7defb5e0d1657085a77a0e78609be58f
File: Recon/PowerView.ps1
SHA-256: 507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87
```

Review selected only these read-only functions:

```powershell
Get-Domain
Get-DomainUser -Identity yassine.karimi
Get-DomainGroup -Identity 'Domain Users'
Get-DomainTrust
Get-DomainObjectAcl -Identity yassine.karimi
```

Do not invoke mutating functions bundled in the same script, including `Set-*`, `Add-*`, `New-*`, or `Remove-*` domain functions.

## Telemetry prerequisites

Require all gates before staging:

```text
Yassine token: medium integrity and not Administrator
LDAP RootDSE: readable as Yassine
Security 4688 process creation: enabled with command lines
PowerShell Script Block Logging: enabled
WazuhSvc: Running
Defender real-time, behavior, IOAV, and tamper protection: enabled
WIN01 agent 004: Active
```

Versioned WIN01 group configuration:

```text
agents/windows/workstation-sysmon-agent.conf
```

It includes:

```xml
<localfile>
  <location>Microsoft-Windows-Windows Defender/Operational</location>
  <log_format>eventchannel</log_format>
</localfile>
```

After group delivery, require endpoint `ossec.log` event `1951` confirming that exact channel is analyzed.

## Bounded positive trigger

Run as `SIMULATION\yassine.karimi` with Defender enabled. Retrieve only the pinned raw file and verify the pinned hash before loading it:

```powershell
$Root = "$env:TEMP\PowerViewLab"
$Path = Join-Path $Root 'PowerView.ps1'
New-Item -ItemType Directory -Path $Root -Force | Out-Null
Invoke-WebRequest -UseBasicParsing `
  'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Recon/PowerView.ps1' `
  -OutFile $Path

$Hash = (Get-FileHash $Path -Algorithm SHA256).Hash.ToLower()
if ($Hash -ne '507e8666c239397561c58609f7ea569c9c49ddbb900cd260e7e42b02d03cfd87') {
    Remove-Item $Path -Force
    throw "PowerView hash mismatch: $Hash"
}
```

Hard stop when Defender blocks retrieval or removes the file. Do not add an exclusion, restore the threat, obfuscate the script, disable AMSI, or disable Defender merely to force execution. If retrieval succeeds, invoke only the reviewed read-only functions and summarize results; do not preserve bulk AD output.

## Expected evidence

Initial process telemetry:

```text
Security 4688
User: SIMULATION\yassine.karimi
Parent: wsmprovhost.exe for WinRM execution
Native/custom Wazuh fallback: 100110 for encoded PowerShell
```

Defender telemetry after adding its Operational channel:

```text
1116 — threat detection
1117 — remediation
Threat Name: Trojan:PowerShell/Powersploit.G
Native Wazuh rules: 62123 detection, 62124 action
```

Dashboard filters:

```text
agent.id:"004" AND rule.id:"100110" AND data.win.system.eventRecordID:"34415"
agent.id:"004" AND rule.id:"62123" AND data.win.system.eventRecordID:"1235"
agent.id:"004" AND rule.id:"62124" AND data.win.system.eventRecordID:"1237"
```

Do not claim PowerView reconnaissance executed unless the pinned file remained present, loaded successfully, and the selected functions returned results.

## False-positive test

Run a harmless documentation string as Yassine:

```powershell
$Text = 'PowerView documentation reference only'
Write-Output $Text
```

Expected result:

```text
No new Defender 1116/1117 for PowerView or PowerSploit
No new Wazuh 62123/62124
```

## Cleanup

```powershell
Unregister-ScheduledTask -TaskName 'WazuhLab-PowerView-Preflight' -Confirm:$false -ErrorAction SilentlyContinue
Remove-Item "$env:TEMP\PowerViewLab" -Recurse -Force -ErrorAction SilentlyContinue
```

Verify:

```text
PowerViewLab absent
Preflight task absent
PowerView/PowerSploit process count 0
Defender protections enabled
WazuhSvc running
Wazuh manager active
WIN01 agent 004 Active
```

BlueHammer artifacts and retained controls are outside this cleanup scope.
