# DC and Registry Purple-Team Test Catalog

Purpose: controlled, MITRE-mapped Wazuh validation against approved lab assets. Replace placeholders only at execution time. Never store credentials, private keys, internal hostnames, or internal IP addresses here.

## Execution controls

- Snapshot test assets before impact tests.
- Run one case at a time.
- Capture raw Windows event, Wazuh alert, rule ID, level, and MITRE mapping.
- Use a dedicated test account where possible.
- Cleanup every marker after validation.
- Do not run credential dumping, security-control disabling, destructive deletion, or uncontrolled malware.

## Credential setup

```powershell
$cred = Get-Credential 'SIMULATION\yassine.karimi'
```

Placeholders:

```text
<DOMAIN>          simulation.local
<TEST_USER>       yassine.karimi
<DC_HOST_OR_IP>   192.168.56.109
<TEST_DOMAIN>     simulation.local
```

## DC/domain discovery tests

### D01 — domain metadata

ATT&CK: T1059.001, T1482

```powershell
Get-ADDomain | Select-Object DNSRoot,NetBIOSName,DomainMode,PDCEmulator
Get-ADForest | Select-Object RootDomain,ForestMode
Get-ADDomainController -Discover | Select-Object HostName,Site,OperatingSystem
```

### D02 — bounded user discovery

ATT&CK: T1087.002

```powershell
Get-ADUser -Filter * |
  Select-Object -First 10 SamAccountName,Enabled,LastLogonDate
```

### D03 — privileged-group discovery

ATT&CK: T1069.002

```powershell
Get-ADGroupMember -Identity 'Domain Admins' |
  Select-Object -First 10 Name,ObjectClass
```

### D04 — computer discovery

ATT&CK: T1018, T1087.002

```powershell
Get-ADComputer -Filter * |
  Select-Object -First 10 Name,OperatingSystem,Enabled
```

### D05 — password-policy discovery

ATT&CK: T1201

```powershell
Get-ADDefaultDomainPasswordPolicy |
  Select-Object MinPasswordLength,MaxPasswordAge,LockoutThreshold,ComplexityEnabled
```

### D06 — DC query through explicit remoting

ATT&CK: T1021.006, T1059.001

```powershell
Invoke-Command `
  -ComputerName 192.168.56.109 `
  -Credential $cred `
  -Authentication Negotiate `
  -ScriptBlock { whoami; hostname; Get-Date }
```

### D07 — DC locator

ATT&CK: T1016, T1059.001

```powershell
nltest.exe /dsgetdc:simulation.local
nltest.exe /dclist:simulation.local
```

## Registry read tests

### R01 — Run-key inventory

ATT&CK: T1012, T1547.001

```powershell
Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run'
```

### R02 — security-policy inventory

ATT&CK: T1012

```powershell
Get-ItemProperty 'HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
```

### R03 — PowerShell policy inventory

ATT&CK: T1012, T1059.001

```powershell
Get-ItemProperty 'HKLM:\Software\Policies\Microsoft\Windows\PowerShell'
```

## Bounded registry-write tests

These modify only a dedicated HKCU test key and are reversible.

### R04 — create marker key/value

ATT&CK: T1112

```powershell
$key='HKCU:\Software\PurpleTeam\WazuhTest'
New-Item -Path $key -Force | Out-Null
New-ItemProperty -Path $key -Name 'DetectionMarker' -Value 'WAZUH_REGISTRY_TEST' -PropertyType String -Force
Get-ItemProperty -Path $key
```

### R05 — modify marker value

ATT&CK: T1112

```powershell
Set-ItemProperty `
  -Path 'HKCU:\Software\PurpleTeam\WazuhTest' `
  -Name 'DetectionMarker' `
  -Value 'WAZUH_REGISTRY_MODIFIED'
```

### R06 — remove marker key

ATT&CK: T1112

```powershell
Remove-Item 'HKCU:\Software\PurpleTeam\WazuhTest' -Recurse -Force
```

### R07 — command-line registry write syntax

ATT&CK: T1112

```powershell
reg.exe add 'HKCU\Software\PurpleTeam\WazuhTest' /v DetectionMarker /t REG_SZ /d WAZUH_REG_EXE_TEST /f
reg.exe query 'HKCU\Software\PurpleTeam\WazuhTest'
reg.exe delete 'HKCU\Software\PurpleTeam\WazuhTest' /f
```

## Persistence telemetry test — gated

Use only after snapshot and with an explicit test window. This creates a temporary per-user Run value that launches a benign marker command, then removes it immediately.

ATT&CK: T1547.001, T1112

```powershell
$run='HKCU:\Software\Microsoft\Windows\CurrentVersion\Run'
New-ItemProperty -Path $run -Name 'PurpleTeam_Wazuh_Test' -Value 'cmd.exe /c echo WAZUH_RUNKEY_TEST' -PropertyType String -Force
Get-ItemProperty -Path $run -Name 'PurpleTeam_Wazuh_Test'
Remove-ItemProperty -Path $run -Name 'PurpleTeam_Wazuh_Test' -ErrorAction SilentlyContinue
```

## Evidence checklist

For each case record:

```text
Test ID:
UTC timestamp:
Asset label:
Windows Event ID:
Raw event:
Wazuh rule ID:
Alert level:
MITRE technique:
Expected/actual:
Cleanup completed:
```

Validate raw events before modifying rules:

```bash
/var/ossec/bin/wazuh-logtest
```
