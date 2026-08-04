# LOLBins — WIN01 validation

## Scope

Controlled local validation on WIN01 as `SIMULATION\yassine.karimi`.

Target binaries are signed Windows LOLBins already present on WIN01. No LOLBin executables are downloaded.

## Certutil — encode and decode

Run in Command Prompt:

```cmd
echo WAZUH_LOLBIN_CERTUTIL>%TEMP%\WAZUH_LI.txt & certutil.exe -encode %TEMP%\WAZUH_LI.txt %TEMP%\WAZUH_LI.b64 & certutil.exe -decode %TEMP%\WAZUH_LI.b64 %TEMP%\WAZUH_LO.txt & del /q %TEMP%\WAZUH_LI.txt %TEMP%\WAZUH_LI.b64 %TEMP%\WAZUH_LO.txt
```

Expected custom alerts:

```text
100474 — Certutil encoding activity
100473 — Certutil decoding activity
```

## MSHTA — local harmless HTA

Run in PowerShell:

```powershell
$h="$env:TEMP\WAZUH_LOL.hta"; Set-Content $h '<html><head><hta:application showintaskbar="no" windowstate="minimize"></head><script>close()</script></html>'; mshta.exe $h; Remove-Item $h -Force
```

Expected custom alert:

```text
100475 — MSHTA signed-binary proxy execution
```

## Regsvr32 — local harmless scriptlet

Run in PowerShell:

```powershell
$s="$env:TEMP\WAZUH_LOL.sct"; Set-Content $s '<scriptlet><registration progid="Wazuh.Test" classid="{F0001111-0000-0000-0000-0000FEEDACDC}"></registration><script language="JScript">new ActiveXObject("WScript.Shell").Run("cmd.exe /c echo WAZUH_REGSVR32>%TEMP%\WAZUH_REGSVR32.txt",0,true);</script></scriptlet>'; regsvr32.exe /s /n /i:"file:///$($s.Replace("\","/"))" scrobj.dll; Remove-Item $s,"$env:TEMP\WAZUH_REGSVR32.txt" -Force -ErrorAction SilentlyContinue
```

Expected custom alert:

```text
100476 — Regsvr32 scriptlet proxy execution
```

## Rundll32 — local INF launch

Run in PowerShell:

```powershell
$f="$env:TEMP\WAZUH_LOL.inf"; Set-Content $f "[Version]`r`nSignature=`"`$CHICAGO`$`"`r`n[DefaultInstall]`r`nRunPreSetupCommands=Run`r`n[Run]`r`ncmd.exe /c echo WAZUH_RUNDLL32>$env:TEMP\WAZUH_RUNDLL32.txt"; rundll32.exe advpack.dll,LaunchINFSection "$f,DefaultInstall"; Start-Sleep -Seconds 3; Remove-Item $f,"$env:TEMP\WAZUH_RUNDLL32.txt" -Force -ErrorAction SilentlyContinue
```

Expected custom alert:

```text
100477 — Rundll32 suspicious proxy execution
```

## Verified Wazuh evidence

WIN01 agent: `004`.

```text
100473 — Certutil decode
100474 — Certutil encode
100475 — MSHTA
100476 — Regsvr32 scriptlet proxy
100477 — Rundll32 proxy execution
```

Custom rules are in `rules/lolbins_detection.xml` and deployed to `/var/ossec/etc/rules/lolbins_detection.xml` on the Wazuh manager.

Full result: `tests/results/lolbins_validation_2026-08-04.md`.
