# Windows Command Shell Detection Commands

## Rule file

```text
rules/cmd_detection.xml
```

Run one test at a time from an elevated PowerShell session on `WIN01`.
Every test starts a fresh `cmd.exe`, placing the complete tested command in
Security Event 4688. Current workstation agent: `004`.

## Preflight

```powershell
$Identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$Principal = [Security.Principal.WindowsPrincipal]::new($Identity)

[pscustomobject]@{
    Computer = $env:COMPUTERNAME
    Identity = $Identity.Name
    IsAdmin  = $Principal.IsInRole(
        [Security.Principal.WindowsBuiltInRole]::Administrator
    )
}
```

## Test matrix

| Test | Detection | Expected rule |
|---|---|---:|
| C01 | Baseline CMD | base only / no alert |
| C02 | Remote retrieval | 100310 |
| C03 | Download and execute chain | 100330 |
| C04 | Encoded PowerShell through CMD | 100331 |
| C05 | LSASS command syntax | 100332 |
| C06 | SAM/SYSTEM dump syntax | 100341 |
| C07 | SECURITY/LSA Secrets syntax | 100342 |
| C08 | Security-control impairment syntax | 100333 |
| C09 | Run-key persistence | 100334 |
| C10 | Scheduled-task creation | 100335 |
| C11 | Service creation | 100336 |
| C12 | Remote execution syntax | 100337 |
| C13 | Suspicious `wscript.exe` parent | 100338 |
| C14 | Certutil decode | 100340 |
| C15 | Certutil encode | 100344 |
| C16 | CMD launched by PowerShell | 100339 |
| C17 | CMD launched by RunAs | 100343 |
| C18 | Domain account/group discovery | 100311 |
| C19 | Domain/DC discovery | 100312 |
| C20 | Chained host/network discovery | 100313 |
| C21 | Registry modification | 100314 |
| C22 | File permission modification | 100315 |
| C23 | Basic discovery | 100316 |

## C01 — baseline

```powershell
cmd.exe /d /c 'echo WAZUH_CMD_C01'
```

Expected: Event 4688 and parent rule `100300`; no suspicious child alert.

## C02 — remote-content retrieval

Loopback port 9 should fail closed.

```powershell
cmd.exe /d /c 'curl.exe http://127.0.0.1:9/WAZUH_CMD_C02.bin -o %TEMP%\WAZUH_CMD_C02.bin >nul 2>&1 & del /q %TEMP%\WAZUH_CMD_C02.bin 2>nul & echo WAZUH_CMD_C02'
```

Expected: `100310`, level 10.

## C03 — download and execute chain

The loopback request fails, so no downloaded command executes.

```powershell
cmd.exe /d /c 'curl.exe http://127.0.0.1:9/WAZUH_CMD_C03.cmd -o %TEMP%\WAZUH_CMD_C03.cmd >nul 2>&1 & call %TEMP%\WAZUH_CMD_C03.cmd & del /q %TEMP%\WAZUH_CMD_C03.cmd 2>nul & echo WAZUH_CMD_C03'
```

Expected: `100330`, level 13.

## C04 — encoded PowerShell through CMD

Encoded payload: `Write-Output 'WAZUH_CMD_ENCODED_PAYLOAD'`.

```powershell
cmd.exe /d /c 'powershell.exe -NoProfile -NonInteractive -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFcAQQBaAFUASABfAEMATQBEAF8ARQBOAEMATwBEAEUARABfAFAAQQBZAEwATwBBAEQAJwA= >nul 2>&1 & echo WAZUH_CMD_C04'
```

Expected: `100331`, level 12.

## C05 — LSASS syntax-only control

`echo` keeps the dump command from executing while preserving its full syntax
inside the `cmd.exe` command line.

```powershell
cmd.exe /d /c 'echo rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 999 %TEMP%\WAZUH_CMD_C05.dmp full & echo WAZUH_CMD_C05'
```

Expected: `100332`, level 12.

Real LSASS mechanics live in `tests/lsass_cmd.md`.

## C06 — SAM/SYSTEM dump syntax-only control

```powershell
cmd.exe /d /c 'echo reg.exe save HKLM\SAM %TEMP%\sam.save ^& reg.exe save HKLM\SYSTEM %TEMP%\system.save & echo WAZUH_CMD_C06'
```

Expected: `100341`, level 12. No hive is written.

## C07 — SECURITY/LSA Secrets syntax-only control

```powershell
cmd.exe /d /c 'echo reg.exe save HKLM\SECURITY %TEMP%\security.save & echo WAZUH_CMD_C07'
```

Expected: `100342`, level 12. No hive is written.

## C08 — defense-evasion syntax-only controls

```powershell
cmd.exe /d /c 'echo sc.exe stop WinDefend ^& sc.exe config WinDefend start= disabled & echo WAZUH_CMD_C08A'
cmd.exe /d /c 'echo wevtutil.exe cl Security & echo WAZUH_CMD_C08B'
```

Expected: `100333`, level 12. No service or event log changes occur.

## C09 — temporary Run-key persistence

```powershell
cmd.exe /d /c 'reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PurpleTeam_WazuhCmdTest /t REG_SZ /d "cmd.exe /c echo WAZUH_CMD_C09" /f >nul 2>&1 & reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PurpleTeam_WazuhCmdTest /f >nul 2>&1 & echo WAZUH_CMD_C09'
```

Expected: `100334`, level 11. Value is removed in the same command.

## C10 — temporary scheduled task

```powershell
cmd.exe /d /c 'schtasks.exe /create /tn PurpleTeam_WazuhCmdTest /sc ONCE /st 23:59 /tr "cmd.exe /c exit" /f >nul 2>&1 & schtasks.exe /delete /tn PurpleTeam_WazuhCmdTest /f >nul 2>&1 & echo WAZUH_CMD_C10'
```

Expected: `100335`, level 11.

## C11 — temporary service

```powershell
cmd.exe /d /c 'sc.exe create PurpleTeam_WazuhCmdTest binPath= "cmd.exe /c exit" start= demand >nul 2>&1 & sc.exe delete PurpleTeam_WazuhCmdTest >nul 2>&1 & echo WAZUH_CMD_C11'
```

Expected: `100336`, level 11.

## C12 — remote-service syntax-only control

```powershell
cmd.exe /d /c 'echo sc.exe \\DC01 create PurpleTeam binPath= cmd.exe & echo WAZUH_CMD_C12'
```

Expected: `100337`, level 11. No remote service is created.

## C13 — suspicious parent process

Creates a temporary VBS file so `wscript.exe` launches `cmd.exe`.

```powershell
$Vbs = "$env:TEMP\WAZUH_CMD_C13.vbs"
Set-Content -Path $Vbs -Encoding Ascii -Value @'
CreateObject("WScript.Shell").Run "cmd.exe /d /c echo WAZUH_CMD_C13", 0, True
'@

wscript.exe $Vbs
Remove-Item $Vbs -Force
```

Expected: `100338`, level 10; parent image ends in `wscript.exe`.

## C14 — certutil decode

```powershell
cmd.exe /d /c 'echo V0FaVUhfQ01EX0MxNA== > %TEMP%\WAZUH_CMD_C14-enc.txt & certutil.exe -decode %TEMP%\WAZUH_CMD_C14-enc.txt %TEMP%\WAZUH_CMD_C14-out.txt >nul 2>&1 & del /q %TEMP%\WAZUH_CMD_C14-*.txt & echo WAZUH_CMD_C14'
```

Expected: `100340`, level 8.

## C15 — certutil encode

```powershell
cmd.exe /d /c 'echo WAZUH_CMD_C15 > %TEMP%\WAZUH_CMD_C15-in.txt & certutil.exe -encode %TEMP%\WAZUH_CMD_C15-in.txt %TEMP%\WAZUH_CMD_C15-enc.txt >nul 2>&1 & del /q %TEMP%\WAZUH_CMD_C15-*.txt & echo WAZUH_CMD_C15'
```

Expected: `100344`, level 7.

## C16 — CMD launched by PowerShell

```powershell
Start-Process cmd.exe -ArgumentList '/d /c echo WAZUH_CMD_C16' -Wait
```

Expected: `100339`, level 8; parent image is PowerShell.

## C17 — CMD launched through RunAs

This prompts interactively for the approved local-administrator password.

```powershell
runas.exe /user:WIN01\adam.wilson "cmd.exe /d /c echo WAZUH_CMD_C17"
```

Expected: `100343`, level 7; parent image is `runas.exe`.

## C18 — domain account and group discovery

```powershell
cmd.exe /d /c 'net.exe user /domain >nul 2>&1 & echo WAZUH_CMD_C18A'
cmd.exe /d /c 'net.exe group "Domain Admins" /domain >nul 2>&1 & echo WAZUH_CMD_C18B'
cmd.exe /d /c 'net.exe localgroup Administrators >nul 2>&1 & echo WAZUH_CMD_C18C'
```

Expected: `100311`, level 9.

## C19 — domain/DC discovery

```powershell
cmd.exe /d /c 'nltest.exe /dsgetdc:simulation.local >nul 2>&1 & echo WAZUH_CMD_C19A'
cmd.exe /d /c 'nltest.exe /dclist:simulation.local >nul 2>&1 & echo WAZUH_CMD_C19B'
cmd.exe /d /c 'dir \\DC01\SYSVOL >nul 2>&1 & echo WAZUH_CMD_C19C'
```

Expected: `100312`, level 9.

## C20 — chained host and network discovery

```powershell
cmd.exe /d /c 'whoami.exe >nul 2>&1 & hostname.exe >nul 2>&1 & ipconfig.exe /all >nul 2>&1 & netstat.exe -ano >nul 2>&1 & echo WAZUH_CMD_C20'
```

Expected: `100313`, level 8.

## C21 — temporary registry modification

```powershell
cmd.exe /d /c 'reg.exe add HKCU\Software\PurpleTeam\WazuhCmdTest /v Marker /t REG_SZ /d WAZUH_CMD_C21 /f >nul 2>&1 & reg.exe delete HKCU\Software\PurpleTeam\WazuhCmdTest /f >nul 2>&1 & echo WAZUH_CMD_C21'
```

Expected: `100314`, level 8.

## C22 — temporary file-permission modification

```powershell
cmd.exe /d /c 'echo WAZUH_CMD_C22 > %TEMP%\WAZUH_CMD_C22.txt & icacls.exe %TEMP%\WAZUH_CMD_C22.txt /grant %USERNAME%:R >nul 2>&1 & del /q %TEMP%\WAZUH_CMD_C22.txt & echo WAZUH_CMD_C22'
```

Expected: `100315`, level 8.

## C23 — basic discovery

```powershell
cmd.exe /d /c 'whoami.exe /all >nul 2>&1 & echo WAZUH_CMD_C23'
```

Expected: `100316`, level 5.

## False-positive controls

These should not trigger the suspicious child rules named beside them.

```powershell
cmd.exe /d /c 'reg.exe query HKCU\Software >nul 2>&1 & echo WAZUH_CMD_FP01'
cmd.exe /d /c 'schtasks.exe /query /fo LIST >nul 2>&1 & echo WAZUH_CMD_FP02'
cmd.exe /d /c 'net.exe user >nul 2>&1 & echo WAZUH_CMD_FP03'
cmd.exe /d /c 'curl.exe --version >nul 2>&1 & echo WAZUH_CMD_FP04'
cmd.exe /d /c 'sc.exe query WazuhSvc >nul 2>&1 & echo WAZUH_CMD_FP05'
```

## Local Event 4688 verification

Set `$Start` immediately before each test.

```powershell
$Start = Get-Date

Get-WinEvent -FilterHashtable @{
    LogName   = 'Security'
    Id        = 4688
    StartTime = $Start
} | Where-Object Message -Match 'WAZUH_CMD_' |
    Select-Object TimeCreated, RecordId, Message
```

## Dashboard filter

```text
agent.id:004 AND rule.id:(100310 OR 100311 OR 100312 OR 100313 OR 100314 OR 100315 OR 100316 OR 100330 OR 100331 OR 100332 OR 100333 OR 100334 OR 100335 OR 100336 OR 100337 OR 100338 OR 100339 OR 100340 OR 100341 OR 100342 OR 100343 OR 100344)
```

## Cleanup

```powershell
reg.exe delete HKCU\Software\PurpleTeam\WazuhCmdTest /f 2>$null
reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run `
    /v PurpleTeam_WazuhCmdTest /f 2>$null
schtasks.exe /delete /tn PurpleTeam_WazuhCmdTest /f 2>$null
sc.exe delete PurpleTeam_WazuhCmdTest 2>$null
Remove-Item "$env:TEMP\WAZUH_CMD_*" -Force -ErrorAction SilentlyContinue
```
