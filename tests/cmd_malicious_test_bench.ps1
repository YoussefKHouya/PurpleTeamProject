[CmdletBinding()]
param(
    [string]$Target,
    [string]$User,
    [string]$Domain = 'simulation.local',
    [string]$DomainController
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Target)) {
    $Target = Read-Host 'Approved Wazuh Windows agent address'
}
if ([string]::IsNullOrWhiteSpace($User)) {
    $User = Read-Host 'Approved domain test user (DOMAIN\user)'
}
if ([string]::IsNullOrWhiteSpace($DomainController)) {
    $DomainController = Read-Host 'Approved domain-controller hostname or address'
}

$credential = Get-Credential -UserName $User -Message 'Credential for approved Wazuh Windows agent'
$desktop = [Environment]::GetFolderPath('Desktop')
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $desktop "Wazuh-CMD-Malicious-Bench-$stamp.log"

$payload = "Write-Output 'WAZUH_CMD_ENCODED_PAYLOAD'"
$encodedPayload = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($payload))

$cases = @(
    [pscustomobject]@{ Id='M01'; Mode='EXEC'; Name='Baseline CMD'; Command='echo {MARKER}' },
    [pscustomobject]@{ Id='M02'; Mode='EXEC'; Name='Chained host/network discovery'; Command='whoami.exe /all >nul & hostname.exe >nul & ipconfig.exe /all >nul & netstat.exe -ano >nul & echo {MARKER}' },
    [pscustomobject]@{ Id='M03'; Mode='EXEC'; Name='Domain account enumeration'; Command='net.exe user /domain >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M04'; Mode='EXEC'; Name='Privileged domain-group enumeration'; Command='net.exe group "Domain Admins" /domain >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M05'; Mode='EXEC'; Name='Domain-controller discovery'; Command='nltest.exe /dsgetdc:{DOMAIN} >nul 2>&1 & nltest.exe /dclist:{DOMAIN} >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M06'; Mode='EXEC'; Name='Domain-trust discovery'; Command='nltest.exe /domain_trusts >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M07'; Mode='EXEC'; Name='Explicit DC SYSVOL access'; Command='dir \\{DC}\SYSVOL >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M08'; Mode='EXEC'; Name='Domain view discovery'; Command='net.exe view /domain:{DOMAIN} >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M09'; Mode='EXEC'; Name='Certutil loopback URL retrieval'; Command='certutil.exe -urlcache -split -f http://127.0.0.1:9/{MARKER}.bin %TEMP%\{MARKER}.bin >nul 2>&1 & del /q %TEMP%\{MARKER}.bin 2>nul & echo {MARKER}' },
    [pscustomobject]@{ Id='M10'; Mode='EXEC'; Name='Curl download-and-execute syntax'; Command='curl.exe http://127.0.0.1:9/{MARKER}.cmd -o %TEMP%\{MARKER}.cmd >nul 2>&1 & call %TEMP%\{MARKER}.cmd & del /q %TEMP%\{MARKER}.cmd 2>nul & echo {MARKER}' },
    [pscustomobject]@{ Id='M11'; Mode='EXEC'; Name='CMD launches encoded PowerShell'; Command='powershell.exe -NoProfile -NonInteractive -EncodedCommand {ENCODED} >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M12'; Mode='EXEC'; Name='Registry Run-key persistence marker'; Command='reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PurpleTeam_WazuhCmdTest /t REG_SZ /d "cmd.exe /c echo {MARKER}" /f >nul 2>&1 & reg.exe delete HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v PurpleTeam_WazuhCmdTest /f >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M13'; Mode='EXEC'; Name='Generic registry modification'; Command='reg.exe add HKCU\Software\PurpleTeam\WazuhCmdTest /v Marker /t REG_SZ /d {MARKER} /f >nul 2>&1 & reg.exe delete HKCU\Software\PurpleTeam\WazuhCmdTest /f >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M14'; Mode='EXEC'; Name='Scheduled-task create/delete'; Command='schtasks.exe /create /tn PurpleTeam_WazuhCmdTest /sc ONCE /st 23:59 /tr "cmd.exe /c echo {MARKER}" /f >nul 2>&1 & schtasks.exe /delete /tn PurpleTeam_WazuhCmdTest /f >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M15'; Mode='EXEC'; Name='Service creation/deletion attempt'; Command='sc.exe create PurpleTeam_WazuhCmdTest binPath= "cmd.exe /c echo {MARKER} > %TEMP%\{MARKER}-service.txt" start= demand >nul 2>&1 & sc.exe delete PurpleTeam_WazuhCmdTest >nul 2>&1 & del /q %TEMP%\{MARKER}-service.txt 2>nul & echo {MARKER}' },
    [pscustomobject]@{ Id='M16'; Mode='EXEC'; Name='File permission modification'; Command='echo {MARKER} > %TEMP%\{MARKER}.txt & icacls.exe %TEMP%\{MARKER}.txt /grant %USERNAME%:R >nul 2>&1 & del /q %TEMP%\{MARKER}.txt & echo {MARKER}' },
    [pscustomobject]@{ Id='M17'; Mode='EXEC'; Name='Environment-variable command indirection'; Command='set WAZUH_CMD=whoami.exe & call %WAZUH_CMD% >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='M18'; Mode='EXEC'; Name='Temporary batch-file execution'; Command='echo @echo {MARKER} > %TEMP%\{MARKER}.cmd & call %TEMP%\{MARKER}.cmd & del /q %TEMP%\{MARKER}.cmd' },
    [pscustomobject]@{ Id='M19'; Mode='EXEC'; Name='Certutil local encode/decode'; Command='echo {MARKER} > %TEMP%\{MARKER}-in.txt & certutil.exe -encode %TEMP%\{MARKER}-in.txt %TEMP%\{MARKER}-enc.txt >nul & certutil.exe -decode %TEMP%\{MARKER}-enc.txt %TEMP%\{MARKER}-out.txt >nul & del /q %TEMP%\{MARKER}-*.txt & echo {MARKER}' },
    [pscustomobject]@{ Id='M20'; Mode='SYNTAX'; Name='Credential-dump syntax without execution'; Command='echo reg.exe save HKLM\SAM %TEMP%\sam.save ^& reg.exe save HKLM\SYSTEM %TEMP%\system.save & echo {MARKER}' },
    [pscustomobject]@{ Id='M21'; Mode='SYNTAX'; Name='LSASS dump syntax without execution'; Command='echo rundll32.exe C:\Windows\System32\comsvcs.dll MiniDump 999 %TEMP%\lsass.dmp full & echo {MARKER}' },
    [pscustomobject]@{ Id='M22'; Mode='SYNTAX'; Name='Disable Defender syntax without execution'; Command='echo sc.exe stop WinDefend ^& sc.exe config WinDefend start= disabled & echo {MARKER}' },
    [pscustomobject]@{ Id='M23'; Mode='SYNTAX'; Name='Clear Security log syntax without execution'; Command='echo wevtutil.exe cl Security & echo {MARKER}' },
    [pscustomobject]@{ Id='M24'; Mode='SYNTAX'; Name='Remote service execution syntax without execution'; Command='echo sc.exe \\{DC} create PurpleTeam binPath= cmd.exe & echo {MARKER}' },
    [pscustomobject]@{ Id='FP01'; Mode='FP'; Name='Registry read only'; Command='reg.exe query HKCU\Software >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='FP02'; Mode='FP'; Name='Scheduled-task query only'; Command='schtasks.exe /query /fo LIST >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='FP03'; Mode='FP'; Name='Local net user only'; Command='net.exe user >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='FP04'; Mode='FP'; Name='Curl version only'; Command='curl.exe --version >nul 2>&1 & echo {MARKER}' },
    [pscustomobject]@{ Id='FP05'; Mode='FP'; Name='Normal service query'; Command='sc.exe query WazuhSvc >nul 2>&1 & echo {MARKER}' }
)

$remoteCleanup = {
    & reg.exe delete 'HKCU\Software\PurpleTeam\WazuhCmdTest' /f 2>$null | Out-Null
    & reg.exe delete 'HKCU\Software\Microsoft\Windows\CurrentVersion\Run' /v 'PurpleTeam_WazuhCmdTest' /f 2>$null | Out-Null
    & schtasks.exe /delete /tn 'PurpleTeam_WazuhCmdTest' /f 2>$null | Out-Null
    & sc.exe delete 'PurpleTeam_WazuhCmdTest' 2>$null | Out-Null
    Get-ChildItem -LiteralPath $env:TEMP -Filter 'WAZUH_M*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
    Get-ChildItem -LiteralPath $env:TEMP -Filter 'WAZUH_FP*' -ErrorAction SilentlyContinue | Remove-Item -Force -ErrorAction SilentlyContinue
}

Start-Transcript -LiteralPath $transcript -Force | Out-Null
try {
    Write-Host '[+] Verifying WinRM target...' -ForegroundColor Cyan
    Invoke-Command -ComputerName $Target -Credential $credential -Authentication Negotiate -ScriptBlock {
        [pscustomobject]@{ CmdPresent=(Test-Path "$env:SystemRoot\System32\cmd.exe"); Temp=$env:TEMP }
    } | Format-List

    foreach ($case in $cases) {
        Write-Host ''
        Write-Host "[$($case.Id)] [$($case.Mode)] $($case.Name)" -ForegroundColor Yellow
        $choice = Read-Host 'ENTER=run, S=skip, Q=quit and cleanup'
        if ($choice -match '^(?i)q$') { break }
        if ($choice -match '^(?i)s$') { continue }

        $marker = "WAZUH_$($case.Id)_$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
        $line = $case.Command.Replace('{MARKER}',$marker).Replace('{DOMAIN}',$Domain).Replace('{DC}',$DomainController).Replace('{ENCODED}',$encodedPayload)

        Write-Host "START_UTC=$([DateTime]::UtcNow.ToString('o'))" -ForegroundColor Cyan
        Write-Host "MARKER=$marker" -ForegroundColor Cyan
        Write-Host "CMD=$line" -ForegroundColor DarkGray

        Invoke-Command -ComputerName $Target -Credential $credential -Authentication Negotiate -ScriptBlock {
            param([string]$CommandLine)
            & cmd.exe /d /v:on /c $CommandLine
            [pscustomobject]@{ CmdExit=$LASTEXITCODE }
        } -ArgumentList $line

        Write-Host "END_UTC=$([DateTime]::UtcNow.ToString('o'))" -ForegroundColor Green
        Write-Host 'Stop here until Wazuh evidence for this marker is checked.' -ForegroundColor Magenta
    }
}
finally {
    Write-Host '[+] Cleanup...' -ForegroundColor Cyan
    try {
        Invoke-Command -ComputerName $Target -Credential $credential -Authentication Negotiate -ScriptBlock $remoteCleanup
        Write-Host 'Cleanup command completed.' -ForegroundColor Green
    }
    catch {
        Write-Warning "Cleanup failed: $($_.Exception.Message)"
    }
    Stop-Transcript | Out-Null
    Write-Host "Transcript=$transcript" -ForegroundColor Green
}
