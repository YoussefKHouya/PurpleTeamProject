[CmdletBinding()]
param(
    [string]$Target = '__TARGET__',
    [string]$User = '__USER__'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

if ([string]::IsNullOrWhiteSpace($Target) -or $Target -eq '__TARGET__') {
    $Target = Read-Host 'Approved Wazuh Windows agent address'
}
if ([string]::IsNullOrWhiteSpace($User) -or $User -eq '__USER__') {
    $User = Read-Host 'Approved domain test user (DOMAIN\user)'
}

$desktop = [Environment]::GetFolderPath('Desktop')
$stamp = Get-Date -Format 'yyyyMMdd-HHmmss'
$transcript = Join-Path $desktop "Wazuh-MSDOS-$stamp.log"
$credential = Get-Credential -UserName $User -Message 'Credential for approved Wazuh Windows agent'

$cases = @(
    [pscustomobject]@{ Id='CMD01'; Name='Baseline cmd.exe /c marker'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD02'; Name='Command chaining with &&'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD03'; Name='Temporary batch-file execution'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD04'; Name='Environment-variable command indirection'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD05'; Name='Identity and privilege discovery'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD06'; Name='Domain-controller discovery with nltest'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD07'; Name='Registry read-only false-positive test'; Kind='FalsePositive' },
    [pscustomobject]@{ Id='CMD08'; Name='Bounded HKCU registry add/query/delete'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD09'; Name='Scheduled-task query false-positive test'; Kind='FalsePositive' },
    [pscustomobject]@{ Id='CMD10'; Name='Temporary scheduled task create/run/delete'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD11'; Name='Local certutil encode/decode'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD12'; Name='cmd.exe spawning PowerShell'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD13'; Name='Service discovery through sc.exe'; Kind='Positive' },
    [pscustomobject]@{ Id='CMD14'; Name='Normal cmd.exe echo false-positive test'; Kind='FalsePositive' }
)

$remoteCase = {
    param([string]$CaseId, [string]$Marker)

    $ErrorActionPreference = 'Continue'
    $cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
    $testKey = 'HKCU\Software\PurpleTeam\WazuhCmdTest'
    $taskName = 'PurpleTeam_WazuhCmdTest'

    function Invoke-TestCmd([string]$Line) {
        Write-Output "COMMAND=$Line"
        & $cmd /d /c $Line
        Write-Output "CMD_EXIT=$LASTEXITCODE"
    }

    switch ($CaseId) {
        'CMD01' {
            $file = Join-Path $env:TEMP "$Marker.txt"
            Invoke-TestCmd "echo $Marker > `"$file`" & type `"$file`" & del /q `"$file`""
        }
        'CMD02' {
            Invoke-TestCmd "echo ${Marker}_FIRST && echo $Marker"
        }
        'CMD03' {
            $batch = Join-Path $env:TEMP "$Marker.cmd"
            Set-Content -LiteralPath $batch -Encoding Ascii -Value "@echo off`r`necho $Marker`r`n"
            Invoke-TestCmd "`"$batch`""
            Remove-Item -LiteralPath $batch -Force -ErrorAction SilentlyContinue
        }
        'CMD04' {
            Invoke-TestCmd "set WAZUH_CMD=whoami & call %WAZUH_CMD% >nul & echo $Marker"
        }
        'CMD05' {
            Invoke-TestCmd "whoami /all >nul & echo $Marker"
        }
        'CMD06' {
            Invoke-TestCmd "nltest.exe /dsgetdc:simulation.local >nul 2>&1 & echo $Marker"
        }
        'CMD07' {
            Invoke-TestCmd "reg.exe query HKCU\Software >nul 2>&1 & echo $Marker"
        }
        'CMD08' {
            Invoke-TestCmd "reg.exe add $testKey /v DetectionMarker /t REG_SZ /d $Marker /f && reg.exe query $testKey /v DetectionMarker && reg.exe delete $testKey /f"
        }
        'CMD09' {
            Invoke-TestCmd "schtasks.exe /query /fo LIST >nul 2>&1 & echo $Marker"
        }
        'CMD10' {
            $taskFile = Join-Path $env:TEMP "$Marker-task.txt"
            $startTime = (Get-Date).AddMinutes(5).ToString('HH:mm')
            $action = "cmd.exe /d /c echo $Marker ^> `"$taskFile`""
            Invoke-TestCmd "schtasks.exe /create /tn `"$taskName`" /sc ONCE /st $startTime /tr `"$action`" /f && schtasks.exe /run /tn `"$taskName`" & timeout.exe /t 2 /nobreak >nul & schtasks.exe /delete /tn `"$taskName`" /f"
            Remove-Item -LiteralPath $taskFile -Force -ErrorAction SilentlyContinue
        }
        'CMD11' {
            $inputFile = Join-Path $env:TEMP "$Marker-input.txt"
            $encodedFile = Join-Path $env:TEMP "$Marker-encoded.txt"
            $decodedFile = Join-Path $env:TEMP "$Marker-decoded.txt"
            Set-Content -LiteralPath $inputFile -Encoding Ascii -Value $Marker
            Invoke-TestCmd "certutil.exe -encode `"$inputFile`" `"$encodedFile`" >nul && certutil.exe -decode `"$encodedFile`" `"$decodedFile`" >nul && type `"$decodedFile`""
            Remove-Item -LiteralPath $inputFile,$encodedFile,$decodedFile -Force -ErrorAction SilentlyContinue
        }
        'CMD12' {
            Invoke-TestCmd "powershell.exe -NoProfile -NonInteractive -Command `"Write-Output '$Marker'`""
        }
        'CMD13' {
            Invoke-TestCmd "sc.exe query WazuhSvc >nul 2>&1 & echo $Marker"
        }
        'CMD14' {
            Invoke-TestCmd "echo $Marker"
        }
        default {
            throw "Unknown case: $CaseId"
        }
    }
}

$remoteCleanup = {
    $testKey = 'HKCU\Software\PurpleTeam\WazuhCmdTest'
    & reg.exe delete $testKey /f 2>$null | Out-Null
    & schtasks.exe /delete /tn 'PurpleTeam_WazuhCmdTest' /f 2>$null | Out-Null
    Get-ChildItem -LiteralPath $env:TEMP -Filter 'WAZUH_CMD_*' -ErrorAction SilentlyContinue |
        Remove-Item -Force -ErrorAction SilentlyContinue

    & reg.exe query $testKey 2>$null | Out-Null
    $registryKeyPresent = ($LASTEXITCODE -eq 0)
    & schtasks.exe /query /tn 'PurpleTeam_WazuhCmdTest' 2>$null | Out-Null
    $scheduledTaskPresent = ($LASTEXITCODE -eq 0)

    [pscustomobject]@{
        RegistryKeyPresent = $registryKeyPresent
        ScheduledTaskPresent = $scheduledTaskPresent
        MarkerFiles = @(Get-ChildItem -LiteralPath $env:TEMP -Filter 'WAZUH_CMD_*' -ErrorAction SilentlyContinue).Count
    }
}

Start-Transcript -LiteralPath $transcript -Force | Out-Null
try {
    Write-Host "[+] Preflight: $Target" -ForegroundColor Cyan
    $identity = Invoke-Command -ComputerName $Target -Credential $credential -Authentication Negotiate -ScriptBlock {
        [pscustomobject]@{
            Identity = [Security.Principal.WindowsIdentity]::GetCurrent().Name
            Host = $env:COMPUTERNAME
            Cmd = (Get-Command cmd.exe).Source
        }
    }
    $identity | Format-List

    foreach ($case in $cases) {
        Write-Host ''
        Write-Host "[$($case.Id)] $($case.Name) [$($case.Kind)]" -ForegroundColor Yellow
        $choice = Read-Host 'ENTER=run, S=skip, Q=quit'
        if ($choice -match '^(?i)q$') { break }
        if ($choice -match '^(?i)s$') { continue }

        $marker = "WAZUH_$($case.Id)_$([DateTime]::UtcNow.ToString('yyyyMMddHHmmss'))"
        $started = [DateTime]::UtcNow.ToString('o')
        Write-Host "START_UTC=$started MARKER=$marker" -ForegroundColor Cyan

        Invoke-Command `
            -ComputerName $Target `
            -Credential $credential `
            -Authentication Negotiate `
            -ScriptBlock $remoteCase `
            -ArgumentList $case.Id,$marker

        Write-Host "END_UTC=$([DateTime]::UtcNow.ToString('o')) MARKER=$marker" -ForegroundColor Green
        Write-Host 'Wait for Wazuh evidence capture before continuing.' -ForegroundColor DarkGray
    }
}
finally {
    Write-Host '[+] Running final cleanup verification...' -ForegroundColor Cyan
    try {
        $cleanup = Invoke-Command -ComputerName $Target -Credential $credential -Authentication Negotiate -ScriptBlock $remoteCleanup
        $cleanup | Format-List
    }
    catch {
        Write-Warning "Cleanup verification failed: $($_.Exception.Message)"
    }
    Stop-Transcript | Out-Null
    Write-Host "Transcript: $transcript" -ForegroundColor Green
}
