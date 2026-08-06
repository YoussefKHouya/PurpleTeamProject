# Run locally from an interactive PowerShell session as SIMULATION\yassine.karimi.
# Read-only PowerUp closure checks. Downloads pinned upstream source, verifies SHA-256,
# executes two service-enumeration functions, emits JSON, and removes PowerUp artifacts.

$ErrorActionPreference = 'Stop'
$root = Join-Path $env:TEMP 'PowerSploitLocalLab'
$artifact = Join-Path $root 'PowerUp.ps1'
$expected = '9d59d4c128570eb80c0e8d13e2185030f93d965278b203c91dd196b2e1d3cd22'
$started = [DateTime]::UtcNow.ToString('o')

function Invoke-PowerUpCheck {
    param(
        [Parameter(Mandatory)]
        [string]$Name,

        [Parameter(Mandatory)]
        [scriptblock]$Action
    )

    try {
        $items = @(& $Action)

        [pscustomobject]@{
            Name     = $Name
            Status   = 'PASS'
            Findings = $items.Count
            Sample   = @(
                $items |
                    Select-Object -First 10 `
                        ServiceName,
                        Name,
                        Path,
                        StartName,
                        ModifiablePath,
                        IdentityReference
            )
        }
    }
    catch {
        [pscustomobject]@{
            Name   = $Name
            Status = 'FAIL'
            Error  = $_.Exception.Message
        }
    }
}

Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Path $root -Force | Out-Null

try {
    Invoke-WebRequest `
        -UseBasicParsing `
        'https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/d943001a7defb5e0d1657085a77a0e78609be58f/Privesc/PowerUp.ps1' `
        -OutFile $artifact

    if (-not (Test-Path $artifact)) {
        throw 'PowerUp artifact absent after retrieval'
    }

    $hash = (Get-FileHash $artifact -Algorithm SHA256).Hash.ToLower()

    if ($hash -ne $expected) {
        throw "PowerUp hash mismatch: $hash"
    }

    Set-ExecutionPolicy -Scope Process Bypass -Force
    . $artifact

    $checks = @(
        Invoke-PowerUpCheck 'Get-UnquotedService' {
            Get-UnquotedService
        }

        Invoke-PowerUpCheck 'Get-ModifiableService' {
            Get-ModifiableService
        }
    )

    [pscustomobject]@{
        Verdict            = if (@($checks | Where-Object Status -eq 'FAIL').Count) { 'EXECUTION_PASS_WITH_CHECK_FAILURES' } else { 'EXECUTION_PASS' }
        Identity           = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        AuthenticationType = [Security.Principal.WindowsIdentity]::GetCurrent().AuthenticationType
        Integrity          = ((whoami /groups | Select-String 'Mandatory Label') -join '; ')
        SessionId          = (Get-Process -Id $PID).SessionId
        Hash               = $hash
        StartedUtc         = $started
        EndedUtc           = [DateTime]::UtcNow.ToString('o')
        Checks             = $checks
    } | ConvertTo-Json -Depth 8
}
catch {
    [pscustomobject]@{
        Verdict   = 'BLOCKED_OR_FAILED'
        Identity  = [Security.Principal.WindowsIdentity]::GetCurrent().Name
        StartedUtc = $started
        EndedUtc   = [DateTime]::UtcNow.ToString('o')
        Error      = $_.Exception.Message
    } | ConvertTo-Json -Depth 5
}
finally {
    Remove-Item $root -Recurse -Force -ErrorAction SilentlyContinue
}
