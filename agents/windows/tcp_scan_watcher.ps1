# WIN01 target-side TCP scan watcher.
# Uses built-in pktmon to observe inbound SYN packets between one approved
# source/target pair and emits Windows Application events collected by Wazuh.
[CmdletBinding()]
param(
  [string]$SourceIp = '192.168.56.101',
  [string]$TargetIp = '192.168.56.111',
  [int]$WindowSeconds = 10,
  [int]$DistinctPortThreshold = 20,
  [int]$QuietSeconds = 15,
  [int]$PollMilliseconds = 250,
  [string]$WorkDirectory = 'C:\ProgramData\WazuhLab'
)

$ErrorActionPreference = 'Stop'
$provider = 'WazuhTcpScanWatcher'
$outputPath = Join-Path $WorkDirectory 'tcp_scan_pktmon.out'
$errorPath = Join-Path $WorkDirectory 'tcp_scan_pktmon.err'

if (-not [System.Diagnostics.EventLog]::SourceExists($provider)) {
  New-EventLog -LogName Application -Source $provider
}

function Write-ScanEvent {
  param([int]$EventId, [string]$EventType, [hashtable]$Data)
  $body = [ordered]@{
    event_type = $EventType
    source_ip = $SourceIp
    target_ip = $TargetIp
    host = $env:COMPUTERNAME
    window_seconds = $WindowSeconds
    distinct_port_threshold = $DistinctPortThreshold
  }
  foreach ($key in $Data.Keys) { $body[$key] = $Data[$key] }
  Write-EventLog -LogName Application -Source $provider -EventId $EventId `
    -EntryType Information -Message ($body | ConvertTo-Json -Compress)
}

New-Item -ItemType Directory -Force $WorkDirectory | Out-Null
$fatalPath = Join-Path $WorkDirectory 'tcp_scan_watcher_fatal.log'
Remove-Item $outputPath,$errorPath,$fatalPath -Force -ErrorAction SilentlyContinue
trap {
  $fatal = "$(Get-Date -Format o) $($_.Exception.GetType().FullName): $($_.Exception.Message)"
  try { Set-Content -LiteralPath $fatalPath -Value $fatal -Encoding UTF8 } catch {}
  try {
    Write-ScanEvent -EventId 1102 -EventType 'tcp_scan_watcher_error' -Data @{
      sensor = 'pktmon'
      error_type = $_.Exception.GetType().FullName
      error_message = $_.Exception.Message
    }
  } catch {}
  exit 1
}

# Pktmon filter matches packets containing both exact IPs and TCP SYN.
# Direction is enforced again by parser below.
& cmd.exe /d /c 'pktmon stop >nul 2>&1' | Out-Null
& cmd.exe /d /c 'pktmon filter remove >nul 2>&1' | Out-Null
$filterOutput = (pktmon filter add WazuhScan -i $SourceIp $TargetIp -t TCP SYN 2>&1) -join ' '
if ($LASTEXITCODE -ne 0) { throw "pktmon filter failed: $filterOutput" }

$pktmonArgs = 'start --capture --comp nics --pkt-size 128 --log-mode real-time'
$pktmon = Start-Process -FilePath "$env:SystemRoot\System32\pktmon.exe" `
  -ArgumentList $pktmonArgs -RedirectStandardOutput $outputPath `
  -RedirectStandardError $errorPath -WindowStyle Hidden -PassThru
Start-Sleep -Seconds 1
if ($pktmon.HasExited) {
  $detail = if (Test-Path $errorPath) { (Get-Content $errorPath) -join ' ' } else { 'no stderr' }
  throw "pktmon exited during startup: $detail"
}

Write-ScanEvent -EventId 1100 -EventType 'tcp_scan_watcher_ready' -Data @{
  sensor = 'pktmon'
  pktmon_pid = $pktmon.Id
  quiet_seconds = $QuietSeconds
  poll_milliseconds = $PollMilliseconds
}

$position = [int64]0
$observations = @()
$alerted = $false
$alertFirstSeen = $null
$lastMatch = $null
$totalMatches = 0
$lastErrorMessage = $null
$lastErrorTime = [datetime]::MinValue
$packetPattern = '^\s*[^ ]+\s+>\s+[^,]+,.*:\s+' +
  [regex]::Escape($SourceIp) + '\.(\d+)\s+>\s+' +
  [regex]::Escape($TargetIp) + '\.(\d+):\s+Flags\s+\[S\],'

while ($true) {
  $now = [datetime]::UtcNow
  try {
    if ($pktmon.HasExited) {
      $detail = if (Test-Path $errorPath) { (Get-Content $errorPath) -join ' ' } else { 'no stderr' }
      throw "pktmon exited unexpectedly with $($pktmon.ExitCode): $detail"
    }

    if (Test-Path $outputPath) {
      $share = [IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete
      $stream = [IO.File]::Open($outputPath,[IO.FileMode]::Open,[IO.FileAccess]::Read,$share)
      try {
        if ($stream.Length -lt $position) { $position = 0 }
        [void]$stream.Seek($position,[IO.SeekOrigin]::Begin)
        $reader = New-Object IO.StreamReader($stream)
        try {
          while (($line = $reader.ReadLine()) -ne $null) {
            $match = [regex]::Match($line,$packetPattern)
            if (-not $match.Success) { continue }
            $port = [int]$match.Groups[2].Value
            $observations += [pscustomobject]@{ Seen = $now; Port = $port }
            $lastMatch = $now
            $totalMatches++
          }
        } finally {
          $position = $stream.Length
          $reader.Dispose()
        }
      } finally {
        $stream.Dispose()
      }
    }

    $cutoff = $now.AddSeconds(-$WindowSeconds)
    $observations = @($observations | Where-Object { $_.Seen -ge $cutoff })
    $ports = @($observations | Select-Object -ExpandProperty Port -Unique | Sort-Object)

    if (-not $alerted -and $ports.Count -ge $DistinctPortThreshold) {
      $alerted = $true
      $alertFirstSeen = $now
      Write-ScanEvent -EventId 1101 -EventType 'tcp_port_scan_detected' -Data @{
        sensor = 'pktmon'
        distinct_ports = $ports.Count
        packet_count_window = $observations.Count
        sample_ports = (($ports | Select-Object -First 32) -join ',')
        first_alert_utc = $now.ToString('o')
      }
    }

    if ($alerted -and $lastMatch -and (($now - $lastMatch).TotalSeconds -ge $QuietSeconds)) {
      Write-ScanEvent -EventId 1103 -EventType 'tcp_scan_quiet' -Data @{
        sensor = 'pktmon'
        total_matching_syns = $totalMatches
        alert_first_seen_utc = $alertFirstSeen.ToString('o')
        last_packet_utc = $lastMatch.ToString('o')
      }
      $alerted = $false
      $alertFirstSeen = $null
      $lastMatch = $null
      $totalMatches = 0
      $observations = @()
    }
  } catch {
    $message = $_.Exception.Message
    if ($message -ne $lastErrorMessage -or (($now - $lastErrorTime).TotalSeconds -ge 60)) {
      Write-ScanEvent -EventId 1102 -EventType 'tcp_scan_watcher_error' -Data @{
        sensor = 'pktmon'
        error_type = $_.Exception.GetType().FullName
        error_message = $message
      }
      $lastErrorMessage = $message
      $lastErrorTime = $now
    }
  }
  Start-Sleep -Milliseconds $PollMilliseconds
}
