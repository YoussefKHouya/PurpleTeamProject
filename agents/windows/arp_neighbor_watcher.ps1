# Wazuh ARP-neighbor integrity watcher for WIN01 Ethernet.
# Emits Windows Application events. Wazuh already collects this channel.
[CmdletBinding()]
param(
  [string]$InterfaceAlias = 'Ethernet',
  [string]$WatchIp = '172.16.2.17',
  [string]$ExpectedMac = '08-00-27-0C-FE-D8',
  [int]$IntervalSeconds = 1
)

$ErrorActionPreference = 'Stop'
$source = 'WazuhArpWatcher'
if (-not [System.Diagnostics.EventLog]::SourceExists($source)) {
  New-EventLog -LogName Application -Source $source
}

function Write-ArpEvent {
  param([string]$EventType, [int]$EventId, [string]$ObservedMac, [string]$PreviousMac, [string]$State)
  $message = [pscustomobject]@{
    event_type     = $EventType
    interface      = $InterfaceAlias
    ip_address     = $WatchIp
    expected_mac   = $ExpectedMac.ToUpperInvariant()
    observed_mac   = $ObservedMac
    previous_mac   = $PreviousMac
    neighbor_state = $State
    host           = $env:COMPUTERNAME
  } | ConvertTo-Json -Compress
  Write-EventLog -LogName Application -Source $source -EventId $EventId -EntryType Information -Message $message
}

$previousMac = $null
$first = $true
while ($true) {
  try {
    $neighbor = Get-NetNeighbor -InterfaceAlias $InterfaceAlias -AddressFamily IPv4 -IPAddress $WatchIp -ErrorAction SilentlyContinue
    $mac = if ($neighbor) { $neighbor.LinkLayerAddress.ToUpperInvariant() } else { $null }
    $state = if ($neighbor) { [string]$neighbor.State } else { 'Absent' }

    if ($first) {
      Write-ArpEvent -EventType 'arp_neighbor_baseline' -EventId 1000 -ObservedMac $mac -PreviousMac $null -State $state
      $first = $false
    } elseif ($mac -ne $previousMac) {
      if ($mac -eq $ExpectedMac.ToUpperInvariant()) {
        Write-ArpEvent -EventType 'arp_neighbor_restored' -EventId 1003 -ObservedMac $mac -PreviousMac $previousMac -State $state
      } else {
        Write-ArpEvent -EventType 'arp_neighbor_change' -EventId 1001 -ObservedMac $mac -PreviousMac $previousMac -State $state
      }
    }
    $previousMac = $mac
  } catch {
    Write-ArpEvent -EventType 'arp_watcher_error' -EventId 1002 -ObservedMac $null -PreviousMac $previousMac -State $_.Exception.GetType().Name
  }
  Start-Sleep -Seconds $IntervalSeconds
}
