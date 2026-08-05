# TCP scan watcher — WIN01/Wazuh validation

## Purpose

Detect broad TCP port scans from one source against WIN01 without depending on
`nmap`, `masscan`, filename, packet window fingerprint, or scanner output.

Evidence source:

```text
Windows built-in pktmon exact-IP TCP SYN capture
  -> WIN01 SYSTEM watcher
  -> Windows Application provider WazuhTcpScanWatcher
  -> Wazuh custom rules
```

Versioned components:

```text
agents/windows/tcp_scan_watcher.ps1
rules/tcp_scan_detection.xml
```

## Scope

```text
Source:      <AUTHORIZED_SCANNER_IPV4>
Target:      <WIN01_IPV4>
Protocol:    dropped inbound TCP
Window:      10 seconds
Threshold:   20 distinct destination ports
Quiet reset: 15 seconds
```

Only exact source-to-target inbound SYN records count. Reverse SYN-ACK traffic and
normal repeated connections to a small port set remain below threshold. Detection
is behavior-based and covers Masscan, Nmap SYN, and custom scanners.

## Baseline

Record any existing `pktmon` session/filters, task/provider absence, and Wazuh
health. The watcher must own no pre-existing packet-monitor session. Cleanup must
stop pktmon and remove its exact filter/output files.

```powershell
pktmon status
pktmon filter list
Get-ScheduledTask -TaskName WazuhTcpScanWatcher -ErrorAction SilentlyContinue
Get-Service WazuhSvc
```

## Deploy Wazuh rule

```bash
sudo install -o root -g wazuh -m 0640 \
  rules/tcp_scan_detection.xml \
  /var/ossec/etc/rules/tcp_scan_detection.xml
sudo /var/ossec/bin/wazuh-analysisd -t
sudo systemctl restart wazuh-manager
sudo systemctl is-active wazuh-manager
```

Require agent `004` Active again before endpoint trigger.

## Deploy watcher

Place script at:

```text
C:\ProgramData\WazuhLab\tcp_scan_watcher.ps1
```

The script owns one exact `pktmon` filter and starts real-time capture. Register a
SYSTEM task with arguments:

```powershell
-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "C:\ProgramData\WazuhLab\tcp_scan_watcher.ps1" -SourceIp <AUTHORIZED_SCANNER_IPV4> -TargetIp <WIN01_IPV4> -WindowSeconds 10 -DistinctPortThreshold 20 -QuietSeconds 15
```

Require:

1. Task state `Running` under SYSTEM.
2. Local Application Event `1100`, provider `WazuhTcpScanWatcher`.
3. Wazuh rule `100510` from agent `004`.

## Positive test

Run one bounded scanner only. Require local Event `1101` and Wazuh rule
`100511` level `12`, MITRE `T1046`. Preserve source, target, distinct-port count,
window packet count, and sample ports from event message.

Wait for Event `1103` / Wazuh `100513` before next test.

## False-positive controls

```bash
sudo nmap -sS -Pn -n -p 445 --max-retries 0 <WIN01_IPV4>
sudo nmap -sS -Pn -n -p 135,139,445,3389 --max-rate 1 --max-retries 0 <WIN01_IPV4>
```

Expected: SYN records may exist, but fewer than 20 distinct ports in ten seconds;
no new Event `1101` or Wazuh `100511`.

## Cleanup

```powershell
Stop-ScheduledTask -TaskName WazuhTcpScanWatcher
Unregister-ScheduledTask -TaskName WazuhTcpScanWatcher -Confirm:$false
pktmon stop
pktmon filter remove
Remove-Item C:\ProgramData\WazuhLab\tcp_scan_watcher.ps1,
  C:\ProgramData\WazuhLab\tcp_scan_pktmon.out,
  C:\ProgramData\WazuhLab\tcp_scan_pktmon.err -Force
```

Remove custom event source only after all evidence is collected. Verify task,
script, output files, pktmon session, and filter absent; verify `WazuhSvc`, manager,
and agent `004` healthy.
