# WinRM remote-execution playbook

## Scope

- Technique: `T1021.006` — Windows Remote Management
- Source: controlled management host through Kali bridge
- Target: WIN01 only
- Identity: controlled WIN01 administrator
- Transport: HTTP/WinRM with NTLM inside the lab route

Credentials must be loaded from an ignored local fixture and supplied in memory.
Never place passwords in argv, Git, reports, or target command lines.

## Preflight

```powershell
$f='C:\ProgramData\WazuhLab\winrm_<UTC>.json'
[pscustomobject]@{
  UTC=(Get-Date).ToUniversalTime().ToString('o')
  Identity=[Security.Principal.WindowsIdentity]::GetCurrent().Name
  MarkerExists=Test-Path $f
  Wazuh=(Get-Service WazuhSvc).Status
}
auditpol /get /subcategory:'Process Creation'
```

Require intended identity, marker absence, Wazuh running, and Security `4688`
auditing enabled.

## Bounded trigger

Execute one PowerShell payload through WinRM that:

1. Creates `C:\ProgramData\WazuhLab` if absent.
2. Records UTC, identity, hostname, PID, image, parent PID/image, and transport.
3. Writes one uniquely named JSON marker.
4. Returns the marker and exits.

Do not run an interactive shell, download payloads, alter accounts/services/policy,
or perform unrelated discovery.

## Expected evidence

```text
Security 4688: WinrsHost.exe -> cmd.exe -> powershell.exe
Sysmon 1: same parent/child chain
Sysmon 11: marker creation
Wazuh 100331 level 12: CMD launched encoded PowerShell
Wazuh 100110 level 10: encoded PowerShell
Wazuh 92052: cmd.exe from abnormal WinrsHost parent
```

Primary Dashboard filter:

```text
agent.id:"004" AND rule.id:"100331" AND data.win.system.eventRecordID:"<CMD_4688_RECORD>"
```

## False-positive test

Authenticate, open a WinRM shell, and close it without executing any command.
Expected generic `WinrsHost.exe`/`conhost.exe` process visibility is acceptable;
rules `100331` and `100110` must not fire because no command payload exists.

## Cleanup

Delete the marker and empty test directory. Close the WinRM shell and verify
Wazuh/firewall health. Defender restoration is handled once at final batch closure,
not per test, because the operator intentionally kept it disabled.
