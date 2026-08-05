# PsExec remote-execution playbook

## Scope

- Techniques: `T1021.002` — SMB/Windows Admin Shares
- Technique: `T1569.002` — Service Execution
- Source: controlled Kali lab host
- Target: WIN01 only
- Tool: Impacket `psexec`
- Identity: controlled account proven local administrator on WIN01

Credentials must be supplied through an interactive/in-memory prompt. Never place
the password in argv, scripts, Git, reports, or Wazuh-visible command lines.

## Preflight

```text
Kali -> WIN01 TCP/445
WIN01 LanmanServer and RpcSs running
WIN01 ADMIN$ writable by selected account
WIN01 Wazuh agent 004 Active
marker/service/file absent
```

If inbound SMB is blocked, use one temporary firewall rule limited to Kali's lab
address and TCP/445. Record and remove it after the atomic test.

## Bounded trigger

From Kali, invoke Impacket PsExec noninteractively and run one `cmd.exe /Q /c`
command that:

1. Creates `C:\ProgramData\WazuhLab` if absent.
2. Writes `whoami`, hostname, and time to a uniquely named marker.
3. Exits immediately.

Do not request an interactive SYSTEM shell, download payloads, alter accounts,
install persistence, or run unrelated discovery.

## Expected evidence

```text
System 7045: randomized service and %systemroot% randomized binary
Security 4688: services.exe -> service binary -> cmd.exe
Sysmon 1/11: service binary, SYSTEM child, marker
Security 4624/5140/5145 when auditing exposes network/share access
Wazuh 92650 level 12: root-path service likely dropped via ADMIN$
Wazuh 67027: generic process creation
```

Primary Dashboard filter:

```text
agent.id:"004" AND rule.id:"92650" AND data.win.system.eventRecordID:"<7045_RECORD>"
```

## False-positive test

Perform authenticated SMB share listing only. It may create network/share events,
but must not create System `7045`, service binary/process, marker, or rule `92650`.

## Cleanup

Verify Impacket removed randomized service/binary. Remove marker, empty test
directory, exact WER report caused by the randomized service if present, and the
temporary SMB firewall rule. Confirm TCP/445 returns to baseline, services remain
healthy, and no rule `203` queue-loss alert appears.
