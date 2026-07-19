# Linux Audit Execution Telemetry

This directory contains agent-side telemetry required by `rules/unix_shell_detection.xml`.

## Files

- `50-wazuh-shell.rules` — auditd `execve`/`execveat` capture for real login users
- `wazuh-audit-exec-json.py` — correlates audit records, decodes hex arguments, emits normalized JSON Lines
- `wazuh-exec.conf` — audit dispatcher plugin configuration
- `ossec-audit-localfile.xml` — Wazuh agent collection blocks
- `wazuh-audit-exec.logrotate` — bounded JSON log retention

## Deployed paths

```text
/etc/audit/rules.d/50-wazuh-shell.rules
/etc/audit/plugins.d/wazuh-exec.conf
/usr/local/sbin/wazuh-audit-exec-json
/etc/logrotate.d/wazuh-audit-exec
/var/log/wazuh-audit-exec.json
```

Wazuh agent collects:

```text
/var/log/audit/audit.log
/var/log/wazuh-audit-exec.json
```

## Why normalization exists

Linux auditd hex-encodes unsafe or whitespace-containing EXECVE arguments. Wazuh 4.14.6 decoded quoted arguments but omitted hex-encoded shell payloads such as `bash -c "..."` from `audit.execve.a2`.

The normalizer restores complete arguments and emits fields including:

```json
{
  "event_source": "auditd_execve",
  "exe": "/usr/bin/bash",
  "auid": "1000",
  "uid": "1000",
  "argv": ["bash", "-c", "echo example"],
  "command_line": "bash -c 'echo example'"
}
```

## Verification

```bash
sudo auditctl -l
sudo auditctl -s
systemctl is-active auditd wazuh-agent
pgrep -af '^python3 /usr/local/sbin/wazuh-audit-exec-json'
sudo /var/ossec/bin/wazuh-agentd -t
```

Expected audit status includes `lost 0`.
