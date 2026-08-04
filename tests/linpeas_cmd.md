# LinPEAS — Linux enumeration validation

## Detection

No filename-specific rule. Uses generic rules in `rules/unix_shell_detection.xml`:

```text
100203 / level 7  — remote content retrieval
100205 / level 7  — executable permission added under /tmp
100207 / level 8  — temporary-directory script execution
100220 / level 12 — downloaded content passed to a shell
```

## Trigger

Run as the controlled low-privilege Linux account after staging the script:

```bash
chmod 700 /tmp/WAZUH_linpeas.sh
/bin/bash /tmp/WAZUH_linpeas.sh > /tmp/WAZUH_linpeas.out 2>&1
```

If download telemetry is part of the test, retrieve the approved LinPEAS copy into `/tmp/WAZUH_linpeas.sh` first. Do not hardcode credentials or private URLs in this playbook.

## Dashboard filter

```text
agent.id:003 AND (rule.id:100203 OR rule.id:100205 OR rule.id:100207 OR rule.id:100220 OR rule.id:203)
```

## Cleanup

```bash
rm -f /tmp/WAZUH_linpeas.sh /tmp/WAZUH_linpeas.out
```

## Validation status

Execution and generic detection chain were observed. Final telemetry-integrity verdict remains constrained when fresh rule `203` reports a full agent event queue; rerun after queue health is proven if exhaustive coverage is required.
