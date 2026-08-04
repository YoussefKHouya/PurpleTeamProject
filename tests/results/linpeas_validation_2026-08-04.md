# LinPEAS validation result — 2026-08-04

## Verdict

**EXECUTION/DETECTION PASS; TELEMETRY INTEGRITY CONSTRAINED**.

## Execution

- Endpoint: Linux workstation / Wazuh agent `003`
- Identity: controlled low-privilege user
- Output: 1,288 lines / 101,270 bytes
- Temporary script and output: removed

## Live generic detections

```text
100203 / level 7  — retrieval
100205 / level 7  — chmod under /tmp
100207 / level 8  — /tmp script execution
100220 / level 12 — download-to-shell chain
```

No LinPEAS filename rule was added; the generic chain survives renaming.

## Integrity limitation

Fresh Wazuh rule `203` reported:

```text
Agent event queue is full. Events may be lost.
Agent: 003
Level: 9
Fired times observed: 33
Timestamp: 2026-08-04T09:14:55.608+0000
```

A queue of 10,000 with 1,000 EPS remained insufficient under the follow-up load. An attempted larger configuration created duplicate `client_buffer` blocks and was rolled back to the known-good configuration. Exhaustive final coverage must not be claimed until a clean rerun has no fresh rule `203`.

## Artifacts

```text
rules/unix_shell_detection.xml
tests/linpeas_cmd.md
```
