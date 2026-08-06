# AMSI bypass prevention and detection — 2026-08-06

## Verdict

```text
AMSI/Defender preflight: PASS
Bounded bypass attempt: BLOCKED BEFORE EXECUTION
AMSI bypass achieved: NO
PowerShell telemetry: PASS
Rule 100538 / level 14 / T1562.001: PASS
Harmless AMSI-text false-positive test: PASS
Cleanup: NOT REQUIRED
Overall: PREVENTION PASS / DETECTION PASS
```

WIN01 ran Windows PowerShell 5.1 in Full Language Mode as `WIN01\adam.wilson`. Defender antivirus, real-time protection, AMSI, Tamper Protection, and Wazuh were active.

The bounded command attempted a process-local reflection change to `System.Management.Automation.AmsiUtils.amsiInitFailed`, using only the harmless EICAR test string for a before/during/after scan comparison. Defender rejected the script at parse time with `ScriptContainedMaliciousContent`. The reflection call did not execute, no bypass occurred, and no payload or persistent setting was created.

The first blocked attempt produced PowerShell 4103 record `163861`. After deriving the live event shape and correcting the parent to native informational rule `60009`, the live retest selected final child rule `100538`, level 14, on record `164327`. Rule `100538` requires both the antivirus block message and AMSI-specific text; it maps to `T1562.001`. Parent rule `100537`, level 12, preserves generic PowerShell antivirus-block visibility and maps to `T1059.001`.

The harmless command `Write-Output 'AmsiScanBuffer documentation review';'AMSI_FP_DONE'` produced PowerShell records `164363`, `164364`, and `164365`. It mentioned AMSI but did not contain an antivirus block result; neither `100537` nor `100538` fired.

The Wazuh manager remained active, and the deployed XML SHA-256 matched the repository file. No cleanup was required because Defender blocked execution before any memory modification.
