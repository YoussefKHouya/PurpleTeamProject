# LOLBins validation result — 2026-08-04

## Verdict

**PASS** — all four controlled signed-binary scenarios produced live custom alerts on WIN01 agent `004`.

## Live evidence

```text
100473 / level 8  — CertUtil decode
100474 / level 6  — CertUtil encode
100475 / level 8  — MSHTA local HTA execution
100476 / level 10 — Regsvr32 local scriptlet proxy
100477 / level 10 — Rundll32 LaunchINFSection proxy
```

Latest clean executions were approximately `11:34 UTC`. Tests used local harmless files and native signed Windows binaries; no remote payload was downloaded. Temporary HTA, scriptlet, INF, encoded, decoded, and marker files were removed.

## Artifacts

```text
rules/lolbins_detection.xml
tests/lolbin_cmd.md
```
