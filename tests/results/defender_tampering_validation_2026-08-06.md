# Microsoft Defender preference tampering — 2026-08-06

## Verdict

```text
Defender exclusion change: PASS
PowerShell telemetry: PASS
Custom rule 100536: PASS
Read-only false-positive test: PASS
Manager health and deployed hash: PASS
Cleanup: PASS
Overall: COMPLETE / PASS
```

An Administrator PowerShell session added the controlled exclusion `C:\ProgramData\DefenderTamperLab`. The endpoint confirmed that the exclusion existed. This was a bounded lab-only Defender preference change; Defender was not disabled globally.

Rule `100536`, level 10, mapped to `T1562.001`, fired on PowerShell 4104 record `161611`. A later final trigger also fired as rule `100536` on record `162758`. The rule detects `Add-MpPreference` or `Set-MpPreference` script blocks containing Defender exclusion or explicit protection-disable syntax and describes the telemetry as an impairment attempt.

The read-only command `(Get-MpPreference).DisableRealtimeMonitoring` produced PowerShell 4104 record `161641` and no custom Defender-tampering alert. The returned value was `False`; the command did not alter Defender configuration.

A proposed 4103 high-confidence rule was not retained. Live 4103 records `161612`, `162459`, and `162759` preserved the `Add-MpPreference` invocation, but two bounded refinements did not produce a custom alert because the live payload carries doubled escaped separators and follows a distinct PowerShell parent shape. Proven rule `100536` remains deployed; no unvalidated rule was versioned.

The Wazuh manager remained active, and the final deployed XML SHA-256 matched the repository file. The operator removed the controlled exclusion and directory; the endpoint returned `DEFENDER_CLEANUP=PASS`.
