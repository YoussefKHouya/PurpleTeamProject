# Wazuh PowerShell Detection Test Cases

Purpose: harmless purple-team probes for `powershell_detection.xml`.

These commands are not payloads. They emit test strings, use loopback/closed-port URLs, or intentionally fail. Do not replace loopback URLs with external infrastructure during ordinary validation.

## Preconditions

- Run on approved Windows test host only.
- PowerShell process creation auditing enabled.
- Security Event ID 4688 includes command line.
- Forward resulting events to Wazuh.
- Capture raw event before judging rule behavior.

## Test matrix

| ID | Command behavior | Expected rule |
|---|---|---|
| T01 | Baseline PowerShell | Base only; normally no alert |
| T02 | Encoded command | 100110 |
| T03 | Download indicator | 100113 |
| T04 | Download + IEX | 100130 |
| T05 | Download + Import-Module | 100137 |
| T06 | Execution-policy bypass | 100111 |
| T07 | Hidden window | 100115 |
| T08 | Base64 + IEX | 100133 or 100112 |
| T09 | NoProfile + IEX | 100116 |
| T10 | IEX-free module execution | 100120 |
| T11 | Obfuscation pattern | 100119 |
| T12 | Full chain syntax | 100136, if rule ordering/selection behaves as designed |

## Commands

Run individually. Do not paste the whole file into PowerShell.

### T01 — baseline

```powershell
powershell.exe -NoProfile -NonInteractive -Command "Write-Output 'WAZUH_BASELINE_TEST'"
```

Expected: process creation observed; no suspicious child alert expected.

### T02 — encoded command, benign payload

```powershell
powershell.exe -EncodedCommand VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFcAQQBaAFUASABfAEUATgBDAE8ARABFAEQAXwBUAEUAUwBUACcA
```

Decoded payload: `Write-Output 'WAZUH_ENCODED_TEST'`.

Expected: `100110`.

### T03 — download indicator, controlled closed port

```powershell
powershell.exe -NoProfile -Command "Invoke-WebRequest http://127.0.0.1:9/wazuh-test -UseBasicParsing"
```

Expected: controlled connection failure; `100113`.

### T04 — download + dynamic execution syntax, benign local output

```powershell
powershell.exe -NoProfile -Command "try { Invoke-WebRequest http://127.0.0.1:9/wazuh-test -UseBasicParsing } catch {}; Invoke-Expression 'Write-Output WAZUH_DOWNLOAD_IEX_TEST'"
```

Expected: `100130`. No external network access.

### T05 — download + IEX-free module load

```powershell
powershell.exe -NoProfile -Command "try { Invoke-WebRequest http://127.0.0.1:9/wazuh-test -UseBasicParsing } catch {}; Import-Module Microsoft.PowerShell.Management"
```

Expected: `100137`.

### T06 — execution-policy bypass with harmless output

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -Command "Write-Output WAZUH_POLICY_TEST"
```

Expected: `100111`.

### T07 — hidden window with harmless output

```powershell
powershell.exe -NoProfile -WindowStyle Hidden -Command "Write-Output WAZUH_HIDDEN_TEST"
```

Expected: `100115`.

### T08 — Base64 conversion + IEX, benign payload

```powershell
powershell.exe -NoProfile -Command "IEX ([Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('VwByAGkAdABlAC0ATwB1AHQAcAB1AHQAIAAnAFcAQQBaAFUASABfAFQARQBTAFQAJwA=')))"
```

Expected: `100133` or `100112`, depending on rule evaluation.

### T09 — stealth options + IEX

```powershell
powershell.exe -NoProfile -NonInteractive -Command "IEX 'Write-Output WAZUH_STEALTH_TEST'"
```

Expected: `100116`.

### T10 — IEX-free execution/module load

```powershell
powershell.exe -NoProfile -Command "Import-Module Microsoft.PowerShell.Management"
```

Expected: `100120`.

### T11 — simple obfuscation-pattern test

```powershell
powershell.exe -NoProfile -Command "Write-Output ([char]87+[char]65+[char]90+[char]85+[char]72)"
```

Expected: `100119` if the command-line regex matches the deployed event format.

### T12 — full chain syntax, loopback only

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "try { Invoke-WebRequest http://127.0.0.1:9/wazuh-test -UseBasicParsing } catch {}; Invoke-Expression 'Write-Output WAZUH_FULL_CHAIN_TEST'"
```

Expected: `100136` if all four conditions and child-rule selection behave as intended.

## Verification

For every test, record:

- UTC timestamp
- Hostname
- Test ID
- Raw Security 4688 event
- Wazuh alert ID
- Wazuh rule ID and level
- MITRE technique output
- Whether multiple rules matched
- False-positive result

Use Wazuh logtest with the raw event before changing rules:

```bash
/var/ossec/bin/wazuh-logtest
```

## Bounded-impact profile

Baseline probes above validate regex coverage. Use these opt-in cases when testing realistic behavior. They create only a clearly named temporary marker, then remove it. They do not persist, access credentials, disable security tools, contact external infrastructure, or move laterally.

### T13 — encoded command with temporary marker

```powershell
powershell.exe -EncodedCommand JABwAD0AIgAkAGUAbgB2ADoAVABFAE0AUABcAHcAYQB6AHUAaABfAHAAdQByAHAAbABlAF8AZQBuAGMAbwBkAGUAZAAuAHQAeAB0ACIAOwAgAFMAZQB0AC0AQwBvAG4AdABlAG4AdAAgAC0AUABhAHQAaAAgACQAcAAgAC0AVgBhAGwAdQBlACAAJwBXAEEAWgBVAEgAXwBFAE4AQwBPAEQARQBEAF8ASQBNAFAAQQBDAFQAXwBUAEUAUwBUACcA
```

Decoded intent: create `%TEMP%\wazuh_purple_encoded.txt` containing a test marker. Remove afterward:

```powershell
Remove-Item "$env:TEMP\wazuh_purple_encoded.txt" -Force -ErrorAction SilentlyContinue
```

Expected: `100110`.

### T14 — download cradle syntax + local marker

```powershell
powershell.exe -NoProfile -Command "try { `$x=(Invoke-WebRequest http://127.0.0.1:9/wazuh-test -UseBasicParsing).Content; Invoke-Expression `$x } catch {}; Set-Content `$env:TEMP\wazuh_purple_cradle.txt 'WAZUH_CRADLE_TEST'"
```

Expected: `100130`. The request targets loopback port 9 and should fail closed; marker creation proves command reached the controlled post-request path.

### T15 — hidden bypass + child process

```powershell
powershell.exe -NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -Command "Start-Process cmd.exe -ArgumentList '/c echo WAZUH_CHILD_TEST ^> %TEMP%\\wazuh_purple_child.txt' -Wait"
```

Expected: `100136` only if download/IEX conditions are also present; otherwise `100111`/`100115`. Remove marker afterward:

```powershell
Remove-Item "$env:TEMP\wazuh_purple_child.txt" -Force -ErrorAction SilentlyContinue
```

### T16 — dynamic execution with temporary marker

```powershell
powershell.exe -NoProfile -Command "Invoke-Expression \"Set-Content `$env:TEMP\\wazuh_purple_iex.txt 'WAZUH_IEX_TEST'\""
```

Expected: `100112` or `100116`, depending on switches and rule evaluation. Remove marker afterward:

```powershell
Remove-Item "$env:TEMP\wazuh_purple_iex.txt" -Force -ErrorAction SilentlyContinue
```

## Safety notes

- T03–T05 and T12/T14 use `127.0.0.1:9`; they must not contact an external host.
- T13–T16 create only named files under the current user's `%TEMP%`; clean them after each run.
- T15 launches only `cmd.exe` to write a marker file.
- No test creates persistence, dumps credentials, changes policy, disables security, deletes logs, or touches another host.
- T07 hides the console; use only on a test host and expect no visible window.
- Do not test parent-process rules by launching from real Office documents. Simulate/submit raw events to `wazuh-logtest` instead.
- A matching alert proves detection only, not prevention.
