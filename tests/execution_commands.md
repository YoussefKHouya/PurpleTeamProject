# Purple-Team Execution Command Reference

Professional command reference for authorized Windows/Wazuh validation. Contains no credentials, internal hostnames, internal IP addresses, or private key material.

## Credential setup

Enter credentials interactively. Never hardcode passwords in scripts or commits.

```powershell
$cred = Get-Credential '<DOMAIN>\<DOMAIN_USER>'
```

## Direct WinRM to test workstation

Replace `<TARGET_HOST_OR_IP>` with the approved test endpoint at execution time.

```powershell
Enter-PSSession `
  -ComputerName <TARGET_HOST_OR_IP> `
  -Credential $cred `
  -Authentication Negotiate
```

One-shot identity probe:

```powershell
Invoke-Command `
  -ComputerName <TARGET_HOST_OR_IP> `
  -Credential $cred `
  -Authentication Negotiate `
  -ScriptBlock { whoami; hostname; Get-Location }
```

## Read-only domain discovery from test workstation

Run inside the authenticated test-workstation session. Requires the AD PowerShell module.

```powershell
whoami
hostname
Get-ADDomain | Select-Object DNSRoot,NetBIOSName
Get-ADUser -Identity <DOMAIN_USER> |
  Select-Object SamAccountName,Enabled
Get-ADUser -Filter * |
  Select-Object -First 5 SamAccountName,Enabled
```

ATT&CK mapping:

- T1059.001 — PowerShell
- T1087.002 — Domain Account discovery

## Wazuh log validation

On Wazuh manager:

```bash
/var/ossec/bin/wazuh-logtest
```

Record:

- Raw event
- Rule ID
- Alert level
- MITRE IDs
- Timestamp
- Sanitized hostname/asset identifier
- Test case

## Controlled execution rules

- Execute only against explicitly approved lab endpoints.
- Keep administrative workstation outside destructive test scope.
- Keep domain discovery read-only.
- Do not dump credentials.
- Do not disable security controls.
- Do not create persistence.
- Do not use external C2 or random malware.
- Use Atomic Red Team or bounded-impact probes.
- Clean temporary markers after tests.
- Never place passwords, tokens, private keys, internal IPs, or hostnames in this repository.
