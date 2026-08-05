# Delegated GPO persistence simulation

## Scope

Use a dedicated disposable workstation GPO. Never overwrite the operational
Wazuh auditing GPO or either default domain policy.

```text
GPO: Workstation Software Update
Link: domain root, not enforced
Read: Authenticated Users
Apply: WIN01 computer only
Delegated editor: low-privilege workstation user
Persistence: HKLM Run value pointing to benign target-local updater script
```

## Preconditions

1. Preserve operational Wazuh GPO GUID, modification time, user/computer version,
   links, permissions, and service health.
2. Confirm disposable GPO, Run value, updater script, and marker are absent.
3. Confirm DC01 and WIN01 Wazuh agents Active.
4. Record UTC start/end times for every mutation and control.

## Build vulnerable control

As domain administrator:

1. Create `Workstation Software Update`.
2. Link it once to the domain root, not enforced.
3. Set `Authenticated Users` to `GpoRead` only.
4. Grant `WIN01$` `GpoApply`.
5. Grant the low-privilege test user `GpoEdit`.
6. Verify effective permissions and link before mutation.

`GpoRead` on Authenticated Users preserves normal GPO readability without broad
application. Only WIN01 receives Apply permission.

## Benign updater

Stage `C:\ProgramData\WazuhLab\UpdateHealth.cmd`. It may write only:

```text
C:\ProgramData\WazuhLab\gpo_update_health.json
```

No account, service, firewall, Defender, privilege, credential, or network
configuration change is permitted.

## Attack

As delegated low-privilege user, use `Set-GPRegistryValue` against the disposable
GPO:

```text
Key:       HKLM\Software\Microsoft\Windows\CurrentVersion\Run
Value:     WindowsUpdateHealth
Data:      C:\ProgramData\WazuhLab\UpdateHealth.cmd
Type:      String
```

Require GPO computer version increase and actor identity proof. Force WIN01
computer-policy refresh. Require GPO listed as applied and exact Run value present.
Do not claim payload execution unless marker evidence exists.

## Detection

Collect:

- DC Security 5136 record IDs, actor, GPO DN, changed attribute, operation, value.
- Wazuh agent 001 rule ID/level/MITRE mapping.
- WIN01 GroupPolicy Operational 5312, 4016, 8004.
- WIN01 System 1502.
- Sysmon registry telemetry if present; label gap if absent.

## False-positive control

As the same delegated user, run read-only `Get-GPO`. Require zero 5136 and zero
matching Wazuh policy-modification alerts in the bounded control window.

## Cleanup

1. As delegated user, `Remove-GPRegistryValue`.
2. Force WIN01 computer-policy refresh.
3. If HKLM Run remains tattooed, remove only `WindowsUpdateHealth` explicitly.
4. As administrator, remove link and disposable GPO.
5. Verify GPO, link, SYSVOL directory, Run value, updater script, and marker absent.
6. Force final WIN01 policy refresh and verify test GPO absent from `gpresult`.
7. Verify operational Wazuh GPO fingerprint unchanged and all Wazuh services/agents
   healthy.
