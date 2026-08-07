# Chisel port-forward validation

## Artifact

```text
Source: https://github.com/jpillora/chisel
Release: v1.11.8
Commit: 310eec3696e82ef14048268d1d12f1cd99d6dbe9
Windows SHA-256: 333e76e0f05b84035396f62990c8e84a31e23a5a43e99766f8d922c634f512e3
Kali server SHA-256: 292820f6188ddaba744c36042c3139f8c090902f175e6098075f7c3014844c7f
```

Build from pinned source with Go, `CGO_ENABLED=0`, `-trimpath`, and explicit Windows AMD64/Linux AMD64 targets. Run `go test ./...` before deployment.

## Bounded positive

Kali server:

```bash
chisel-server server --host <KALI_HOST_ONLY> --port 18082 --reverse
```

WIN01, medium-integrity ordinary domain user:

```text
chisel.exe client --fingerprint <SERVER_FINGERPRINT> --max-retry-count 3 <KALI_HOST_ONLY>:18082 R:127.0.0.1:18089:127.0.0.1:3389
```

Expected: Kali loopback listener `127.0.0.1:18089`; an RDP negotiation packet returns a 19-byte RDP response through the tunnel.

## Reverse SOCKS and ProxyChains

Kali server:

```bash
chisel-server server --host <KALI_HOST_ONLY> --port 18082 --reverse
```

WIN01, local medium-integrity Yassine PowerShell:

```text
chisel.exe client --fingerprint <SERVER_FINGERPRINT> --max-retry-count 3 <KALI_HOST_ONLY>:18082 R:socks
```

Use a temporary ProxyChains configuration containing only `socks5 127.0.0.1 1080`, then make one bounded TCP connection through it to the known domain controller LDAP service. Require the Chisel server to report `R:127.0.0.1:1080=>socks: Listening`, ProxyChains to report an `OK` chain, and Wazuh rule `100526` from the genuine client process. Do not scan a subnet or authenticate to LDAP in this test.

## Detection retests

Rename-resistant known-build execution:

```text
relay-service.exe --version
```

Tunnel syntax positive:

```text
relay-service.exe client --max-retry-count 1 127.0.0.1:9 R:127.0.0.1:18090:127.0.0.1:3389
```

Negative control—same misleading syntax, wrong binary hash:

```text
whoami.exe client R:127.0.0.1:18090:127.0.0.1:3389
```

Expected: `100525` for the known build; `100526` for the known build plus client-forward grammar. Rule `100543` provides lower-confidence, hash-independent visibility for client tunnel syntax from a user-writable executable path. The `whoami.exe` control may select `100543` because it deliberately reproduces that behavior grammar, but it must never select Chisel-attribution rules `100525` or `100526`.

## Cleanup

Stop endpoint Chisel processes and Kali server, and remove the temporary ProxyChains configuration. Remove temporary Defender exclusion with Administrator PowerShell after endpoint artifacts are no longer needed:

```powershell
Remove-MpPreference -ExclusionPath "C:\Users\yassine.karimi\AppData\Local\Temp\ChiselLab"
```
