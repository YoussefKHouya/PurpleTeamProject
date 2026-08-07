#!/usr/bin/env python3
"""Regression checks for production-hardening changes to custom Wazuh rules."""

from pathlib import Path
import re
import unittest
import xml.etree.ElementTree as ET

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


class RuleHardeningTests(unittest.TestCase):
    def test_mssql_execution_rule_keeps_live_proven_parent(self) -> None:
        rules = load_rules("mssql_xp_cmdshell_detection.xml")
        self.assertEqual(child_text(rules["100541"], "if_sid"), "100300")

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


if __name__ == "__main__":
    unittest.main(verbosity=2)
