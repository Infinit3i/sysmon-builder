from pathlib import Path
from xml.dom import minidom
import xml.etree.ElementTree as ET

from data.sysmon_events import get_event_xml_tag
from models.sysmon_config import SysmonConfig


def prettify_xml(element: ET.Element) -> str:
    rough_string: bytes = ET.tostring(element, encoding="utf-8")
    parsed = minidom.parseString(rough_string)
    return parsed.toprettyxml(indent="  ")


def export_config(config: SysmonConfig, output_path: str) -> None:
    root = ET.Element(
        "Sysmon",
        attrib={
            "schemaversion": "4.90",
        },
    )

    event_filtering = ET.SubElement(root, "EventFiltering")

    for event_id, event_config in sorted(config.events.items()):
        if not event_config.rules:
            continue

        event_tag = get_event_xml_tag(event_id)

        grouped_rules: dict[str, list] = {
            "include": [],
            "exclude": [],
        }

        for rule in event_config.rules:
            grouped_rules.setdefault(rule.rule_type, []).append(rule)

        for rule_type, rules in grouped_rules.items():
            if not rules:
                continue

            event_element = ET.SubElement(
                event_filtering,
                event_tag,
                attrib={"onmatch": rule_type},
            )

            emitted_groups: set[str] = set()
            grouped_rule_members: dict[str, list] = {}

            for rule in rules:
                if rule.group_id:
                    grouped_rule_members.setdefault(rule.group_id, []).append(rule)

            for rule in rules:
                if not rule.group_id:
                    field_element = ET.SubElement(
                        event_element,
                        rule.field_name,
                        attrib={"condition": rule.condition},
                    )
                    field_element.text = rule.value
                    continue

                if rule.group_id in emitted_groups:
                    continue

                group_rules = grouped_rule_members.get(rule.group_id, [rule])
                group_attrs: dict[str, str] = {}
                if rule.group_name:
                    group_attrs["name"] = rule.group_name
                if rule.group_relation:
                    group_attrs["groupRelation"] = rule.group_relation

                rule_group_element = ET.SubElement(event_element, "Rule", attrib=group_attrs)

                for grouped_rule in group_rules:
                    field_element = ET.SubElement(
                        rule_group_element,
                        grouped_rule.field_name,
                        attrib={"condition": grouped_rule.condition},
                    )
                    field_element.text = grouped_rule.value

                emitted_groups.add(rule.group_id)

    xml_output: str = prettify_xml(root)

    output_file = Path(output_path)
    output_file.write_text(xml_output, encoding="utf-8")
