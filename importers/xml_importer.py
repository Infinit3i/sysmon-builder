from xml.etree import ElementTree as ET

from data.sysmon_events import SYS_MON_EVENTS, get_event_id_from_xml_tag
from models.sysmon_config import RuleFilter, SysmonConfig


def extract_rules_from_node(
    node: ET.Element,
    event_config,
    rule_type: str,
) -> None:
    for child in node:
        if child.tag == "Rule":
            extract_rules_from_node(child, event_config, rule_type)
            continue

        if len(child) > 0:
            extract_rules_from_node(child, event_config, rule_type)
            continue

        field_name = child.tag
        condition = child.attrib.get("condition", "is")
        value = (child.text or "").strip()

        if not value:
            continue

        event_config.rules.append(
            RuleFilter(
                rule_type=rule_type,
                field_name=field_name,
                condition=condition,
                value=value,
            )
        )


def import_config(input_path: str) -> SysmonConfig:
    tree = ET.parse(input_path)
    root = tree.getroot()

    config = SysmonConfig()

    event_filtering = root.find("EventFiltering")
    if event_filtering is None:
        return config

    for rule_group in event_filtering:
        if rule_group.tag != "RuleGroup":
            continue

        for event_element in rule_group:
            event_tag = event_element.tag
            event_id = get_event_id_from_xml_tag(event_tag)

            if event_id is None:
                continue

            event_name = SYS_MON_EVENTS.get(event_id, event_tag)
            rule_type = event_element.attrib.get("onmatch", "include")

            event_config = config.get_or_create_event(event_id, event_name)
            extract_rules_from_node(event_element, event_config, rule_type)

    return config