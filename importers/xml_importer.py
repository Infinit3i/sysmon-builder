from xml.etree import ElementTree as ET

from data.sysmon_events import SYS_MON_EVENTS, get_event_id_from_xml_tag
from models.sysmon_config import RuleFilter, SysmonConfig


def strip_namespace(tag: str) -> str:
    if "}" in tag:
        return tag.split("}", 1)[1]
    return tag


def extract_rules_from_node(
    node: ET.Element,
    event_config,
    rule_type: str,
    group_id: str | None = None,
    group_relation: str | None = None,
    group_name: str | None = None,
    group_counter: list[int] | None = None,
) -> None:
    for child in node:
        child_tag = strip_namespace(child.tag)

        if child_tag == "Rule":
            next_group_id = group_id
            if next_group_id is None and group_counter is not None:
                next_group_id = f"imported-group-{group_counter[0]}"
                group_counter[0] += 1

            next_group_relation = child.attrib.get("groupRelation", group_relation)
            next_group_name = child.attrib.get("name", group_name)

            extract_rules_from_node(
                child,
                event_config,
                rule_type,
                next_group_id,
                next_group_relation,
                next_group_name,
                group_counter,
            )
            continue

        if len(child) > 0:
            extract_rules_from_node(
                child,
                event_config,
                rule_type,
                group_id,
                group_relation,
                group_name,
                group_counter,
            )
            continue

        field_name = child_tag
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
                imported=True,
                group_id=group_id,
                group_relation=group_relation,
                group_name=group_name,
            )
        )


def import_config(input_path: str) -> SysmonConfig:
    tree = ET.parse(input_path)
    root = tree.getroot()

    config = SysmonConfig()

    event_filtering = root.find("EventFiltering")
    if event_filtering is None:
        for child in root:
            if strip_namespace(child.tag) == "EventFiltering":
                event_filtering = child
                break

    if event_filtering is None:
        return config

    group_counter = [1]

    for child in event_filtering:
        child_tag = strip_namespace(child.tag)
        event_elements = child if child_tag == "RuleGroup" else [child]

        for event_element in event_elements:
            event_tag = strip_namespace(event_element.tag)
            event_id = get_event_id_from_xml_tag(event_tag)

            if event_id is None:
                continue

            event_name = SYS_MON_EVENTS.get(event_id, event_tag)
            rule_type = event_element.attrib.get("onmatch", "include")

            event_config = config.get_or_create_event(event_id, event_name)
            extract_rules_from_node(
                event_element,
                event_config,
                rule_type,
                group_counter=group_counter,
            )

    return config
