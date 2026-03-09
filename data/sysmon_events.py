SYS_MON_EVENTS: dict[int, str] = {
    1: "Process Create",
    2: "File Create Time",
    3: "Network Connect",
    4: "Sysmon State Change",
    5: "Process Terminate",
    6: "Driver Load",
    7: "Image Load",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "Process Access",
    11: "File Create",
    12: "Registry Event",
    13: "Registry Event",
    14: "Registry Event",
    15: "File Create Stream Hash",
    16: "Sysmon Config State Changed",
    17: "Pipe Event",
    18: "Pipe Event",
    19: "Wmi Event",
    20: "Wmi Event",
    21: "Wmi Event",
    22: "DNS Query",
    23: "File Delete",
    24: "Clipboard Change",
    25: "Process Tampering",
    26: "File Delete Detected",
    27: "File Block Executable",
    28: "File Block Shredding",
    29: "File Executable Detected",
    30: "File Blocked",
}

def _normalize(tag: str) -> str:
    return tag.replace(" ", "").lower()


def get_event_xml_tag(event_id: int) -> str:
    name = SYS_MON_EVENTS.get(event_id, f"Event{event_id}")
    return name.replace(" ", "")


def get_event_id_from_xml_tag(xml_tag: str) -> int | None:
    normalized = _normalize(xml_tag)

    for event_id in SYS_MON_EVENTS:
        if _normalize(get_event_xml_tag(event_id)) == normalized:
            return event_id

    return None
