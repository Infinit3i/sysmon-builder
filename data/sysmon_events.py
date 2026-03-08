SYS_MON_EVENTS: dict[int, str] = {
    1: "Process Create",
    2: "File Creation Time Changed",
    3: "Network Connection",
    4: "Sysmon Service State Changed",
    5: "Process Terminated",
    6: "Driver Loaded",
    7: "Image Loaded",
    8: "CreateRemoteThread",
    9: "RawAccessRead",
    10: "Process Access",
    11: "File Create",
    12: "Registry Object Added or Deleted",
    13: "Registry Value Set",
    14: "Registry Key or Value Renamed",
    15: "File Create Stream Hash",
    16: "Sysmon Config State Changed",
    17: "Pipe Created",
    18: "Pipe Connected",
    19: "WMI Event Filter",
    20: "WMI Event Consumer",
    21: "WMI Event Consumer To Filter",
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


def get_event_xml_tag(event_id: int) -> str:
    name = SYS_MON_EVENTS.get(event_id, f"Event{event_id}")
    return name.replace(" ", "")


def get_event_id_from_xml_tag(xml_tag: str) -> int | None:
    normalized = xml_tag.replace(" ", "").lower()

    for event_id in SYS_MON_EVENTS:
        if get_event_xml_tag(event_id).lower() == normalized:
            return event_id

    return None