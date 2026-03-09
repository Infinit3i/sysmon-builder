import json
import platform
import re
import shutil
import subprocess
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any, Callable

from models.sysmon_config import RuleFilter, SysmonConfig
from importers.powershell_script_generator import ensure_ps_scripts


def _get_powershell_executable() -> str:
    candidates = ["powershell.exe", "pwsh.exe", "pwsh", "powershell"]
    for candidate in candidates:
        resolved = shutil.which(candidate)
        if resolved:
            return resolved
    raise RuntimeError("PowerShell executable not found (expected powershell.exe or pwsh.exe).")


def _load_script_json(powershell_exe: str, script_path: Path) -> Any:
    command = [
        powershell_exe,
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        stderr = result.stderr.strip() or "Unknown PowerShell error"
        raise RuntimeError(f"PowerShell script failed: {script_path.name}\n{stderr}")

    raw_stdout = result.stdout.strip()
    if not raw_stdout:
        return []

    try:
        return json.loads(raw_stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"Failed to parse JSON from {script_path.name}: {exc}") from exc


def _as_record_list(value: Any) -> list[dict[str, Any]]:
    if isinstance(value, list):
        return [item for item in value if isinstance(item, dict)]
    if isinstance(value, dict):
        return [value]
    return []


def _extract_binary_path(path_name: str) -> str:
    candidate = (path_name or "").strip()
    if not candidate:
        return ""

    quoted_match = re.match(r'^"([^"]+)"', candidate)
    if quoted_match:
        return quoted_match.group(1).strip()

    exe_match = re.search(r"([A-Za-z]:\\[^\r\n]*?\.exe)", candidate, re.IGNORECASE)
    if exe_match:
        return exe_match.group(1).strip()

    return candidate.split(" ", 1)[0].strip()


def _add_rule_if_missing(
    event_rules: list[RuleFilter],
    seen: set[tuple[str, str, str, str, str | None, str | None, str | None]],
    rule_type: str,
    field_name: str,
    condition: str,
    value: str,
    group_id: str | None,
    group_name: str | None,
    group_relation: str | None,
) -> None:
    normalized_value = value.strip()
    if not normalized_value:
        return

    key = (
        rule_type,
        field_name,
        condition,
        normalized_value.lower(),
        group_id,
        group_name,
        group_relation,
    )
    if key in seen:
        return
    seen.add(key)

    event_rules.append(
        RuleFilter(
            rule_type=rule_type,
            field_name=field_name,
            condition=condition,
            value=normalized_value,
            imported=True,
            group_id=group_id,
            group_name=group_name,
            group_relation=group_relation,
        )
    )


def _parse_event_id(value: Any) -> int | None:
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return None


def _mode_for_event(event_id: int, event_rule_modes: dict[int, str]) -> str:
    mode = event_rule_modes.get(event_id, "include").strip().lower()
    return "exclude" if mode == "exclude" else "include"


def _add_sysmon_event_baselines(
    config: SysmonConfig,
    records: list[dict[str, Any]],
    selected_event_ids: set[int],
    event_rule_modes: dict[int, str],
    per_field_limit: int = 50,
) -> None:
    by_event: dict[int, dict[str, Counter[str]]] = defaultdict(lambda: defaultdict(Counter))

    for record in records:
        event_id = _parse_event_id(record.get("EventId"))
        if event_id is None or event_id not in selected_event_ids:
            continue

        for key, raw_value in record.items():
            if key == "EventId":
                continue
            value = str(raw_value or "").strip()
            if not value:
                continue
            by_event[event_id][key][value] += 1

    for event_id, field_map in by_event.items():
        event_config = config.get_or_create_event(event_id, f"Sysmon Event {event_id}")
        rule_mode = _mode_for_event(event_id, event_rule_modes)
        seen: set[tuple[str, str, str, str, str | None, str | None, str | None]] = {
            (
                rule.rule_type,
                rule.field_name,
                rule.condition,
                rule.value.strip().lower(),
                rule.group_id,
                rule.group_name,
                rule.group_relation,
            )
            for rule in event_config.rules
        }

        group_id = f"live-event-{event_id:02d}"
        group_name = f"Live Event {event_id} Baseline"

        for field_name, counter in field_map.items():
            for value, _count in counter.most_common(per_field_limit):
                _add_rule_if_missing(
                    event_config.rules,
                    seen,
                    rule_mode,
                    field_name,
                    "is",
                    value,
                    group_id,
                    group_name,
                    "or",
                )


def import_live_system_state(
    *,
    enabled_sources: set[str] | None = None,
    selected_event_ids: set[int] | None = None,
    event_rule_modes: dict[int, str] | None = None,
    status_callback: Callable[[str], None] | None = None,
) -> SysmonConfig:
    if platform.system().lower() != "windows":
        raise RuntimeError("Live PowerShell import is only supported on Windows systems.")

    enabled = enabled_sources or {
        "processes",
        "network",
        "services",
        "scheduled_tasks",
        "registry",
        "sysmon_events",
    }
    selected_ids = selected_event_ids or set(range(1, 31))
    rule_modes = event_rule_modes or {}

    script_paths = ensure_ps_scripts()
    scripts_by_name = {path.name: path for path in script_paths}

    required = [
        "get_processes.ps1",
        "get_network_connections.ps1",
        "get_services.ps1",
        "get_scheduled_tasks.ps1",
        "get_registry_keys.ps1",
    ]
    for script_name in required:
        if script_name not in scripts_by_name:
            raise RuntimeError(f"Missing required script: {script_name}")

    powershell_exe = _get_powershell_executable()

    process_data: list[dict[str, Any]] = []
    network_data: Any = []
    service_data: list[dict[str, Any]] = []
    scheduled_task_data: list[dict[str, Any]] = []
    registry_data: list[dict[str, Any]] = []
    sysmon_event_data: list[dict[str, Any]] = []

    if "processes" in enabled:
        if status_callback:
            status_callback("Collecting processes...")
        process_data = _as_record_list(
            _load_script_json(powershell_exe, scripts_by_name["get_processes.ps1"])
        )

    if "network" in enabled:
        if status_callback:
            status_callback("Collecting network connections...")
        network_data = _load_script_json(powershell_exe, scripts_by_name["get_network_connections.ps1"])

    if "services" in enabled:
        if status_callback:
            status_callback("Collecting services...")
        service_data = _as_record_list(
            _load_script_json(powershell_exe, scripts_by_name["get_services.ps1"])
        )

    if "scheduled_tasks" in enabled:
        if status_callback:
            status_callback("Collecting scheduled tasks...")
        scheduled_task_data = _as_record_list(
            _load_script_json(powershell_exe, scripts_by_name["get_scheduled_tasks.ps1"])
        )

    if "registry" in enabled:
        if status_callback:
            status_callback("Collecting registry keys...")
        registry_data = _as_record_list(
            _load_script_json(powershell_exe, scripts_by_name["get_registry_keys.ps1"])
        )

    if "sysmon_events" in enabled:
        if status_callback:
            status_callback("Collecting Sysmon events...")
        sysmon_event_data = _as_record_list(
            _load_script_json(powershell_exe, scripts_by_name["get_sysmon_events.ps1"])
        )

    config = SysmonConfig()

    include_event_1 = 1 in selected_ids
    include_event_3 = 3 in selected_ids
    include_event_13 = 13 in selected_ids

    process_event = config.get_or_create_event(1, "Process Create") if include_event_1 else None
    network_event = config.get_or_create_event(3, "Network connection") if include_event_3 else None
    registry_event = config.get_or_create_event(13, "Registry Event") if include_event_13 else None

    process_seen: set[tuple[str, str, str, str, str | None, str | None, str | None]] = set()
    network_seen: set[tuple[str, str, str, str, str | None, str | None, str | None]] = set()
    registry_seen: set[tuple[str, str, str, str, str | None, str | None, str | None]] = set()

    event_1_mode = _mode_for_event(1, rule_modes)
    event_3_mode = _mode_for_event(3, rule_modes)
    event_13_mode = _mode_for_event(13, rule_modes)

    process_group_id = "live-processes"
    process_group_name = "Live Process Inventory"
    network_group_id = "live-network"
    network_group_name = "Live Network Connections"
    service_group_id = "live-services"
    service_group_name = "Live Services"
    scheduled_task_group_id = "live-scheduled-tasks"
    scheduled_task_group_name = "Live Scheduled Tasks"
    registry_group_id = "live-registry"
    registry_group_name = "Live Registry Keys"

    process_id_to_image: dict[int, str] = {}

    for process in process_data:
        pid = process.get("ProcessId")
        if isinstance(pid, int):
            image_value = str(process.get("ExecutablePath") or process.get("Name") or "").strip()
            if image_value:
                process_id_to_image[pid] = image_value

        image = str(process.get("ExecutablePath") or process.get("Name") or "").strip()
        if image and process_event is not None:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                event_1_mode,
                "Image",
                "is",
                image,
                process_group_id,
                process_group_name,
                "or",
            )

    for service in service_data:
        binary_path = _extract_binary_path(str(service.get("PathName") or ""))
        if binary_path and process_event is not None:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                event_1_mode,
                "Image",
                "is",
                binary_path,
                service_group_id,
                service_group_name,
                "or",
            )

    for task in scheduled_task_data:
        execute_raw = str(task.get("Execute") or "").strip()
        arguments = str(task.get("Arguments") or "").strip()
        execute_image = _extract_binary_path(execute_raw)

        if execute_image and process_event is not None:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                event_1_mode,
                "Image",
                "is",
                execute_image,
                scheduled_task_group_id,
                scheduled_task_group_name,
                "or",
            )

        if execute_raw and arguments and process_event is not None:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                event_1_mode,
                "CommandLine",
                "contains",
                f"{execute_raw} {arguments}".strip(),
                scheduled_task_group_id,
                scheduled_task_group_name,
                "or",
            )
        elif arguments and process_event is not None:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                event_1_mode,
                "CommandLine",
                "contains",
                arguments,
                scheduled_task_group_id,
                scheduled_task_group_name,
                "or",
            )

    if isinstance(network_data, dict):
        tcp_connections = _as_record_list(network_data.get("Tcp"))
    else:
        tcp_connections = _as_record_list(network_data)

    for connection in tcp_connections:
        remote_ip = str(connection.get("RemoteAddress") or "").strip()
        remote_port = str(connection.get("RemotePort") or "").strip()
        owning_pid = connection.get("OwningProcess")

        if remote_ip and remote_ip not in {"0.0.0.0", "::"} and network_event is not None:
            _add_rule_if_missing(
                network_event.rules,
                network_seen,
                event_3_mode,
                "DestinationIp",
                "is",
                remote_ip,
                network_group_id,
                network_group_name,
                "or",
            )

        if remote_port and remote_port != "0" and network_event is not None:
            _add_rule_if_missing(
                network_event.rules,
                network_seen,
                event_3_mode,
                "DestinationPort",
                "is",
                remote_port,
                network_group_id,
                network_group_name,
                "or",
            )

        if (
            isinstance(owning_pid, int)
            and owning_pid in process_id_to_image
            and network_event is not None
        ):
            _add_rule_if_missing(
                network_event.rules,
                network_seen,
                event_3_mode,
                "Image",
                "is",
                process_id_to_image[owning_pid],
                network_group_id,
                network_group_name,
                "or",
            )

    for record in registry_data:
        path = str(record.get("RegistryPath") or "").strip()
        name = str(record.get("Name") or "").strip()
        value = str(record.get("Value") or "").strip()
        kind = str(record.get("Kind") or "").strip().lower()

        if path and registry_event is not None:
            normalized_path = path.replace("Microsoft.PowerShell.Core\\Registry::", "").strip()
            _add_rule_if_missing(
                registry_event.rules,
                registry_seen,
                event_13_mode,
                "TargetObject",
                "contains",
                normalized_path,
                registry_group_id,
                registry_group_name,
                "or",
            )

        if kind == "value" and name and value and registry_event is not None:
            _add_rule_if_missing(
                registry_event.rules,
                registry_seen,
                event_13_mode,
                "Details",
                "contains",
                f"{name}={value}",
                registry_group_id,
                registry_group_name,
                "or",
            )

    _add_sysmon_event_baselines(
        config,
        sysmon_event_data,
        selected_ids,
        rule_modes,
    )

    if process_event is not None and not process_event.rules:
        config.events.pop(1, None)
    if network_event is not None and not network_event.rules:
        config.events.pop(3, None)
    if registry_event is not None and not registry_event.rules:
        config.events.pop(13, None)

    return config
