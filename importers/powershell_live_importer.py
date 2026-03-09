import json
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

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


def import_live_system_state() -> SysmonConfig:
    if platform.system().lower() != "windows":
        raise RuntimeError("Live PowerShell import is only supported on Windows systems.")

    script_paths = ensure_ps_scripts()
    scripts_by_name = {path.name: path for path in script_paths}

    required = ["get_processes.ps1", "get_network_connections.ps1", "get_services.ps1"]
    for script_name in required:
        if script_name not in scripts_by_name:
            raise RuntimeError(f"Missing required script: {script_name}")

    powershell_exe = _get_powershell_executable()

    process_data = _as_record_list(
        _load_script_json(powershell_exe, scripts_by_name["get_processes.ps1"])
    )
    network_data = _load_script_json(powershell_exe, scripts_by_name["get_network_connections.ps1"])
    service_data = _as_record_list(
        _load_script_json(powershell_exe, scripts_by_name["get_services.ps1"])
    )

    config = SysmonConfig()

    process_event = config.get_or_create_event(1, "Process Create")
    network_event = config.get_or_create_event(3, "Network connection")

    process_seen: set[tuple[str, str, str, str, str | None, str | None, str | None]] = set()
    network_seen: set[tuple[str, str, str, str, str | None, str | None, str | None]] = set()

    process_group_id = "live-processes"
    process_group_name = "Live Process Inventory"
    network_group_id = "live-network"
    network_group_name = "Live Network Connections"
    service_group_id = "live-services"
    service_group_name = "Live Services"

    process_id_to_image: dict[int, str] = {}

    for process in process_data:
        pid = process.get("ProcessId")
        if isinstance(pid, int):
            image_value = str(process.get("ExecutablePath") or process.get("Name") or "").strip()
            if image_value:
                process_id_to_image[pid] = image_value

        image = str(process.get("ExecutablePath") or process.get("Name") or "").strip()
        if image:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                "include",
                "Image",
                "is",
                image,
                process_group_id,
                process_group_name,
                "or",
            )

    for service in service_data:
        binary_path = _extract_binary_path(str(service.get("PathName") or ""))
        if binary_path:
            _add_rule_if_missing(
                process_event.rules,
                process_seen,
                "include",
                "Image",
                "is",
                binary_path,
                service_group_id,
                service_group_name,
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

        if remote_ip and remote_ip not in {"0.0.0.0", "::"}:
            _add_rule_if_missing(
                network_event.rules,
                network_seen,
                "include",
                "DestinationIp",
                "is",
                remote_ip,
                network_group_id,
                network_group_name,
                "or",
            )

        if remote_port and remote_port != "0":
            _add_rule_if_missing(
                network_event.rules,
                network_seen,
                "include",
                "DestinationPort",
                "is",
                remote_port,
                network_group_id,
                network_group_name,
                "or",
            )

        if isinstance(owning_pid, int) and owning_pid in process_id_to_image:
            _add_rule_if_missing(
                network_event.rules,
                network_seen,
                "include",
                "Image",
                "is",
                process_id_to_image[owning_pid],
                network_group_id,
                network_group_name,
                "or",
            )

    if not process_event.rules:
        config.events.pop(1, None)
    if not network_event.rules:
        config.events.pop(3, None)

    return config
