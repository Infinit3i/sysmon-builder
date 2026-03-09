from pathlib import Path


SCRIPT_DEFINITIONS: dict[str, str] = {
    "get_processes.ps1": r"""$ErrorActionPreference = 'Stop'
Get-CimInstance Win32_Process |
Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine |
ConvertTo-Json -Depth 4 -Compress
""",
    "get_network_connections.ps1": r"""$ErrorActionPreference = 'Stop'
$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
Select-Object LocalAddress, LocalPort, OwningProcess

[PSCustomObject]@{
    Tcp = $tcp
    Udp = $udp
} | ConvertTo-Json -Depth 5 -Compress
""",
    "get_services.ps1": r"""$ErrorActionPreference = 'Stop'
Get-CimInstance Win32_Service |
Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId |
ConvertTo-Json -Depth 4 -Compress
""",
}


def ensure_ps_scripts(output_dir: str | Path | None = None) -> list[Path]:
    base_dir = Path(output_dir) if output_dir is not None else Path(__file__).resolve().parent / "ps1"
    base_dir.mkdir(parents=True, exist_ok=True)

    written_files: list[Path] = []
    for file_name, content in SCRIPT_DEFINITIONS.items():
        file_path = base_dir / file_name
        file_path.write_text(content, encoding="utf-8")
        written_files.append(file_path)

    return written_files
