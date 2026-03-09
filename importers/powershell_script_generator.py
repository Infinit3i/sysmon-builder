from pathlib import Path

SCRIPT_DEFINITIONS: dict[str, str] = {
    "get_sysmon_events.ps1": r"""param(
    [int[]]$EventIds = @(1..30),
    [int]$MaxEventsPerId = 500
)

$ErrorActionPreference = 'Stop'
$logName = 'Microsoft-Windows-Sysmon/Operational'

$all = foreach ($eventId in $EventIds) {
    try {
        $events = Get-WinEvent -FilterHashtable @{ LogName = $logName; Id = $eventId } -MaxEvents $MaxEventsPerId -ErrorAction Stop
    }
    catch {
        continue
    }

    foreach ($ev in $events) {
        $xml = [xml]$ev.ToXml()
        $flat = [ordered]@{
            EventId = [int]$eventId
        }

        foreach ($node in $xml.Event.EventData.Data) {
            if ($null -eq $node.Name -or [string]::IsNullOrWhiteSpace($node.Name)) {
                continue
            }

            $name = [string]$node.Name
            $value = [string]$node.'#text'
            if ([string]::IsNullOrWhiteSpace($value)) {
                continue
            }

            $flat[$name] = $value
        }

        [PSCustomObject]$flat
    }
}

$all | ConvertTo-Json -Depth 8 -Compress
""",
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
    "get_registry_keys.ps1": r"""param(
    [int]$MaxPerPath = 200
)

$ErrorActionPreference = 'Stop'

$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SYSTEM\CurrentControlSet\Services',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
    'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\System'
)

$results = foreach ($path in $paths) {
    if (-not (Test-Path $path)) {
        continue
    }

    try {
        $item = Get-Item -LiteralPath $path -ErrorAction Stop
        $values = Get-ItemProperty -LiteralPath $path -ErrorAction SilentlyContinue
        if ($null -ne $values) {
            foreach ($prop in $values.PSObject.Properties) {
                if ($prop.Name -in @('PSPath', 'PSParentPath', 'PSChildName', 'PSDrive', 'PSProvider')) {
                    continue
                }
                [PSCustomObject]@{
                    RegistryPath = $path
                    Name = $prop.Name
                    Value = [string]$prop.Value
                    Kind = 'Value'
                }
            }
        }

        Get-ChildItem -LiteralPath $path -ErrorAction SilentlyContinue |
        Select-Object -First $MaxPerPath |
        ForEach-Object {
            [PSCustomObject]@{
                RegistryPath = $_.PSPath
                Name = $_.PSChildName
                Value = ''
                Kind = 'SubKey'
            }
        }
    }
    catch {
        [PSCustomObject]@{
            RegistryPath = $path
            Name = '_error'
            Value = $_.Exception.Message
            Kind = 'Error'
        }
    }
}

$results | ConvertTo-Json -Depth 5 -Compress
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

    legacy_patterns = ("event_*.ps1", "_query_sysmon_event.ps1")
    for pattern in legacy_patterns:
        for old_file in base_dir.glob(pattern):
            if old_file.name in SCRIPT_DEFINITIONS:
                continue
            old_file.unlink(missing_ok=True)

    return written_files
