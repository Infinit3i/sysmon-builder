$ErrorActionPreference = 'Stop'
Get-CimInstance Win32_Process |
Select-Object Name, ProcessId, ParentProcessId, ExecutablePath, CommandLine |
ConvertTo-Json -Depth 4 -Compress
