$ErrorActionPreference = 'Stop'
Get-CimInstance Win32_Service |
Select-Object Name, DisplayName, State, StartMode, PathName, ProcessId |
ConvertTo-Json -Depth 4 -Compress
