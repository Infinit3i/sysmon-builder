param(
    [int]$MaxPerPath = 200
)

$ErrorActionPreference = 'Stop'

$paths = @(
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run',
    'HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
    'HKLM:\SYSTEM\CurrentControlSet\Services',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tasks',
    'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree',
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
