param(
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
