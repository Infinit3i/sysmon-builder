$ErrorActionPreference = 'Stop'

$tasks = Get-ScheduledTask -ErrorAction SilentlyContinue

$results = foreach ($task in $tasks) {
    foreach ($action in $task.Actions) {
        if ($null -eq $action.Execute -or [string]::IsNullOrWhiteSpace([string]$action.Execute)) {
            continue
        }

        [PSCustomObject]@{
            TaskName = [string]$task.TaskName
            TaskPath = [string]$task.TaskPath
            State = [string]$task.State
            Execute = [string]$action.Execute
            Arguments = [string]$action.Arguments
            WorkingDirectory = [string]$action.WorkingDirectory
            UserId = [string]$task.Principal.UserId
            LogonType = [string]$task.Principal.LogonType
            RunLevel = [string]$task.Principal.RunLevel
        }
    }
}

$results | ConvertTo-Json -Depth 5 -Compress
