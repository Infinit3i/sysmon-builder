$ErrorActionPreference = 'Stop'
$tcp = Get-NetTCPConnection -ErrorAction SilentlyContinue |
Select-Object State, LocalAddress, LocalPort, RemoteAddress, RemotePort, OwningProcess

$udp = Get-NetUDPEndpoint -ErrorAction SilentlyContinue |
Select-Object LocalAddress, LocalPort, OwningProcess

[PSCustomObject]@{
    Tcp = $tcp
    Udp = $udp
} | ConvertTo-Json -Depth 5 -Compress
