@echo off
chcp 936
echo ===================================================
echo    Check WireGuard and ICS Status
echo ===================================================

echo.
echo Step 1: Checking WireGuard processes...
powershell -ExecutionPolicy Bypass -Command "Get-Process | Where-Object {$_.Name -like '*pekserver*' -or $_.Name -like '*wg*'} | Format-Table Name, Id, CPU"

echo.
echo Step 2: Checking network interfaces...
powershell -ExecutionPolicy Bypass -Command "Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex"

echo.
echo Step 3: Checking IP forwarding status...
powershell -ExecutionPolicy Bypass -Command "Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | Format-Table ifIndex, InterfaceAlias, AddressFamily, Forwarding"

echo.
echo Step 4: Checking Internet Connection Sharing status...
powershell -ExecutionPolicy Bypass -Command "& {
    try {
        $netShare = New-Object -ComObject HNetCfg.HNetShare
        $connections = $netShare.EnumEveryConnection
        
        Write-Host 'Network connection sharing status:'
        foreach ($conn in $connections) {
            $props = $netShare.NetConnectionProps.Invoke($conn)
            $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($conn)
            
            $sharingEnabled = $config.SharingEnabled
            $sharingType = 'None'
            if ($sharingEnabled) {
                if ($config.SharingConnectionType -eq 0) {
                    $sharingType = 'Public (Internet)'
                } elseif ($config.SharingConnectionType -eq 1) {
                    $sharingType = 'Private (Client)'
                }
            }
            
            Write-Host ('Interface: ' + $props.Name)
            Write-Host ('  Description: ' + $props.DeviceDescription)
            Write-Host ('  Sharing: ' + $(if ($sharingEnabled) { 'Enabled' } else { 'Disabled' }))
            Write-Host ('  Type: ' + $sharingType)
            Write-Host ''
        }
    } catch {
        Write-Host ('Error getting sharing status: ' + $_)
    }
}"

echo.
echo Step 5: Checking WireGuard interface IP configuration...
powershell -ExecutionPolicy Bypass -Command "Get-NetIPAddress | Where-Object {$_.InterfaceAlias -like '*WireGuard*'} | Format-Table InterfaceAlias, IPAddress, PrefixLength"

echo.
echo Step 6: Checking routing table...
powershell -ExecutionPolicy Bypass -Command "Get-NetRoute | Where-Object {$_.InterfaceAlias -like '*WireGuard*'} | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias"

echo.
echo ===================================================
echo    Diagnostics Complete
echo ===================================================
echo.
echo If WireGuard interface is not shown or status is not "Up", try restarting the server.
echo If IP forwarding is not enabled, run:
echo powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1"
echo.
echo If Internet Connection Sharing is not properly configured, run simple_ics_setup.bat.

pause
