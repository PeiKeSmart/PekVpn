@echo off
chcp 936
echo ===================================================
echo    Manual Internet Connection Sharing Configuration
echo ===================================================

echo.
echo Step 1: Checking administrator privileges...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo Error: Please run this script as administrator!
    echo Right-click the script and select "Run as administrator"
    pause
    exit /b 1
)
echo Administrator privileges confirmed.

echo.
echo Step 2: Displaying all network interfaces...
powershell -ExecutionPolicy Bypass -Command "Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex"

echo.
echo Step 3: Attempting to configure Internet Connection Sharing...
powershell -ExecutionPolicy Bypass -Command "& {
    # Get all network adapters
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    
    # Display all interfaces
    Write-Host 'Available network interfaces:'
    $adapters | ForEach-Object { Write-Host ('Index: ' + $_.ifIndex + ', Name: ' + $_.Name + ', Description: ' + $_.InterfaceDescription) }
    
    # Get external interface
    $externalInterface = $adapters | Where-Object { 
        $_.InterfaceDescription -notlike '*WireGuard*' -and 
        $_.InterfaceDescription -notlike '*TAP-Windows*' 
    } | Select-Object -First 1
    
    # Get WireGuard interface
    $wireguardInterface = $adapters | Where-Object { 
        $_.InterfaceDescription -like '*WireGuard*' -or 
        $_.InterfaceDescription -like '*TAP-Windows*' -or 
        $_.InterfaceAlias -like '*WireGuard*' 
    } | Select-Object -First 1
    
    if ($externalInterface -and $wireguardInterface) {
        Write-Host ('Using external interface: ' + $externalInterface.Name)
        Write-Host ('Using WireGuard interface: ' + $wireguardInterface.Name)
        
        # Ensure interfaces are enabled
        netsh interface set interface name=\"$($externalInterface.Name)\" admin=enabled
        netsh interface set interface name=\"$($wireguardInterface.Name)\" admin=enabled
        
        # Try using COM object to configure ICS
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare
            $connections = $netShare.EnumEveryConnection
            
            # Display all connections
            Write-Host 'All network connections:'
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                Write-Host ('Name: ' + $props.Name + ', Device Index: ' + $props.DeviceIndex)
            }
            
            # Find external interface connection
            $externalConn = $null
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                if ($props.Name -eq $externalInterface.Name) {
                    $externalConn = $conn
                    break
                }
            }
            
            # Find WireGuard interface connection
            $wireguardConn = $null
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                if ($props.Name -eq $wireguardInterface.Name) {
                    $wireguardConn = $conn
                    break
                }
            }
            
            # Configure ICS
            if ($externalConn) {
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($externalConn)
                $config.EnableSharing(0)
                Write-Host ('Enabled sharing on external interface: ' + $externalInterface.Name)
            } else {
                Write-Host ('Could not find external connection configuration')
            }
            
            if ($wireguardConn) {
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($wireguardConn)
                $config.EnableSharing(1)
                Write-Host ('Enabled sharing on WireGuard interface: ' + $wireguardInterface.Name)
            } else {
                Write-Host ('Could not find WireGuard connection configuration')
                
                # Try to find by interface index
                Write-Host 'Trying to find WireGuard interface by index...'
                foreach ($conn in $connections) {
                    $props = $netShare.NetConnectionProps.Invoke($conn)
                    if ($props.DeviceIndex -eq $wireguardInterface.ifIndex) {
                        $wireguardConn = $conn
                        $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($wireguardConn)
                        $config.EnableSharing(1)
                        Write-Host ('Found and enabled sharing on WireGuard interface by index')
                        break
                    }
                }
            }
        } catch {
            Write-Host ('Error configuring ICS: ' + $_)
        }
    } else {
        if (-not $externalInterface) {
            Write-Host 'Could not find external network interface'
        }
        if (-not $wireguardInterface) {
            Write-Host 'Could not find WireGuard network interface'
        }
    }
}"

echo.
echo Step 4: Displaying current Internet Connection Sharing status...
powershell -ExecutionPolicy Bypass -Command "& {
    try {
        $netShare = New-Object -ComObject HNetCfg.HNetShare
        $connections = $netShare.EnumEveryConnection
        
        Write-Host 'Current Internet Connection Sharing status:'
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
echo ===================================================
echo    Manual Configuration Complete
echo ===================================================
echo.
echo If Internet Connection Sharing is still not properly configured, please:
echo 1. Open "Network Connections" (press Win+R, type ncpa.cpl)
echo 2. Right-click your main network connection (usually the one connected to the internet)
echo 3. Select "Properties"
echo 4. Switch to the "Sharing" tab
echo 5. Check "Allow other network users to connect through this computer's Internet connection"
echo 6. Select the WireGuard network connection in the dropdown menu
echo 7. Click "OK"

pause
