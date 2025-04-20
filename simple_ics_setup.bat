@echo off
chcp 936
echo ===================================================
echo    Simple ICS Setup for WireGuard VPN
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
echo Step 2: Enabling IP forwarding...
powershell -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1"
if %errorlevel% neq 0 (
    echo Warning: Enabling IP forwarding may have failed, but will continue.
) else (
    echo IP forwarding enabled.
)

echo.
echo Step 3: Configuring firewall rules...
powershell -ExecutionPolicy Bypass -Command "netsh advfirewall firewall add rule name='Allow VPN Traffic' dir=in action=allow protocol=UDP localport=23456"
powershell -ExecutionPolicy Bypass -Command "netsh advfirewall firewall add rule name='Allow VPN Forwarding' dir=in action=allow protocol=ANY"
echo Firewall rules configured.

echo.
echo Step 4: Starting VPN server...
echo Starting VPN server, please keep this window open.
start /b pekserver.exe -port 23456 -enable-reg -skip-ip-forward-check=true
if %errorlevel% neq 0 (
    echo Error: Failed to start VPN server!
    pause
    exit /b 1
)
echo VPN server started.

echo.
echo Step 5: Waiting for WireGuard interface creation...
echo Waiting 10 seconds for the interface to be created...
timeout /t 10 /nobreak
echo Checking for WireGuard interface...

echo.
echo Step 6: Configuring Internet Connection Sharing...
powershell -ExecutionPolicy Bypass -Command "& {
    # Get external interface (connected to the internet)
    $externalInterface = Get-NetAdapter | Where-Object {
        $_.Status -eq 'Up' -and 
        $_.InterfaceDescription -notlike '*WireGuard*' -and 
        $_.InterfaceDescription -notlike '*TAP-Windows*'
    } | Select-Object -First 1
    
    # Wait a bit longer for WireGuard interface
    Start-Sleep -Seconds 3
    
    # Get WireGuard interface
    $vpnInterface = Get-NetAdapter | Where-Object {
        $_.InterfaceDescription -like '*WireGuard*' -or 
        $_.InterfaceDescription -like '*TAP-Windows*' -or 
        $_.InterfaceAlias -like '*WireGuard*'
    } | Select-Object -First 1
    
    if($externalInterface -and $vpnInterface) {
        Write-Host ('Using ' + $externalInterface.Name + ' to share to ' + $vpnInterface.Name)
        
        # Make sure both interfaces are enabled
        try {
            Enable-NetAdapter -Name $externalInterface.Name -Confirm:$false
            Enable-NetAdapter -Name $vpnInterface.Name -Confirm:$false
            Write-Host 'Network interfaces enabled'
        } catch {
            Write-Host ('Error enabling interfaces: ' + $_)
        }
        
        # Configure ICS
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare
            $connections = $netShare.EnumEveryConnection
            $externalConn = $null
            $vpnConn = $null
            
            # Find connections by name
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                if ($props.Name -eq $externalInterface.Name) {
                    $externalConn = $conn
                    Write-Host ('Found external connection: ' + $props.Name)
                } elseif ($props.Name -eq $vpnInterface.Name) {
                    $vpnConn = $conn
                    Write-Host ('Found VPN connection: ' + $props.Name)
                }
            }
            
            # Configure external interface
            if ($externalConn) {
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($externalConn)
                $config.EnableSharing(0) # 0 = PUBLIC
                Write-Host ('Enabled sharing on external interface: ' + $externalInterface.Name)
            } else {
                Write-Host ('Could not find external connection configuration')
            }
            
            # Configure VPN interface
            if ($vpnConn) {
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($vpnConn)
                $config.EnableSharing(1) # 1 = PRIVATE
                Write-Host ('Enabled sharing on VPN interface: ' + $vpnInterface.Name)
            } else {
                Write-Host ('Could not find VPN connection configuration')
                
                # Try to find by interface index
                Write-Host 'Trying to find VPN interface by index...'
                $found = $false
                foreach ($conn in $connections) {
                    $props = $netShare.NetConnectionProps.Invoke($conn)
                    Write-Host ('Checking interface: ' + $props.Name + ' (index: ' + $props.DeviceIndex + ')')
                    if ($props.DeviceIndex -eq $vpnInterface.ifIndex) {
                        $vpnConn = $conn
                        $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($vpnConn)
                        $config.EnableSharing(1)
                        Write-Host ('Found and enabled sharing on VPN interface by index')
                        $found = $true
                        break
                    }
                }
                
                if (-not $found) {
                    Write-Host 'Could not find VPN connection configuration by any method'
                }
            }
        } catch {
            Write-Host ('Error configuring ICS: ' + $_)
            Write-Host 'Please configure Internet Connection Sharing manually'
        }
    } else {
        if (-not $externalInterface) {
            Write-Host 'Could not find external network interface'
        }
        if (-not $vpnInterface) {
            Write-Host 'Could not find WireGuard network interface'
            Write-Host 'All network interfaces:'
            Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex
        }
    }
}"

echo.
echo ===================================================
echo    VPN Server Started and ICS Configured
echo ===================================================
echo.
echo If clients cannot access the internet after connecting, try:
echo 1. Manually configure Internet Connection Sharing:
echo    a. Open "Network Connections" (press Win+R, type ncpa.cpl)
echo    b. Right-click your main network connection (usually the one connected to the internet)
echo    c. Select "Properties"
echo    d. Switch to the "Sharing" tab
echo    e. Check "Allow other network users to connect through this computer's Internet connection"
echo    f. Select the WireGuard network connection in the dropdown menu
echo    g. Click "OK"
echo.
echo Note: If you cannot find the WireGuard network connection in the dropdown menu, try:
echo 1. Close and restart the server
echo 2. Make sure the server runs for a few seconds before configuring sharing
echo 3. If you still cannot find it, try restarting your computer
echo.
echo Server log:
echo ---------------------------------------------------
timeout /t 2 /nobreak
type nul > server_log.txt
powershell -ExecutionPolicy Bypass -Command "Get-Content -Path server_log.txt -Wait"
