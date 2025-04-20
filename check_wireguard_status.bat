@echo off
echo ===================================================
echo    检查 WireGuard 接口和网络共享状态
echo ===================================================

echo.
echo 步骤1: 检查 WireGuard 进程...
powershell -ExecutionPolicy Bypass -Command "Get-Process | Where-Object {$_.Name -like '*pekserver*' -or $_.Name -like '*wg*'} | Format-Table Name, Id, CPU"

echo.
echo 步骤2: 检查网络接口...
powershell -ExecutionPolicy Bypass -Command "Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex"

echo.
echo 步骤3: 检查 IP 转发状态...
powershell -ExecutionPolicy Bypass -Command "Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | Format-Table ifIndex, InterfaceAlias, AddressFamily, Forwarding"

echo.
echo 步骤4: 检查 Internet 连接共享状态...
powershell -ExecutionPolicy Bypass -Command "& {
    try {
        $netShare = New-Object -ComObject HNetCfg.HNetShare
        $connections = $netShare.EnumEveryConnection
        
        Write-Host '网络连接共享状态:'
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
            
            Write-Host ('接口: ' + $props.Name)
            Write-Host ('  描述: ' + $props.DeviceDescription)
            Write-Host ('  共享: ' + $(if ($sharingEnabled) { 'Enabled' } else { 'Disabled' }))
            Write-Host ('  类型: ' + $sharingType)
            Write-Host ''
        }
    } catch {
        Write-Host ('获取共享状态时出错: ' + $_)
    }
}"

echo.
echo 步骤5: 检查 WireGuard 接口 IP 配置...
powershell -ExecutionPolicy Bypass -Command "Get-NetIPAddress | Where-Object {$_.InterfaceAlias -like '*WireGuard*'} | Format-Table InterfaceAlias, IPAddress, PrefixLength"

echo.
echo 步骤6: 检查路由表...
powershell -ExecutionPolicy Bypass -Command "Get-NetRoute | Where-Object {$_.InterfaceAlias -like '*WireGuard*'} | Format-Table DestinationPrefix, NextHop, RouteMetric, InterfaceAlias"

echo.
echo ===================================================
echo    诊断完成
echo ===================================================
echo.
echo 如果 WireGuard 接口未显示或状态不是"Up"，请尝试重启服务器。
echo 如果 IP 转发未启用，请运行以下命令:
echo powershell -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1"
echo.
echo 如果 Internet 连接共享未正确配置，请运行 manual_configure_ics.bat 脚本。

pause
