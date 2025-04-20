@echo off
echo ===================================================
echo    手动配置 Internet 连接共享
echo ===================================================
echo 此脚本用于在自动配置失败时手动配置 Internet 连接共享

echo.
echo 步骤1: 检查管理员权限...
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo 错误: 请以管理员身份运行此脚本!
    echo 右键点击此脚本，选择"以管理员身份运行"
    pause
    exit /b 1
)
echo 已确认管理员权限

echo.
echo 步骤2: 显示所有网络接口...
powershell -ExecutionPolicy Bypass -Command "Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex"

echo.
echo 步骤3: 尝试使用备用方法配置 Internet 连接共享...
powershell -ExecutionPolicy Bypass -Command "& {
    # 获取所有网络接口
    $adapters = Get-NetAdapter | Where-Object { $_.Status -eq 'Up' }
    
    # 显示所有接口
    Write-Host '可用的网络接口:'
    $adapters | ForEach-Object { Write-Host ('索引: ' + $_.ifIndex + ', 名称: ' + $_.Name + ', 描述: ' + $_.InterfaceDescription) }
    
    # 尝试使用netsh命令配置ICS
    Write-Host '尝试使用netsh命令配置ICS...'
    
    # 获取外部接口
    $externalInterface = $adapters | Where-Object { 
        $_.InterfaceDescription -notlike '*WireGuard*' -and 
        $_.InterfaceDescription -notlike '*TAP-Windows*' 
    } | Select-Object -First 1
    
    # 获取WireGuard接口
    $wireguardInterface = $adapters | Where-Object { 
        $_.InterfaceDescription -like '*WireGuard*' -or 
        $_.InterfaceDescription -like '*TAP-Windows*' -or 
        $_.InterfaceAlias -like '*WireGuard*' 
    } | Select-Object -First 1
    
    if ($externalInterface -and $wireguardInterface) {
        Write-Host ('使用外部接口: ' + $externalInterface.Name)
        Write-Host ('使用WireGuard接口: ' + $wireguardInterface.Name)
        
        # 确保接口已启用
        netsh interface set interface name=\"$($externalInterface.Name)\" admin=enabled
        netsh interface set interface name=\"$($wireguardInterface.Name)\" admin=enabled
        
        # 尝试使用COM对象配置ICS
        try {
            $netShare = New-Object -ComObject HNetCfg.HNetShare
            $connections = $netShare.EnumEveryConnection
            
            # 遍历所有连接并显示详细信息
            Write-Host '所有网络连接:'
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                Write-Host ('名称: ' + $props.Name + ', 设备索引: ' + $props.DeviceIndex)
            }
            
            # 尝试找到外部接口
            $externalConn = $null
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                if ($props.Name -eq $externalInterface.Name) {
                    $externalConn = $conn
                    break
                }
            }
            
            # 尝试找到WireGuard接口
            $wireguardConn = $null
            foreach ($conn in $connections) {
                $props = $netShare.NetConnectionProps.Invoke($conn)
                if ($props.Name -eq $wireguardInterface.Name) {
                    $wireguardConn = $conn
                    break
                }
            }
            
            # 配置ICS
            if ($externalConn) {
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($externalConn)
                $config.EnableSharing(0)
                Write-Host ('已启用外部接口共享: ' + $externalInterface.Name)
            } else {
                Write-Host ('无法找到外部接口连接: ' + $externalInterface.Name)
            }
            
            if ($wireguardConn) {
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($wireguardConn)
                $config.EnableSharing(1)
                Write-Host ('已启用WireGuard接口共享: ' + $wireguardInterface.Name)
            } else {
                Write-Host ('无法找到WireGuard接口连接: ' + $wireguardInterface.Name)
            }
        } catch {
            Write-Host ('配置ICS时出错: ' + $_)
        }
    } else {
        if (-not $externalInterface) {
            Write-Host '未找到外部网络接口'
        }
        if (-not $wireguardInterface) {
            Write-Host '未找到WireGuard网络接口'
        }
    }
}"

echo.
echo 步骤4: 显示手动配置说明...
echo 如果自动配置仍然失败，请按照以下步骤手动配置:
echo 1. 打开"网络连接"(按 Win+R，输入 ncpa.cpl)
echo 2. 右键点击您的主要网络连接(通常是连接到互联网的那个)
echo 3. 选择"属性"
echo 4. 切换到"共享"选项卡
echo 5. 勾选"允许其他网络用户通过此计算机的 Internet 连接来连接"
echo 6. 在下拉菜单中选择 WireGuard 网络连接
echo 7. 点击"确定"

echo.
echo 配置完成后，您可以使用以下命令检查 IP 转发是否正常工作:
echo powershell -Command "Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'}"

pause
