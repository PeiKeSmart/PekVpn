# 配置Internet连接共享的PowerShell脚本
# 需要管理员权限运行

# 设置错误操作首选项
$ErrorActionPreference = "Continue"

Write-Host "开始配置Internet连接共享..."

# 等待几秒钟，确保WireGuard接口已创建
Write-Host "等待WireGuard接口创建..."
Start-Sleep -Seconds 3

# 获取外部接口（通常是连接到Internet的接口）
Write-Host "正在查找外部网络接口..."
$externalInterface = Get-NetAdapter | Where-Object {
    $_.Status -eq 'Up' -and 
    $_.InterfaceDescription -notlike '*WireGuard*' -and 
    $_.InterfaceDescription -notlike '*TAP-Windows*'
} | Select-Object -First 1

if ($externalInterface) {
    Write-Host "找到外部网络接口: $($externalInterface.Name) (索引: $($externalInterface.ifIndex))"
} else {
    Write-Host "错误: 未找到可用的外部网络接口"
    exit 1
}

# 获取WireGuard接口（内部接口）
Write-Host "正在查找WireGuard接口..."
$wireguardInterface = Get-NetAdapter | Where-Object {
    $_.InterfaceDescription -like '*WireGuard*' -or 
    $_.InterfaceDescription -like '*TAP-Windows*' -or 
    $_.InterfaceAlias -like '*WireGuard*'
} | Select-Object -First 1

if ($wireguardInterface) {
    Write-Host "找到WireGuard接口: $($wireguardInterface.Name) (索引: $($wireguardInterface.ifIndex))"
} else {
    Write-Host "错误: 未找到WireGuard网络接口"
    Write-Host "可能的原因:"
    Write-Host "1. WireGuard服务器尚未启动"
    Write-Host "2. WireGuard接口创建失败"
    Write-Host "3. 接口名称与预期不符"
    
    # 列出所有网络接口以便诊断
    Write-Host "`n所有网络接口:"
    Get-NetAdapter | Format-Table Name, InterfaceDescription, Status, ifIndex
    
    exit 1
}

# 确保两个接口都已启用
Write-Host "确保网络接口已启用..."
try {
    Enable-NetAdapter -Name $externalInterface.Name -Confirm:$false
    Enable-NetAdapter -Name $wireguardInterface.Name -Confirm:$false
    Write-Host "网络接口已启用"
} catch {
    Write-Host "启用网络接口时出错: $_"
}

# 使用HNetCfg.HNetShare COM对象配置Internet连接共享
Write-Host "正在配置Internet连接共享..."
try {
    # 创建HNetCfg.HNetShare COM对象
    $netShare = New-Object -ComObject HNetCfg.HNetShare
    
    # 获取外部接口的连接
    $connections = $netShare.EnumEveryConnection
    $externalConnection = $null
    $wireguardConnection = $null
    
    foreach ($conn in $connections) {
        $props = $netShare.NetConnectionProps.Invoke($conn)
        if ($props.Name -eq $externalInterface.Name) {
            $externalConnection = $conn
            Write-Host "找到外部接口连接: $($props.Name)"
        } elseif ($props.Name -eq $wireguardInterface.Name) {
            $wireguardConnection = $conn
            Write-Host "找到WireGuard接口连接: $($props.Name)"
        }
    }
    
    # 配置外部接口共享
    if ($externalConnection) {
        $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($externalConnection)
        # 0 = PUBLIC, 1 = PRIVATE
        $config.EnableSharing(0)
        Write-Host "已启用外部接口($($externalInterface.Name))的共享"
    } else {
        Write-Host "错误: 无法找到外部接口的连接配置"
    }
    
    # 配置WireGuard接口共享
    if ($wireguardConnection) {
        $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($wireguardConnection)
        # 0 = PUBLIC, 1 = PRIVATE
        $config.EnableSharing(1)
        Write-Host "已启用WireGuard接口($($wireguardInterface.Name))的共享"
    } else {
        Write-Host "错误: 无法找到WireGuard接口的连接配置"
        
        # 尝试使用接口索引查找
        Write-Host "尝试使用接口索引查找WireGuard接口..."
        $found = $false
        foreach ($conn in $connections) {
            $props = $netShare.NetConnectionProps.Invoke($conn)
            Write-Host "检查接口: $($props.Name) (索引: $($props.DeviceIndex))"
            if ($props.DeviceIndex -eq $wireguardInterface.ifIndex) {
                $wireguardConnection = $conn
                $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($wireguardConnection)
                $config.EnableSharing(1)
                Write-Host "已通过索引找到并启用WireGuard接口的共享"
                $found = $true
                break
            }
        }
        
        if (-not $found) {
            Write-Host "无法通过任何方式找到WireGuard接口的连接配置"
        }
    }
    
    Write-Host "Internet连接共享配置完成"
} catch {
    Write-Host "配置Internet连接共享时出错: $_"
    Write-Host "请手动配置Internet连接共享"
    
    Write-Host "`n手动配置步骤:"
    Write-Host "1. 打开'网络连接'(按Win+R，输入ncpa.cpl)"
    Write-Host "2. 右键点击您的主要网络连接(通常是连接到互联网的那个)"
    Write-Host "3. 选择'属性'"
    Write-Host "4. 切换到'共享'选项卡"
    Write-Host "5. 勾选'允许其他网络用户通过此计算机的Internet连接来连接'"
    Write-Host "6. 在下拉菜单中选择WireGuard网络连接"
    Write-Host "7. 点击'确定'"
}

# 显示当前的共享状态
Write-Host "`n当前Internet连接共享状态:"
try {
    $netShare = New-Object -ComObject HNetCfg.HNetShare
    $connections = $netShare.EnumEveryConnection
    
    foreach ($conn in $connections) {
        $props = $netShare.NetConnectionProps.Invoke($conn)
        $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($conn)
        
        $publicEnabled = $config.SharingEnabled -and $config.SharingConnectionType -eq 0
        $privateEnabled = $config.SharingEnabled -and $config.SharingConnectionType -eq 1
        
        $status = "未共享"
        if ($publicEnabled) { $status = "共享为公共连接" }
        if ($privateEnabled) { $status = "共享为私有连接" }
        
        Write-Host "接口: $($props.Name), 状态: $status"
    }
} catch {
    Write-Host "获取共享状态时出错: $_"
}

Write-Host "`nInternet连接共享配置脚本执行完成"
