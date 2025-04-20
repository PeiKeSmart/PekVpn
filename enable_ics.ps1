# 启用Internet连接共享的PowerShell脚本
# 需要管理员权限运行

# 获取外部接口（通常是连接到Internet的接口）
$externalInterface = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*'} | Select-Object -First 1

# 获取WireGuard接口（内部接口）
$wireguardInterface = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -First 1

if ($externalInterface -and $wireguardInterface) {
    try {
        # 使用netsh命令启用ICS
        $externalIndex = $externalInterface.ifIndex
        $wireguardIndex = $wireguardInterface.ifIndex
        
        # 启用Internet连接共享
        $sharingManager = New-Object -ComObject HNetCfg.HNetShare
        $connection = $sharingManager.EnumEveryConnection | Where-Object {
            $sharingManager.NetConnectionProps.Invoke($_).DeviceName -eq $externalInterface.Name
        }
        
        if ($connection) {
            $sharingConfig = $sharingManager.INetSharingConfigurationForINetConnection.Invoke($connection)
            $sharingConfig.EnableSharing(0) # 0 = PUBLIC, 1 = PRIVATE
            
            $connection = $sharingManager.EnumEveryConnection | Where-Object {
                $sharingManager.NetConnectionProps.Invoke($_).DeviceName -eq $wireguardInterface.Name
            }
            
            if ($connection) {
                $sharingConfig = $sharingManager.INetSharingConfigurationForINetConnection.Invoke($connection)
                $sharingConfig.EnableSharing(1) # 0 = PUBLIC, 1 = PRIVATE
                Write-Host "已成功启用Internet连接共享"
                Write-Host "外部接口: $($externalInterface.Name) (索引: $externalIndex)"
                Write-Host "WireGuard接口: $($wireguardInterface.Name) (索引: $wireguardIndex)"
                exit 0
            } else {
                Write-Host "无法找到WireGuard接口的连接配置"
                exit 1
            }
        } else {
            Write-Host "无法找到外部接口的连接配置"
            exit 1
        }
    } catch {
        Write-Host "启用Internet连接共享时出错: $_"
        exit 1
    }
} else {
    if (-not $externalInterface) {
        Write-Host "未找到外部网络接口"
    }
    if (-not $wireguardInterface) {
        Write-Host "未找到WireGuard网络接口"
    }
    exit 1
}
