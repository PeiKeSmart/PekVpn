# 简化版NAT配置脚本
# 需要管理员权限运行

# 启用IP转发
Write-Host "正在启用IP转发..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1

# 获取外部接口（通常是连接到Internet的接口）
$externalInterface = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*'} | Select-Object -First 1

# 获取WireGuard接口（内部接口）
$wireguardInterface = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -First 1

if ($externalInterface -and $wireguardInterface) {
    try {
        # 使用netsh命令配置IP转发
        $externalIndex = $externalInterface.ifIndex
        $wireguardIndex = $wireguardInterface.ifIndex
        
        # 配置防火墙允许转发
        Write-Host "正在配置防火墙规则..."
        netsh advfirewall firewall add rule name="Allow VPN Traffic" dir=in action=allow protocol=UDP localport=23456
        netsh advfirewall firewall add rule name="Allow VPN Forwarding" dir=in action=allow protocol=ANY
        
        # 尝试使用Internet连接共享
        Write-Host "正在配置Internet连接共享..."
        # 使用netsh命令启用ICS
        netsh interface set interface "$($externalInterface.Name)" ENABLED
        netsh interface set interface "$($wireguardInterface.Name)" ENABLED
        
        # 使用netsh命令配置NAT
        netsh interface portproxy add v4tov4 listenport=0 listenaddress=0.0.0.0 connectport=0 connectaddress=0.0.0.0 protocol=tcp
        
        Write-Host "配置完成"
        Write-Host "外部接口: $($externalInterface.Name) (索引: $externalIndex)"
        Write-Host "WireGuard接口: $($wireguardInterface.Name) (索引: $wireguardIndex)"
        
    } catch {
        Write-Host "配置NAT时出错: $_"
    }
} else {
    if (-not $externalInterface) {
        Write-Host "未找到外部网络接口"
    }
    if (-not $wireguardInterface) {
        Write-Host "未找到WireGuard网络接口"
    }
}
