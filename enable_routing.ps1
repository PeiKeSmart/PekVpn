# 启用路由和远程访问服务的PowerShell脚本
# 需要管理员权限运行

# 启用IP转发
Write-Host "正在启用IP转发..."
Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters" -Name "IPEnableRouter" -Value 1

# 启用路由和远程访问服务
Write-Host "正在启用路由和远程访问服务..."
$service = Get-Service -Name RemoteAccess -ErrorAction SilentlyContinue
if ($service) {
    if ($service.Status -ne "Running") {
        Set-Service -Name RemoteAccess -StartupType Automatic
        Start-Service -Name RemoteAccess
        Write-Host "已启动路由和远程访问服务"
    } else {
        Write-Host "路由和远程访问服务已在运行"
    }
} else {
    Write-Host "未找到路由和远程访问服务，尝试安装..."
    # 尝试安装RRAS功能
    try {
        Install-WindowsFeature -Name Routing -IncludeManagementTools
        Write-Host "已安装路由功能"
        
        # 再次尝试启动服务
        Set-Service -Name RemoteAccess -StartupType Automatic
        Start-Service -Name RemoteAccess
        Write-Host "已启动路由和远程访问服务"
    } catch {
        Write-Host "安装路由功能失败: $_"
        Write-Host "请手动安装路由和远程访问服务"
    }
}

# 配置NAT
Write-Host "正在配置NAT..."
try {
    # 获取WireGuard接口
    $wireguardInterface = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -First 1
    
    if ($wireguardInterface) {
        # 移除现有的NAT配置
        Get-NetNat -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue
        
        # 创建新的NAT配置
        $natName = "WireGuardNAT_" + (Get-Random)
        New-NetNat -Name $natName -InternalIPInterfaceAddressPrefix "10.8.0.0/24"
        Write-Host "已创建NAT配置: $natName"
    } else {
        Write-Host "未找到WireGuard接口，无法配置NAT"
    }
} catch {
    Write-Host "配置NAT失败: $_"
}

Write-Host "IP转发和NAT配置完成"
