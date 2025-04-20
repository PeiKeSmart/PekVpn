@echo off
chcp 936
echo ===================================================
echo    PekHight VPN 服务器启动脚本 (Windows 家庭版)
echo ===================================================
echo 此脚本专为没有 Routing and Remote Access 服务的 Windows 10/11 家庭版设计

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
echo 步骤2: 启用 IP 转发...
powershell -ExecutionPolicy Bypass -Command "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters' -Name 'IPEnableRouter' -Value 1"
if %errorlevel% neq 0 (
    echo 警告: 启用 IP 转发可能失败，但将继续执行
) else (
    echo IP 转发已启用
)

echo.
echo 步骤3: 配置防火墙规则...
powershell -ExecutionPolicy Bypass -Command "netsh advfirewall firewall add rule name='Allow VPN Traffic' dir=in action=allow protocol=UDP localport=23456"
powershell -ExecutionPolicy Bypass -Command "netsh advfirewall firewall add rule name='Allow VPN Forwarding' dir=in action=allow protocol=ANY"
echo 防火墙规则已配置

echo.
echo 步骤4: 启动 VPN 服务器...
echo 正在启动 VPN 服务器，请保持此窗口打开
start /b pekserver.exe -port 23456 -enable-reg -skip-ip-forward-check=true
if %errorlevel% neq 0 (
    echo 错误: 启动 VPN 服务器失败!
    pause
    exit /b 1
)
echo VPN 服务器已启动

echo.
echo 步骤5: 等待 WireGuard 接口创建...
timeout /t 5 /nobreak
echo 正在检查 WireGuard 接口...

echo.
echo 步骤6: 配置 Internet 连接共享...
powershell -ExecutionPolicy Bypass -Command "$publicConnection = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*' -and $_.InterfaceDescription -notlike '*TAP-Windows*'} | Select-Object -First 1; Start-Sleep -Seconds 2; $vpnConnection = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*' -or $_.InterfaceDescription -like '*TAP-Windows*' -or $_.InterfaceAlias -like '*WireGuard*'} | Select-Object -First 1; if($publicConnection -and $vpnConnection) { Write-Host ('使用 ' + $publicConnection.Name + ' 共享到 ' + $vpnConnection.Name); try { $netShare = New-Object -ComObject HNetCfg.HNetShare; $connection = $netShare.EnumEveryConnection | Where-Object { $netShare.NetConnectionProps.Invoke($_).Name -eq $publicConnection.Name }; if ($connection) { $config = $netShare.INetSharingConfigurationForINetConnection.Invoke($connection); $config.EnableSharing(0); Write-Host ('已启用 ' + $publicConnection.Name + ' 的共享'); }; $wgConnection = $netShare.EnumEveryConnection | Where-Object { $netShare.NetConnectionProps.Invoke($_).Name -eq $vpnConnection.Name }; if ($wgConnection) { $wgConfig = $netShare.INetSharingConfigurationForINetConnection.Invoke($wgConnection); $wgConfig.EnableSharing(1); Write-Host ('已启用 ' + $vpnConnection.Name + ' 的共享'); } else { Write-Host ('无法找到 ' + $vpnConnection.Name + ' 的连接配置'); } } catch { Write-Host ('启用共享时出错: ' + $_); Write-Host '请手动配置Internet连接共享'; } } else { Write-Host '未找到所需网络接口，请手动配置 Internet 连接共享'; }"

echo.
echo ===================================================
echo    VPN 服务器已启动并配置完成
echo ===================================================
echo.
echo 如果客户端连接后无法访问互联网，请尝试以下操作:
echo 1. 手动配置 Internet 连接共享:
echo    a. 打开"网络连接"(按 Win+R，输入 ncpa.cpl)
echo    b. 右键点击您的主要网络连接(通常是连接到互联网的那个)
echo    c. 选择"属性"
echo    d. 切换到"共享"选项卡
echo    e. 勾选"允许其他网络用户通过此计算机的 Internet 连接来连接"
echo    f. 在下拉菜单中选择 WireGuard 网络连接
echo    g. 点击"确定"
echo.
echo 注意: 如果在下拉菜单中找不到 WireGuard 网络连接，请尝试以下操作:
echo 1. 关闭并重新运行服务器
echo 2. 确保服务器运行几秒后再配置共享
echo 3. 如果仍然无法找到，请尝试重启计算机后再试
echo.
echo 服务器日志:
echo ---------------------------------------------------
timeout /t 2 /nobreak
type nul > server_log.txt
powershell -ExecutionPolicy Bypass -Command "Get-Content -Path server_log.txt -Wait"
