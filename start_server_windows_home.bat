@echo off
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
echo 步骤4: 等待 WireGuard 接口创建...
echo 注意: 服务器将在启动后创建 WireGuard 接口
echo 启动服务器后，请等待几秒钟，然后再尝试配置 Internet 连接共享

echo.
echo 步骤5: 启动 VPN 服务器...
echo 正在启动 VPN 服务器，请保持此窗口打开
start /b pekserver.exe -port 23456 -enable-reg -skip-ip-forward-check=true
if %errorlevel% neq 0 (
    echo 错误: 启动 VPN 服务器失败!
    pause
    exit /b 1
)
echo VPN 服务器已启动

echo.
echo 步骤6: 等待 WireGuard 接口创建...
timeout /t 5 /nobreak
echo 正在检查 WireGuard 接口...

echo.
echo 步骤7: 配置 Internet 连接共享...
powershell -ExecutionPolicy Bypass -Command "$publicConnection = Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*'} | Select-Object -First 1; $vpnConnection = Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -First 1; if($publicConnection -and $vpnConnection) { Write-Host ('使用 ' + $publicConnection.Name + ' 共享到 ' + $vpnConnection.Name); netsh interface set interface \"$($publicConnection.Name)\" enabled; netsh interface set interface \"$($vpnConnection.Name)\" enabled; } else { Write-Host '未找到所需网络接口，请手动配置 Internet 连接共享'; }"

echo.
echo ===================================================
echo    VPN 服务器已启动并配置完成
echo ===================================================
echo.
echo 如果客户端连接后无法访问互联网，请手动配置 Internet 连接共享:
echo 1. 打开"网络连接"(按 Win+R，输入 ncpa.cpl)
echo 2. 右键点击您的主要网络连接(通常是连接到互联网的那个)
echo 3. 选择"属性"
echo 4. 切换到"共享"选项卡
echo 5. 勾选"允许其他网络用户通过此计算机的 Internet 连接来连接"
echo 6. 在下拉菜单中选择 WireGuard 网络连接
echo 7. 点击"确定"
echo.
echo 服务器日志:
echo ---------------------------------------------------
timeout /t 2 /nobreak
type nul > server_log.txt
powershell -ExecutionPolicy Bypass -Command "Get-Content -Path server_log.txt -Wait"
