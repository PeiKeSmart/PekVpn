@echo off
chcp 65001 > nul
echo 正在检查并关闭可能冲突的WireGuard服务端...

REM 尝试查找并关闭WireGuard服务端进程
taskkill /f /im wgserver.exe 2>nul
if %errorlevel% equ 0 (
    echo 已关闭WireGuard服务端进程
    timeout /t 2 > nul
) else (
    echo 未发现运行中的WireGuard服务端进程
)

REM 清理可能存在的网络资源
echo 正在清理网络资源...
powershell -Command "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Remove-NetAdapter -Confirm:$false -ErrorAction SilentlyContinue"
timeout /t 2 > nul

REM 启动客户端
echo 正在启动WireGuard客户端...
start /b wgclient.exe -server 127.0.0.1:51820 -listen-port 51821

echo 客户端已启动，请查看客户端窗口获取详细信息
timeout /t 3 > nul
