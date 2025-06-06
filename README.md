# PekHight VPN

基于 WireGuard 协议的高性能 VPN 解决方案，支持客户端自动注册、动态配置和全局代理模式。采用现代化的架构设计，提供高效、安全的网络连接体验。

## 功能特点

### 核心功能

- [x] 基于 WireGuard 协议的高性能安全连接
- [x] 支持全局代理和分流模式，灵活控制网络流量
- [x] 跨平台支持 (Windows, Linux, macOS)，一套代码多平台运行
- [x] 支持 IP 转发和 NAT，实现完整的网络访问

### 客户端管理

- [x] 支持客户端自动注册和动态配置
- [x] 服务器端支持多客户端管理
- [x] 客户端状态监控和自动清理功能
- [x] 支持密钥自动生成和管理

### 安全和隐私

- [x] 支持 WebRTC 泄露防护，避免真实 IP 暴露
- [x] 支持 DNS 配置和泄露防护
- [x] 支持自定义 TUN/TAP 设备配置
- [x] 支持动态 MTU 探测和优化
- [x] 支持 IPv6 禁用功能，防止 IPv6 地址泄露
- [x] 实现心跳机制，确保连接状态准确监控
- [x] 优化网络切换，减少连接和断开时的网络波动
- [x] 修复Windows NCSI网络连接状态指示器，确保VPN连接后系统托盘显示正确的网络状态

## 系统要求

### 软件要求

- Go 1.18 或更高版本
- WireGuard 内核模块（Linux）或 WireGuard 应用程序（Windows, macOS）

### 权限要求

- 管理员/root 权限（用于创建 TUN/TAP 设备和配置网络）

### 平台特定要求

- **Windows**: 需要 wintun.dll 驱动
- **Linux**: 需要开启 IP 转发功能
- **macOS**: 需要安装 WireGuard 应用程序

## 安装和配置

### 安装 Go 环境

请访问 [Go 官方网站](https://golang.org/dl/) 下载并安装 Go 环境。

### 获取源代码

```bash
git clone https://github.com/pekhightvpn/pekhightvpn.git
cd pekhightvpn
```

### 安装依赖

```bash
go mod download
```

### Windows 平台特殊要求

Windows 平台需要 wintun.dll 驱动，可以通过以下方式获取：

1. 从 [WireGuard 官方网站](https://www.wireguard.com/install/) 下载并安装 WireGuard
2. 安装完成后，将 `C:\Program Files\WireGuard\wintun.dll` 复制到 PekHight VPN 目录下

### Windows 下双击运行可执行文件

在 Windows 下，可以创建批处理文件（.bat）来简化启动过程：

#### 服务器启动文件 (start_server.bat)

```batch
@echo off
echo 正在启动 PekHight VPN 服务器...
pekserver.exe -port 23456 -enable-reg
pause
```

#### 客户端启动文件 (start_client.bat)

```batch
@echo off
echo 正在启动 PekHight VPN 客户端...
pekclient.exe -server 172.16.8.10:23456
pause
```

注意：这些批处理文件需要以管理员权限运行。可以右键点击文件，选择“以管理员身份运行”。

## 使用方法

### 获取预编译版本

如果您不想自己编译，可以直接使用项目中提供的预编译版本：

- `pekserver.exe` - Windows 服务器端可执行文件
- `pekclient.exe` - Windows 客户端可执行文件
- `pekclient.zip` - 客户端打包版本，包含所有必要文件

### 编译可执行文件

#### 基本编译

```bash
# 编译服务器端
go build -o pekserver ./server

# 编译客户端
go build -o pekclient ./client

# Windows 平台编译（添加 .exe 后缀）
go build -o pekserver.exe ./server
go build -o pekclient.exe ./client
```

#### 跨平台编译

```bash
# 为 Windows 64位 编译
GOOS=windows GOARCH=amd64 go build -o pekserver.exe ./server
GOOS=windows GOARCH=amd64 go build -o pekclient.exe ./client

# 为 Linux 64位 编译
GOOS=linux GOARCH=amd64 go build -o pekserver ./server
GOOS=linux GOARCH=amd64 go build -o pekclient ./client

# 为 macOS 64位 编译
GOOS=darwin GOARCH=amd64 go build -o pekserver ./server
GOOS=darwin GOARCH=amd64 go build -o pekclient ./client

# 为 ARM64 架构编译（适用于 Apple M1/M2 Mac 和 ARM Linux）
GOOS=darwin GOARCH=arm64 go build -o pekserver ./server
GOOS=linux GOARCH=arm64 go build -o pekserver ./server
```

#### 优化编译（减小文件大小）

```bash
# 使用编译优化，减小可执行文件大小
go build -ldflags="-s -w" -o pekserver ./server
go build -ldflags="-s -w" -o pekclient ./client

# Windows 平台隐藏控制台窗口（仅适用于有GUI的应用）
go build -ldflags="-s -w -H=windowsgui" -o pekclient.exe ./client
```

#### 批量编译脚本

创建 `build.sh`（Linux/macOS）或 `build.bat`（Windows）来批量编译：

**build.sh**：
```bash
#!/bin/bash
echo "开始编译 PekHight VPN..."

# 创建输出目录
mkdir -p builds/{windows,linux,darwin}

# 编译 Windows 版本
echo "编译 Windows 版本..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o builds/windows/pekserver.exe ./server
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o builds/windows/pekclient.exe ./client

# 编译 Linux 版本
echo "编译 Linux 版本..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o builds/linux/pekserver ./server
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o builds/linux/pekclient ./client

# 编译 macOS 版本
echo "编译 macOS 版本..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o builds/darwin/pekserver ./server
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o builds/darwin/pekclient ./client

echo "编译完成！文件位于 builds/ 目录"
```

**build.bat**：
```batch
@echo off
echo 开始编译 PekHight VPN...

:: 创建输出目录
if not exist builds\windows mkdir builds\windows
if not exist builds\linux mkdir builds\linux
if not exist builds\darwin mkdir builds\darwin

:: 编译 Windows 版本
echo 编译 Windows 版本...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o builds\windows\pekserver.exe .\server
go build -ldflags="-s -w" -o builds\windows\pekclient.exe .\client

:: 编译 Linux 版本
echo 编译 Linux 版本...
set GOOS=linux
set GOARCH=amd64
go build -ldflags="-s -w" -o builds\linux\pekserver .\server
go build -ldflags="-s -w" -o builds\linux\pekclient .\client

:: 编译 macOS 版本
echo 编译 macOS 版本...
set GOOS=darwin
set GOARCH=amd64
go build -ldflags="-s -w" -o builds\darwin\pekserver .\server
go build -ldflags="-s -w" -o builds\darwin\pekclient .\client

echo 编译完成！文件位于 builds\ 目录
pause
```

### 打包分发

#### Windows 打包

```bash
# 创建 Windows 客户端完整包
mkdir pekclient-windows
cp pekclient.exe pekclient-windows/
cp wintun.dll pekclient-windows/
cp run_pekclient.bat pekclient-windows/

# 创建启动脚本
echo '@echo off
echo 正在启动 PekHight VPN 客户端...
echo 请确保以管理员权限运行此脚本
pekclient.exe -server YOUR_SERVER_IP:23456
pause' > pekclient-windows/start_client.bat

# 压缩打包
7z a pekclient-windows.zip pekclient-windows/
```

#### Linux 打包

```bash
# 创建 Linux 客户端包
mkdir pekclient-linux
cp pekclient pekclient-linux/
chmod +x pekclient-linux/pekclient

# 创建启动脚本
echo '#!/bin/bash
echo "正在启动 PekHight VPN 客户端..."
echo "请确保以 root 权限运行此脚本"
if [ "$EUID" -ne 0 ]; then
    echo "请使用 sudo 运行此脚本"
    exit 1
fi
./pekclient -server YOUR_SERVER_IP:23456' > pekclient-linux/start_client.sh
chmod +x pekclient-linux/start_client.sh

# 创建安装脚本
echo '#!/bin/bash
echo "安装 PekHight VPN 客户端..."
sudo cp pekclient /usr/local/bin/
echo "安装完成！使用 sudo pekclient 启动"' > pekclient-linux/install.sh
chmod +x pekclient-linux/install.sh

# 压缩打包
tar -czf pekclient-linux.tar.gz pekclient-linux/
```

#### Docker 打包

创建 `Dockerfile.server`：
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o pekserver ./server

FROM alpine:latest
RUN apk --no-cache add ca-certificates iptables
WORKDIR /root/

COPY --from=builder /app/pekserver .
EXPOSE 23456/udp 23457/udp

CMD ["./pekserver"]
```

创建 `Dockerfile.client`：
```dockerfile
FROM golang:1.21-alpine AS builder

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN go build -ldflags="-s -w" -o pekclient ./client

FROM alpine:latest
RUN apk --no-cache add ca-certificates iptables
WORKDIR /root/

COPY --from=builder /app/pekclient .

CMD ["./pekclient"]
```

构建 Docker 镜像：
```bash
# 构建服务器镜像
docker build -f Dockerfile.server -t pekhight-vpn-server .

# 构建客户端镜像
docker build -f Dockerfile.client -t pekhight-vpn-client .

# 运行服务器容器
docker run -d --name vpn-server --cap-add=NET_ADMIN --device /dev/net/tun -p 23456:23456/udp -p 23457:23457/udp pekhight-vpn-server

# 运行客户端容器
docker run -it --rm --cap-add=NET_ADMIN --device /dev/net/tun pekhight-vpn-client -server SERVER_IP:23456
```

### 依赖说明

#### Go 模块依赖

项目主要依赖以下 Go 模块：
- `golang.zx2c4.com/wireguard/wgctrl` - WireGuard 控制库
- `github.com/songgao/water` - TUN/TAP 接口库
- `golang.org/x/sys` - 系统调用库

这些依赖会在编译时自动下载，但您也可以手动安装：
```bash
go mod tidy
go mod download
```

#### 系统依赖

- **Windows**: 需要 `wintun.dll` 驱动文件
- **Linux**: 需要 `iptables` 和 `iproute2` 工具
- **macOS**: 需要安装 Xcode 命令行工具

### 安装和部署

#### 系统服务安装（Linux）

创建 systemd 服务文件 `/etc/systemd/system/pekvpn-server.service`：
```ini
[Unit]
Description=PekHight VPN Server
After=network.target

[Service]
Type=simple
User=root
ExecStart=/usr/local/bin/pekserver -port 23456 -enable-reg
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

启用服务：
```bash
sudo systemctl daemon-reload
sudo systemctl enable pekvpn-server
sudo systemctl start pekvpn-server
```

#### Windows 服务安装

使用 NSSM (Non-Sucking Service Manager) 将程序安装为 Windows 服务：
```cmd
# 下载并安装 NSSM
nssm install PekVPNServer "C:\path\to\pekserver.exe"
nssm set PekVPNServer Parameters "-port 23456 -enable-reg"
nssm start PekVPNServer
```

## 使用示例

### 场景一：快速启动服务器和客户端

#### 启动服务器

```bash
# 使用 Go 直接运行
cd server
sudo go run main.go

# 或者使用编译后的可执行文件
sudo ./pekserver
# Windows
pekserver.exe
```

#### 启动客户端

```bash
# 使用 Go 直接运行
cd client
sudo go run main.go -server <服务器IP>:23456

# 或者使用编译后的可执行文件
sudo ./pekclient -server <服务器IP>:23456
# Windows
pekclient.exe -server <服务器IP>:23456
```

### 场景二：使用指定密钥

#### 启动服务器（指定密钥）

```bash
# 使用 Go 直接运行
cd server
sudo go run main.go -enable-reg=false -client-pubkey <客户端公钥>

# 或者使用编译后的可执行文件
sudo ./pekserver -enable-reg=false -client-pubkey <客户端公钥>
# Windows
pekserver.exe -enable-reg=false -client-pubkey <客户端公钥>
```

#### 启动客户端（指定密钥）

```bash
# 使用 Go 直接运行
cd client
sudo go run main.go -server <服务器IP>:23456 -private-key <客户端私钥> -server-pubkey <服务器公钥>

# 或者使用编译后的可执行文件
sudo ./pekclient -server <服务器IP>:23456 -private-key <客户端私钥> -server-pubkey <服务器公钥>
# Windows
pekclient.exe -server <服务器IP>:23456 -private-key <客户端私钥> -server-pubkey <服务器公钥>
```

## 高级使用场景

### 场景三：启用 WebRTC 泄露防护

```bash
# 使用 Go 直接运行
cd client
sudo go run main.go -server <服务器IP>:23456 -protect-webrtc=true

# 或者使用编译后的可执行文件
sudo ./pekclient -server <服务器IP>:23456 -protect-webrtc=true
# Windows
pekclient.exe -server <服务器IP>:23456 -protect-webrtc=true
```

WebRTC 泄露防护功能包括：

1. **防火墙规则防护**：自动添加防火墙规则，阻止 STUN/TURN 请求
2. **浏览器配置建议**：提供浏览器配置指南，帮助用户完全禁用 WebRTC
3. **STUN 服务器阻止**：在 hosts 文件中添加常见 STUN 服务器条目，阻止连接

### 场景四：自定义超时清理时间

```bash
# 使用 Go 直接运行
cd server
sudo go run main.go -client-timeout=30 -auto-cleanup=true

# 或者使用编译后的可执行文件
sudo ./pekserver -client-timeout=30 -auto-cleanup=true
# Windows
pekserver.exe -client-timeout=30 -auto-cleanup=true
```

## 最新功能介绍

### IPv6 禁用功能

客户端现在会在连接 VPN 后自动禁用 IPv6，防止 IPv6 地址泄露。这个功能可以确保：

1. 连接 VPN 后，网站和服务无法获取您的 IPv6 地址
2. 只能看到 IPv4 地址，而 IPv4 地址会显示为服务端的 IP
3. 断开 VPN 连接后，系统会自动重新启用 IPv6 功能

### 心跳机制

新增的心跳机制可以解决以下问题：

1. WireGuard 握手时间更新不可靠的问题
2. 客户端活跃状态检测不准确的问题
3. 客户端被错误清理的问题

心跳机制每 30 秒发送一次心跳包，确保服务器能够准确跟踪客户端的活跃状态。

### 网络切换优化

最新版本对网络切换过程进行了优化，减少了连接和断开时的网络波动：

1. 连接前优化网络设置，准备网络环境
2. 设置主网络接口为高优先级，确保非 VPN 流量优先走主网络
3. 断开前降低 VPN 接口优先级，等待流量迁移到主网络
4. 清理资源后恢复原始网络设置

### 端口共享功能

为了减少需要开放的端口数量，我们实现了端口共享功能：

1. 注册服务、心跳服务和断开连接通知服务共用同一个端口
2. 通过不同的命令（REGISTER_CLIENT、HEARTBEAT、DISCONNECT）来区分不同的操作
3. 现在只需要开放 2 个端口：WireGuard 端口和注册/心跳/断开连接通知端口

### Windows NCSI网络连接状态指示器修复

最新版本实现了Windows NCSI（网络连接状态指示器）自动修复功能，解决了VPN连接后系统托盘错误显示"Internet无法上网"的问题：

1. **自动修复时机**：
   - VPN初始连接成功后自动执行
   - VPN重新连接成功后自动执行
   - 网络测试过程中自动执行

2. **修复方法**：
   - 确保EnableActiveProbing注册表项设置为1，启用NCSI主动探测
   - 主动访问Microsoft NCSI测试网站，确保可以访问
   - 重启网络位置感知(NLA)服务，触发NCSI重新检测
   - 如果仍然异常，尝试刷新网络设置（ipconfig /renew和ipconfig /flushdns）

3. **用户体验改进**：
   - 不再出现"Internet无法上网"的错误提示
   - 系统托盘网络图标显示正确的连接状态
   - 无需用户手动修改系统设置或重启网络服务

## 性能优化建议

1. **MTU 优化**：如果遇到网络性能问题，可以尝试手动调整 MTU 值，例如 `-mtu=1380`

2. **网络路由优化**：在复杂网络环境中，可能需要手动调整路由表

3. **DNS 配置**：使用 `-dns-proxy=true` 可以启用 DNS 代理，避免 DNS 泄露

## 开发路线图

### 已完成功能

- [x] 服务器端基本功能实现
- [x] 客户端基本功能实现
- [x] 客户端自动注册机制
- [x] 支持全局代理和分流模式
- [x] 跨平台支持优化
- [x] 客户端状态监控和自动清理
- [x] WebRTC 泄露防护
- [x] DNS 配置和泄露防护
- [x] IPv6 禁用功能，防止地址泄露
- [x] 心跳机制，确保连接状态准确监控
- [x] 网络切换优化，减少连接和断开时的波动
- [x] 端口共享功能，减少需要开放的端口数量
- [x] Windows NCSI网络连接状态指示器修复，解决"Internet无法上网"错误提示问题

### 计划中功能

- [ ] Web 管理界面
- [ ] 连接统计和日志分析
- [ ] 用户认证管理
- [ ] 带宽控制和流量管理
- [ ] 支持多个 VPN 隧道
- [ ] 动态 IP 分配和回收机制优化
- [ ] 服务端高可用方案
- [ ] 增加移动端客户端
- [ ] 支持 WebRTC 穿透
- [ ] 流量混淆与伪装
- [ ] 定期密钥轮换机制
- [ ] DNS over HTTPS/TLS 支持

## 贡献与反馈

欢迎提交问题报告和功能建议，或直接提交代码贡献。我们将不断完善和优化这个项目，为用户提供更好的 VPN 体验。

## 结语

PekHight VPN 是一个基于 WireGuard 协议的高性能 VPN 解决方案，提供了简单易用的命令行界面和丰富的功能。它适合需要安全、高效网络连接的个人和小型团队使用。

最新版本增加了多项重要功能，包括 IPv6 禁用功能、心跳机制、网络切换优化和端口共享功能。这些功能显著提高了隐私保护和用户体验，使 PekHight VPN 成为一个更加完善和安全的 VPN 解决方案。

通过持续的开发和优化，我们将为用户提供更多功能和更好的体验。我们的目标是打造一个兼顾性能、安全性和易用性的现代化 VPN 解决方案。
