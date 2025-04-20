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
pekclient.exe -server 120.79.187.148:23456
pause
```

注意：这些批处理文件需要以管理员权限运行。可以右键点击文件，选择“以管理员身份运行”。

## 使用方法

### 编译可执行文件

可以将服务器和客户端编译为可执行文件，方便分发和使用：

```bash
# 编译服务器
# Linux/macOS
cd server
go build -o pekserver main.go

# Windows
cd server
go build -o pekserver.exe main.go

# 编译客户端
# Linux/macOS
cd client
go build -o pekclient main.go

# Windows
cd client
go build -o pekclient.exe main.go
```

### 服务器端

服务器需要以管理员/root 权限运行：

```bash
# Linux/macOS
cd server
sudo go run main.go -port 23456 -enable-reg
# 或者使用编译后的可执行文件
sudo ./pekserver -port 23456 -enable-reg

# Windows (管理员权限)
cd server
go run main.go -port 23456 -enable-reg
# 或者使用编译后的可执行文件
pekserver.exe -port 23456 -enable-reg
```

服务器端参数说明：

- `-port <端口>`: 指定 WireGuard 监听端口，默认为 23456
- `-ip <IP地址>`: 指定 TUN 设备 IP 地址，默认为 10.8.0.1/24
- `-tun <设备名>`: 指定 TUN 设备名称，默认为 wg0
- `-config <文件路径>`: 指定配置文件路径，默认为 wg-server.conf
- `-enable-reg`: 启用客户端自动注册，默认为 true
- `-reg-secret <密钥>`: 指定客户端注册密钥，默认为 vpnsecret
- `-client-pubkey <公钥>`: 指定特定客户端公钥（当禁用自动注册时）
- `-client-timeout <分钟>`: 客户端超时时间，超过此时间未响应的客户端将被自动清理，默认为 10 分钟
- `-auto-cleanup`: 是否自动清理超时的客户端，默认为 true
- `-amnezia`: 启用 AmneziaWG 特殊修改

### 客户端

客户端需要以管理员/root 权限运行：

```bash
# Linux/macOS
cd client
sudo go run main.go -server <服务器地址:端口>
# 或者使用编译后的可执行文件
sudo ./pekclient -server <服务器地址:端口>

# Windows (管理员权限)
cd client
go run main.go -server <服务器地址:端口>
# 或者使用编译后的可执行文件
pekclient.exe -server <服务器地址:端口>
```

客户端参数说明：

- `-server <地址:端口>`: 指定服务器地址和端口，默认为 120.79.187.148:23456
- `-ip <IP地址>`: 指定客户端 IP 地址，默认为 10.9.0.2/24
- `-tun <设备名>`: 指定 TUN 设备名称，默认为 wgc0
- `-listen-port <端口>`: 指定客户端监听端口，默认为 51821
- `-private-key <私钥>`: 指定客户端私钥（可选）
- `-server-pubkey <公钥>`: 指定服务器公钥（可选）
- `-reg-secret <密钥>`: 指定注册密钥，默认为 vpnsecret
- `-client-name <名称>`: 指定客户端名称
- `-config <文件路径>`: 指定配置文件路径（可选）
- `-full-tunnel`: 启用全局代理模式，默认为 true
- `-protect-webrtc`: 启用 WebRTC 泄露防护，防止真实 IP 地址泄露
- `-dns-proxy`: 启用 DNS 代理，防止 DNS 泄露
- `-amnezia`: 启用 AmneziaWG 特殊修改

## 常见问题

### 创建 TUN 设备失败

- 确保以管理员/root 权限运行程序
- Windows 平台确保 wintun.dll 位于程序目录或系统路径中
- 检查是否已安装 WireGuard 驱动

```bash
# Windows
# 将 wintun.dll 复制到程序目录
copy "C:\Program Files\WireGuard\wintun.dll" .
```

### 无法连接到服务器

- 检查服务器是否启动并监听正确的端口
- 检查防火墙是否允许 WireGuard 端口的 UDP 流量
- 使用 `-server-pubkey` 参数手动指定服务器公钥

### 自动注册失败

- 检查服务器是否启用了自动注册功能 (`-enable-reg`)
- 检查注册密钥是否一致 (`-reg-secret`)
- 检查服务器注册服务端口（WireGuard 端口 + 1）是否可达

### 无法路由流量

- 检查 AllowedIPs 设置
- 确保服务器开启了 IP 转发功能
- 检查服务器 NAT 配置是否正确

### 客户端超时清理

- 服务器会自动清理长时间未响应的客户端
- 可以使用 `-client-timeout` 参数设置超时时间，默认为 10 分钟
- 可以使用 `-auto-cleanup=false` 参数禁用自动清理功能

## 完整使用场景

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

## 贡献与反馈

欢迎提交问题报告和功能建议，或直接提交代码贡献。我们将不断完善和优化这个项目，为用户提供更好的 VPN 体验。

## 结语

PekHight VPN 是一个基于 WireGuard 协议的高性能 VPN 解决方案，提供了简单易用的命令行界面和丰富的功能。它适合需要安全、高效网络连接的个人和小型团队使用。通过持续的开发和优化，我们将为用户提供更多功能和更好的体验。
