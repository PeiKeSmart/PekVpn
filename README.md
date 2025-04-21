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

- [x] 支持 WebRTC 泄露防护，避免真实 IP 暴露，并在关闭时自动清理
- [x] 支持 DNS 配置和泄露防护
- [x] 支持自定义 TUN/TAP 设备配置
- [x] 支持动态 MTU 探测和优化
- [x] 支持 SOCKS5 代理服务器，解决 Windows 10 路由问题
- [x] 支持 SOCKS5 代理与 VPN 公钥认证集成，提高安全性

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
- `-enable-socks`: 是否启用 SOCKS5 代理服务器，默认为 true
- `-socks-port <端口>`: 指定 SOCKS5 代理服务器端口，默认为 1080
- `-socks-user <用户名>`: 指定 SOCKS5 代理服务器用户名，留空则不启用认证
- `-socks-pass <密码>`: 指定 SOCKS5 代理服务器密码，留空则不启用认证
- `-enable-stun`: 是否启用 STUN 服务器，默认为 true
- `-stun-port <端口>`: 指定 STUN 服务器端口，默认为 3478
- `-public-ip <IP地址>`: 指定服务器公网 IP，留空则自动探测

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

- `-server <地址:端口>`: 指定服务器地址和端口，默认为 172.16.8.10:23456
- `-ip <IP地址>`: 指定客户端 IP 地址，默认为 10.9.0.2/24
- `-tun <设备名>`: 指定 TUN 设备名称，默认为 wgc0
- `-listen-port <端口>`: 指定客户端监听端口，默认为 51821
- `-private-key <私钥>`: 指定客户端私钥（可选）
- `-server-pubkey <公钥>`: 指定服务器公钥（可选）
- `-reg-secret <密钥>`: 指定注册密钥，默认为 vpnsecret
- `-client-name <名称>`: 指定客户端名称
- `-config <文件路径>`: 指定配置文件路径（可选）
- `-full-tunnel`: 启用全局代理模式，默认为 true
- `-use-tun2socks`: 启用 SOCKS5 代理功能，默认为 true
- `-socks-port <端口>`: 指定 SOCKS5 代理端口，默认为 1080
- `-socks-user <用户名>`: 指定 SOCKS5 代理用户名，留空则不启用认证
- `-socks-pass <密码>`: 指定 SOCKS5 代理密码，留空则不启用认证
- `-protect-webrtc`: 启用 WebRTC 泄露防护，防止真实 IP 地址泄露
- `-webrtc-mode <模式>`: 指定 WebRTC 保护模式，可选值为 block(阻止)或 spoof(模拟)，默认为 block
- `-stun-server <地址>`: 指定 STUN 服务器地址，用于模拟模式，默认使用 VPN 服务器
- `-dns-proxy`: 启用 DNS 代理，防止 DNS 泄露
- `-amnezia`: 启用 AmneziaWG 特殊修改

## 常见问题

### Windows 10/11 没有 Routing and Remote Access 服务

Windows 10 和 Windows 11 家庭版没有内置的 Routing and Remote Access 服务（RRAS），这会导致 VPN 服务器启动失败。解决方案：

1. **使用不依赖 RRAS 的启动脚本**：

   我们提供了一个专为 Windows 家庭版设计的启动脚本 `start_server_windows_home.bat`，它包含以下功能：
   - 启用 IP 转发
   - 配置防火墙规则
   - 启动 VPN 服务器
   - 配置 Internet 连接共享

   使用方法：右键点击脚本，选择“以管理员身份运行”

2. **使用第三方 NAT 工具**：如 ForwardIP 或 WinNAT

3. **在虚拟机中运行 Linux 服务器**：在 VirtualBox 或 VMware 中运行 Linux 版本的服务器

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

### 获取和使用服务器公钥

当需要手动指定服务器公钥时，可以按照以下步骤操作：

1. **获取服务器公钥**：
   - 从服务器启动日志中获取，日志中会显示“服务器公钥: XXX=”

   ```text
   WireGuard服务器已启动
   服务器: 0.0.0.0:23456
   服务器公钥: AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd=
   ```

   - 或者使用命令生成公钥（如果您有服务器的私钥）：

   ```bash
   # Linux/macOS
   wg pubkey < server_private.key

   # Windows (PowerShell)
   Get-Content server_private.key | wg pubkey
   ```

   - 从服务器配置文件中获取（如果有）：

   ```bash
   cat wg-server.conf
   ```

2. **在客户端中使用**：

   ```bash
   # Windows
   pekclient.exe -server <服务器IP>:23456 -server-pubkey AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd=

   # Linux/macOS
   sudo ./pekclient -server <服务器IP>:23456 -server-pubkey AbCdEfGhIjKlMnOpQrStUvWxYz1234567890AbCd=
   ```

3. **验证连接**：
   连接建立后，可以使用以下命令验证是否使用了正确的服务器公钥：

   ```bash
   # Windows
   wg show

   # Linux/macOS
   sudo wg show
   ```

   输出中应该包含服务器的公钥信息。

4. **为什么需要手动指定服务器公钥？**
   - 当服务器禁用自动注册功能时，客户端必须提供服务器公钥
   - 手动指定公钥可以防止中间人攻击，提高安全性
   - 在某些特殊网络环境中，自动注册可能不可用

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

### 场景三：使用 SOCKS5 代理解决 Windows 10 路由问题

```bash
# 服务端启动 SOCKS5 代理服务器
# 使用 Go 直接运行
cd server
sudo go run main.go -enable-socks=true -socks-port=1080

# 或者使用编译后的可执行文件
sudo ./pekserver -enable-socks=true -socks-port=1080
# Windows
pekserver.exe -enable-socks=true -socks-port=1080
```

```bash
# 客户端启用 SOCKS5 代理功能
# 使用 Go 直接运行
cd client
sudo go run main.go -server <服务器IP>:23456 -use-tun2socks=true -socks-port=1080

# 或者使用编译后的可执行文件
sudo ./pekclient -server <服务器IP>:23456 -use-tun2socks=true -socks-port=1080
# Windows
pekclient.exe -server <服务器IP>:23456 -use-tun2socks=true -socks-port=1080
```

注意：客户端会自动使用 VPN 公钥生成 SOCKS5 认证信息，无需手动指定用户名和密码。如果需要手动指定，可以使用以下参数：

```bash
# 服务端指定用户名和密码
pekserver.exe -enable-socks=true -socks-port=1080 -socks-user=vpnuser -socks-pass=vpnpass

# 客户端指定用户名和密码
pekclient.exe -server <服务器IP>:23456 -use-tun2socks=true -socks-port=1080 -socks-user=vpnuser -socks-pass=vpnpass
```

SOCKS5 代理功能特别适用于 Windows 10 系统，可以解决以下问题：

1. **路由转发问题**：Windows 10 家庭版和专业版缺少 Routing and Remote Access 服务，导致 VPN 流量转发失败
2. **NAT 配置问题**：Windows 10 的 NetNat 功能不稳定，导致转发失败
3. **兼容性问题**：某些应用程序可能不兼容全局 VPN 模式

**注意：** 客户端会自动测试SOCKS5代理连接，测试使用百度网站而非Google，以确保在中国大陆可以正常测试。如果测试失败，请检查服务器端口配置和防火墙设置。

使用方法：

1. 启动服务端和客户端，确保启用 SOCKS5 代理功能
2. 在应用程序中配置 SOCKS5 代理：
   - 代理地址：服务器 IP 地址
   - 代理端口：1080（或自定义端口）
   - 代理类型：SOCKS5
   - 用户名/密码：如果启用了认证，输入相应的用户名和密码

### 场景四：启用 WebRTC 泄露防护

#### 阻止模式（默认）

```bash
# 使用 Go 直接运行
cd client
sudo go run main.go -server <服务器IP>:23456 -protect-webrtc=true -webrtc-mode=block

# 或者使用编译后的可执行文件
sudo ./pekclient -server <服务器IP>:23456 -protect-webrtc=true -webrtc-mode=block
# Windows
pekclient.exe -server <服务器IP>:23456 -protect-webrtc=true -webrtc-mode=block
```

#### 模拟模式（显示VPN服务器IP）

```bash
# 服务端需要启用STUN服务器
pekserver.exe -enable-stun=true -stun-port=3478 -public-ip=<服务器公网IP>

# 客户端使用模拟模式
pekclient.exe -server <服务器IP>:23456 -protect-webrtc=true -webrtc-mode=spoof
```

注意：模拟模式需要服务端启用STUN服务器，否则将自动回退到阻止模式。模拟模式会使 WebRTC 检测到的IP地址与VPN服务器的IP地址一致，而不是完全阻止WebRTC。

WebRTC 泄露防护功能包括：

1. **阻止模式**：完全阻止 WebRTC 获取公网IP地址
   - 在 hosts 文件中将常见 STUN 服务器指向 127.0.0.1，阻止连接

2. **模拟模式**：模拟 WebRTC 获取到的IP地址为 VPN 服务器的IP地址
   - 在 hosts 文件中将常见 STUN 服务器指向 VPN 服务器IP
   - 服务端运行 STUN 服务器，始终返回服务器的公网IP

3. **自动清理**：在 VPN 关闭时自动清理 hosts 文件中的 WebRTC 防护设置，确保关闭 VPN 后网络行为恢复正常

**注意：** 如果关闭 VPN 后 WebRTC 仍然无法显示公共 IP 地址，请尝试重启浏览器或者手动检查 hosts 文件。

**重要说明：** SOCKS 代理连接失败不会影响 VPN 的基本功能。如果 SOCKS 代理连接失败，系统会自动将其标记为非活动状态，但 VPN 仍然可以正常工作。如果您需要使用 SOCKS 代理，请确保服务器端已经正确配置并开启了 SOCKS 服务。

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
- [x] SOCKS5 代理服务器支持
- [x] Windows 10 路由问题解决方案
- [x] SOCKS5 代理与 VPN 公钥认证集成
- [x] WebRTC 模拟模式，显示 VPN 服务器 IP

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
