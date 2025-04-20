# PekHight VPN

基于 WireGuard 协议的高性能 VPN 解决方案，支持客户端自动注册和动态配置。

## 功能特点

- [x] 基于 WireGuard 协议的安全连接
- [x] 支持客户端自动注册
- [x] 支持全局代理和分流模式
- [x] 跨平台支持 (Windows, Linux, macOS)
- [x] 支持自定义 TUN/TAP 设备配置
- [x] 支持 IP 转发和 NAT
- [x] 服务器端支持多客户端管理
- [x] 支持密钥自动生成和管理

## 系统要求

- Go 1.18 或更高版本
- WireGuard 内核模块（Linux）或 WireGuard 应用程序（Windows, macOS）
- Windows 平台需要 wintun.dll 驱动
- 管理员/root 权限（用于创建 TUN/TAP 设备）

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

Windows 平台需要 wintun.dll 驱动，可以从以下位置下载：

1. WireGuard 官方网站: https://www.wireguard.com/install/
2. 下载安装 WireGuard 后，将 wintun.dll 复制到 PekHight VPN 目录下

## 使用方法

### 服务器端

服务器需要以管理员/root 权限运行：

```bash
# Linux/macOS
cd server
sudo go run main.go -port 23456 -enable-reg

# Windows (管理员权限)
cd server
go run main.go -port 23456 -enable-reg
```

服务器端参数说明：

- `-port <端口>`: 指定 WireGuard 监听端口，默认为 23456
- `-ip <IP地址>`: 指定 TUN 设备 IP 地址，默认为 10.8.0.1/24
- `-tun <设备名>`: 指定 TUN 设备名称，默认为 wg0
- `-config <文件路径>`: 指定配置文件路径，默认为 wg-server.conf
- `-enable-reg`: 启用客户端自动注册，默认为 true
- `-reg-secret <密钥>`: 指定客户端注册密钥，默认为 vpnsecret
- `-client-pubkey <公钥>`: 指定特定客户端公钥（当禁用自动注册时）
- `-amnezia`: 启用 AmneziaWG 特殊修改

### 客户端

客户端需要以管理员/root 权限运行：

```bash
# Linux/macOS
cd client
sudo go run main.go -server <服务器地址:端口>

# Windows (管理员权限)
cd client
go run main.go -server <服务器地址:端口>
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

## 完整使用场景

### 场景一：快速启动服务器和客户端

1. 启动服务器：

```bash
cd server
sudo go run main.go
```

2. 启动客户端：

```bash
cd client
sudo go run main.go -server <服务器IP>:23456
```

### 场景二：使用指定密钥

1. 启动服务器：

```bash
cd server
sudo go run main.go -enable-reg=false -client-pubkey <客户端公钥>
```

2. 启动客户端：

```bash
cd client
sudo go run main.go -server <服务器IP>:23456 -private-key <客户端私钥> -server-pubkey <服务器公钥>
```

## 任务清单

- [x] 服务器端基本功能实现
- [x] 客户端基本功能实现
- [x] 客户端自动注册机制
- [x] 支持全局代理和分流模式
- [x] 跨平台支持优化
- [ ] Web 管理界面
- [ ] 客户端状态监控
- [ ] 连接统计和日志分析
- [ ] 用户认证管理
- [ ] 带宽控制和流量管理

## 开发计划

- [ ] 支持多个 VPN 隧道
- [ ] 动态 IP 分配和回收机制优化
- [ ] 服务端高可用方案
- [ ] 支持 DNS 配置和泄漏防护
- [ ] 增加移动端客户端
- [ ] 支持 WebRTC 穿透
