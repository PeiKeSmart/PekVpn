# PekHightVPN

一个使用Golang实现的VPN服务端和客户端，支持WireGuard协议和AmneziaWG。

## 功能特点

- 基于TUN设备的VPN实现
- 支持WireGuard协议
- 支持AmneziaWG修改版
- 安全的加密通信
- 支持Windows、Linux和macOS

## 依赖项

- Go 1.21或更高版本
- [github.com/songgao/water](https://github.com/songgao/water) - TUN/TAP设备库
- [golang.zx2c4.com/wireguard](https://git.zx2c4.com/wireguard-go) - WireGuard实现
- [golang.zx2c4.com/wireguard/wgctrl](https://git.zx2c4.com/wireguard-go) - WireGuard控制库
- 管理员/root权限（用于创建和配置TUN设备）

## 安装

```bash
# 克隆仓库
git clone https://github.com/yourusername/pekhightvpn.git
cd pekhightvpn

# 安装依赖
go mod download
```

## 编译

```bash
# 编译服务端
go build -o wgserver ./server

# 编译客户端
go build -o wgclient ./client
```

## 使用方法

### 服务端

```bash
# 使用默认配置启动服务端
sudo ./wgserver

# 自定义配置
sudo ./wgserver -port 51820 -tun wg0 -ip 10.8.0.1/24 -config wg-server.conf

# 使用AmneziaWG修改
sudo ./wgserver -amnezia
```

参数说明：

- `-port`: WireGuard监听端口，默认为`51820`
- `-tun`: TUN设备名称，默认为`wg0`
- `-ip`: TUN设备IP地址，默认为`10.8.0.1/24`
- `-config`: WireGuard配置文件路径，默认为`wg-server.conf`
- `-amnezia`: 是否使用AmneziaWG修改，默认为`false`

### 客户端

```bash
# 生成新的客户端配置
sudo ./wgclient -server 服务器IP:51820 -ip 10.8.0.2/24

# 使用现有配置文件
sudo ./wgclient -config wg-client.conf

# 使用密钥
sudo ./wgclient -server 服务器IP:51820 -ip 10.8.0.2/24 -server-pubkey 服务器公钥 -private-key 客户端私钥

# 使用AmneziaWG修改
sudo ./wgclient -amnezia -config wg-client.conf
```

参数说明：

- `-server`: 服务器地址，格式为`IP:端口`
- `-tun`: TUN设备名称，默认为`wg0`
- `-ip`: 客户端IP地址，默认为`10.8.0.2/24`
- `-config`: WireGuard配置文件路径
- `-server-pubkey`: 服务器公钥
- `-private-key`: 客户端私钥
- `-amnezia`: 是否使用AmneziaWG修改，默认为`false`

## Windows上的使用方法

在Windows上使用本VPN需要Wintun驱动，有以下两种方式获取驱动：

1. **下载Wintun驱动**：
   - 从[Wintun官网](https://www.wintun.net/)下载驱动
   - 解压后将相应架构的`wintun.dll`文件放在程序目录下

2. **安装WireGuard客户端**：
   - 从[WireGuard官网](https://www.wireguard.com/install/)下载并安装WireGuard客户端
   - 安装后会自动安装Wintun驱动

安装驱动后，使用非常简单：

1. **以管理员身份运行**：
   - 右键点击命令提示符或PowerShell图标，选择"以管理员身份运行"

2. **运行服务端或客户端**：

   ```powershell
   .\wgserver.exe
   ```

   或

   ```powershell
   .\wgclient.exe -server 服务器IP:51820
   ```

我们的实现使用纯 Go 语言的 WireGuard 实现（wireguard-go），它在用户空间运行，不需要安装额外的驱动程序。这使得安装和使用过程非常简单。

## 注意事项

1. 需要管理员/root权限才能创建和配置TUN设备
2. 我们使用纯Go语言的WireGuard实现，不需要安装额外的驱动程序
3. 生成的客户端配置文件包含敏感信息，请妥善保管
4. 此VPN实现仅用于学习和测试，不建议用于生产环境

## 关于AmneziaWG

AmneziaWG是WireGuard的一个修改版本，具有一些特定的变化。本实现包含了对AmneziaWG的基本支持，可以通过`-amnezia`参数启用。

## 许可证

MIT
