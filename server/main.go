package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/pekhightvpn/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

var (
	listenPort    = flag.Int("port", 23456, "WireGuard监听端口")
	tunName       = flag.String("tun", "wg0", "TUN设备名称")
	tunIP         = flag.String("ip", "10.8.0.1/24", "TUN设备IP地址")
	configFile    = flag.String("config", "wg-server.conf", "WireGuard配置文件路径")
	useAmnezia    = flag.Bool("amnezia", false, "是否使用AmneziaWG修改")
	clientPubKey  = flag.String("client-pubkey", "", "客户端公钥")
	regEnabled    = flag.Bool("enable-reg", true, "是否启用客户端自动注册")
	regSecret     = flag.String("reg-secret", "vpnsecret", "客户端注册密钥")
	clientTimeout = flag.Int("client-timeout", 10, "客户端超时时间(分钟)，超过此时间未响应的客户端将被自动清理")
	autoCleanup   = flag.Bool("auto-cleanup", true, "是否自动清理超时的客户端")
	enableSocks   = flag.Bool("enable-socks", true, "是否启用SOCKS5代理服务器")
	socksPort     = flag.Int("socks-port", 1080, "SOCKS5代理服务器端口")
	socksUser     = flag.String("socks-user", "", "SOCKS5代理服务器用户名，留空则不启用认证")
	socksPass     = flag.String("socks-pass", "", "SOCKS5代理服务器密码，留空则不启用认证")
	enableStun    = flag.Bool("enable-stun", true, "是否启用STUN服务器")
	stunPort      = flag.Int("stun-port", 3478, "STUN服务器端口")
	publicIP      = flag.String("public-ip", "", "服务器公网IP，留空则自动探测")

	// 客户端管理
	clients     = make(map[wgtypes.Key]*wireguard.PeerInfo)
	clientsLock sync.RWMutex

	// IP地址分配
	nextIP = net.ParseIP("10.8.0.2").To4()
	ipLock sync.Mutex
)

func main() {
	flag.Parse()

	// 设置日志输出格式
	log.SetFlags(log.LstdFlags | log.Lmicroseconds)

	// 如果是Windows系统，设置控制台编码为UTF-8
	if runtime.GOOS == "windows" {
		// 设置控制台代码页为UTF-8
		cmd := exec.Command("chcp", "65001")
		cmd.Run()

		// 检查并清理孤立的适配器
		cleanupOrphanedAdapters()
	}

	log.Printf("启动WireGuard VPN服务器...")

	// 解析IP地址和子网掩码
	ip, ipNet, err := net.ParseCIDR(*tunIP)
	if err != nil {
		log.Fatalf("无效的IP地址: %s, %v", *tunIP, err)
	}

	// 尝试读取现有配置
	var config *wireguard.Config

	if _, fileErr := os.Stat(*configFile); fileErr == nil {
		// 配置文件存在，尝试读取私钥
		privateKey, readErr := readExistingConfig(*configFile)
		if readErr == nil {
			log.Printf("使用现有配置文件中的密钥对")
			// 使用现有私钥创建配置
			config, err = wireguard.NewServerConfigWithKey(*listenPort, privateKey)
			if err != nil {
				log.Fatalf("使用现有密钥创建配置失败: %v", err)
			}
		} else {
			log.Printf("读取现有配置文件失败: %v，将创建新的密钥对", readErr)
			// 创建新配置
			config, err = wireguard.NewServerConfig(*listenPort)
			if err != nil {
				log.Fatalf("创建服务端配置失败: %v", err)
			}
		}
	} else {
		// 配置文件不存在，创建新配置
		log.Printf("配置文件不存在，创建新的密钥对")
		config, err = wireguard.NewServerConfig(*listenPort)
		if err != nil {
			log.Fatalf("创建服务端配置失败: %v", err)
		}
	}

	// 如果使用AmneziaWG，应用特定修改
	if *useAmnezia {
		wireguard.AmneziaWGModify(config)
		log.Printf("已应用AmneziaWG特定修改")
	}

	// 创建WireGuard设备
	wgDevice, err := wireguard.NewWireGuardDevice(config, true)
	if err != nil {
		log.Fatalf("创建WireGuard设备失败: %v", err)
	}
	defer wgDevice.Close()

	// 配置TUN设备IP地址
	err = configureTunIP(wgDevice.TunName, ip, ipNet)
	if err != nil {
		log.Fatalf("配置TUN设备IP地址失败: %v", err)
	}

	log.Printf("WireGuard服务器已启动")
	log.Printf("监听端口: %d", *listenPort)
	log.Printf("服务器公钥: %s", config.PublicKey.String())
	log.Printf("TUN设备: %s, IP: %s", wgDevice.TunName, *tunIP)

	// 保存配置文件
	saveConfig(config)

	// 启用IP转发
	err = enableIPForwarding()
	if err != nil {
		log.Printf("启用IP转发失败: %v", err)
	} else {
		log.Printf("IP转发已启用")
	}

	// 配置NAT
	err = configureNAT(*tunIP)
	if err != nil {
		log.Printf("配置NAT失败: %v", err)
	} else {
		log.Printf("NAT已配置")
	}

	// 移除默认客户端添加代码，替换为有条件添加
	// 只有在未启用自动注册功能时，才考虑添加指定客户端
	if !*regEnabled {
		if *clientPubKey != "" {
			log.Printf("添加命令行指定的客户端公钥")
			addSpecificClient(config, wgDevice, *clientPubKey)
		} else {
			log.Printf("未启用自动注册功能，也未指定客户端公钥，WireGuard服务器处于等待模式")
		}
	}

	// 如果启用了客户端自动注册，启动注册服务
	if *regEnabled {
		go startClientRegistrationService(*listenPort+1, config, wgDevice)
		log.Printf("客户端自动注册服务已启动，监听端口: %d", *listenPort+1)
	}

	// 启动客户端连接监控
	go monitorClientConnections(wgDevice)

	// 启动SOCKS5代理服务器
	if *enableSocks {
		// 使用注册密钥作为默认密码，如果没有指定密码
		socksUsername := *socksUser
		socksPassword := *socksPass

		// 如果没有指定密码但指定了用户名，使用注册密钥作为密码
		if socksPassword == "" && socksUsername != "" {
			socksPassword = *regSecret
			log.Printf("未指定 SOCKS5 密码，使用注册密钥作为密码")
		}

		// 获取客户端列表的副本，避免并发问题
		clientsLock.RLock()
		clientsCopy := make(map[wgtypes.Key]*wireguard.PeerInfo)
		for k, v := range clients {
			clientsCopy[k] = v
		}
		clientsLock.RUnlock()

		// 启动SOCKS5代理服务器，使用VPN公钥认证
		socksServer, err := StartSocksServer(*tunIP, *socksPort, socksUsername, socksPassword, *regSecret, clientsCopy)
		if err != nil {
			log.Printf("启动SOCKS5代理服务器失败: %v", err)
		} else {
			log.Printf("SOCKS5代理服务器已启动在 %s", socksServer.GetBindAddr())
			defer socksServer.Stop()
		}
	}

	// 启动STUN服务器
	if *enableStun {
		// 获取服务器公网IP
		serverIP, err := GetServerIP(*publicIP)
		if err != nil {
			log.Printf("获取服务器公网IP失败: %v", err)
			log.Printf("将使用TUN设备IP作为STUN服务器的公网IP")
			// 使用TUN设备IP作为备选
			ip := strings.Split(*tunIP, "/")[0]
			serverIP = ip
		}

		// 启动STUN服务器
		stunServer, err := StartSTUNServer(serverIP, *stunPort)
		if err != nil {
			log.Printf("启动STUN服务器失败: %v", err)
		} else {
			log.Printf("STUN服务器已启动，监听端口: %d, 公网IP: %s", *stunPort, serverIP)
			defer stunServer.Stop()
		}
	}

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	log.Printf("正在关闭WireGuard服务器...")

	// 清理资源
	wgDevice.Close()

	// 清理NAT和路由
	cleanupNAT(*tunIP)
}

// readExistingConfig 尝试从配置文件中读取现有的私钥和公钥
func readExistingConfig(configFilePath string) (wgtypes.Key, error) {
	// 检查配置文件是否存在
	_, err := os.Stat(configFilePath)
	if os.IsNotExist(err) {
		return wgtypes.Key{}, fmt.Errorf("配置文件不存在")
	}

	// 读取配置文件内容
	content, err := os.ReadFile(configFilePath)
	if err != nil {
		log.Printf("读取配置文件失败: %v", err)
		return wgtypes.Key{}, err
	}

	// 解析私钥和公钥
	contentStr := string(content)
	lines := strings.Split(contentStr, "\n")

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "PrivateKey = ") {
			privateKeyStr := strings.TrimPrefix(line, "PrivateKey = ")
			// 解析私钥
			return wgtypes.ParseKey(privateKeyStr)
		}
	}

	return wgtypes.Key{}, fmt.Errorf("在配置文件中未找到私钥")
}

// configureTunIP 配置TUN设备IP地址
func configureTunIP(tunName string, ip net.IP, ipNet *net.IPNet) error {
	// 根据操作系统配置IP地址
	switch runtime.GOOS {
	case "linux":
		// 使用ip命令配置
		cmd := fmt.Sprintf("ip addr add %s/%d dev %s", ip.String(), maskBits(ipNet.Mask), tunName)
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置IP地址失败: %v", err)
		}

		// 启用设备
		cmd = fmt.Sprintf("ip link set dev %s up", tunName)
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("启用设备失败: %v", err)
		}
		return nil

	case "darwin": // macOS
		// 使用ifconfig命令配置
		maskStr := net.IP(ipNet.Mask).String()
		cmd := fmt.Sprintf("ifconfig %s inet %s %s netmask %s up", tunName, ip.String(), ip.String(), maskStr)
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置IP地址失败: %v", err)
		}
		return nil

	case "windows":
		// 使用netsh命令配置
		// 注意：在Windows上我们使用PowerShell命令，不需要掩码

		// 在Windows上，有时需要等待设备准备就绪
		time.Sleep(2 * time.Second)

		// 获取接口索引
		cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*' -or $_.InterfaceDescription -like '*TAP-Windows*' -or $_.InterfaceAlias -eq '%s'} | Select-Object -ExpandProperty ifIndex", tunName)
		output, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("获取网络接口失败: %v", err)
		}

		// 解析接口索引
		ifIndex := strings.TrimSpace(output)
		if ifIndex == "" {
			return fmt.Errorf("无法找到WireGuard网络接口")
		}

		// 配置IP地址 - 使用单行命令避免换行问题
		cmd = fmt.Sprintf("New-NetIPAddress -InterfaceIndex %s -IPAddress %s -PrefixLength %d -Confirm:$false", ifIndex, ip.String(), maskBits(ipNet.Mask))
		_, err = runCommand(cmd)
		if err != nil {
			// 如果失败，可能是因为IP已经存在，尝试移除并重新添加
			removeCmd := fmt.Sprintf("Remove-NetIPAddress -InterfaceIndex %s -Confirm:$false -ErrorAction SilentlyContinue", ifIndex)
			_, _ = runCommand(removeCmd)

			// 等待一下，确保IP地址已经被清理
			time.Sleep(1 * time.Second)

			// 尝试使用netsh命令配置IP地址
			netshCmd := fmt.Sprintf("cmd.exe /c \"netsh interface ip add address \\\"%s\\\" %s %s\"", tunName, ip.String(), net.IP(ipNet.Mask).String())
			_, err = runCommand(netshCmd)
			if err != nil {
				return fmt.Errorf("配置IP地址失败: %v", err)
			}
		}
		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// runCommand 运行shell命令
func runCommand(cmd string) (string, error) {
	var command *exec.Cmd

	// 仅在非清理命令时输出日志
	if !strings.Contains(cmd, "Remove-NetAdapter") && !strings.Contains(cmd, "route delete") {
		log.Printf("执行命令: %s", cmd)
	}

	if runtime.GOOS == "windows" {
		command = exec.Command("powershell", "-Command", cmd)
	} else {
		command = exec.Command("sh", "-c", cmd)
	}

	output, err := command.CombinedOutput()
	if err != nil {
		// 仅在非清理命令失败时输出错误日志
		if !strings.Contains(cmd, "Remove-NetAdapter") && !strings.Contains(cmd, "route delete") {
			log.Printf("命令执行失败: %v, 输出: %s", err, string(output))
		}
		return string(output), err
	}

	return string(output), nil
}

// maskBits 计算子网掩码的位数
func maskBits(mask net.IPMask) int {
	bits, _ := mask.Size()
	return bits
}

// allocateIP 分配IP地址给客户端
func allocateIP() net.IP {
	ipLock.Lock()
	defer ipLock.Unlock()

	ip := make(net.IP, len(nextIP))
	copy(ip, nextIP)

	// 增加IP地址
	for i := len(nextIP) - 1; i >= 0; i-- {
		nextIP[i]++
		if nextIP[i] != 0 {
			break
		}
	}

	return ip
}

// saveConfig 保存WireGuard配置到文件
func saveConfig(config *wireguard.Config) {
	// 生成配置文件内容
	configContent := config.GetWireGuardConfigString(true, nil)

	// 添加公钥到配置文件
	publicKey := wireguard.GeneratePublicKey(config.PrivateKey)
	configContent = strings.Replace(configContent, "[Interface]", "[Interface]\nPublicKey = "+publicKey.String(), 1)

	// 保存到文件
	err := os.WriteFile(*configFile, []byte(configContent), 0600)
	if err != nil {
		log.Printf("保存配置文件失败: %v", err)
		return
	}

	log.Printf("配置已保存到: %s", *configFile)
}

// updateConfigFile 更新配置文件，反映当前客户端状态
func updateConfigFile(wgDevice *wireguard.WireGuardDevice) {
	// 获取当前所有客户端
	peers, err := wgDevice.GetPeers()
	if err != nil {
		log.Printf("获取客户端列表失败: %v", err)
		return
	}

	// 创建客户端配置列表
	clientConfigs := make([]*wireguard.Config, 0, len(peers))
	for _, peer := range peers {
		// 创建客户端配置
		clientConfig := &wireguard.Config{
			PublicKey:  peer.PublicKey,
			AllowedIPs: peer.AllowedIPs,
		}
		clientConfigs = append(clientConfigs, clientConfig)
	}

	// 生成配置文件内容
	configContent := wgDevice.Config.GetWireGuardConfigString(true, clientConfigs)

	// 添加公钥到配置文件
	publicKey := wireguard.GeneratePublicKey(wgDevice.Config.PrivateKey)
	configContent = strings.Replace(configContent, "[Interface]", "[Interface]\nPublicKey = "+publicKey.String(), 1)

	// 保存到文件
	err = os.WriteFile(*configFile, []byte(configContent), 0600)
	if err != nil {
		log.Printf("更新配置文件失败: %v", err)
		return
	}

	log.Printf("配置文件已更新，移除了超时客户端")
}

// addClient 添加客户端
func addClient(serverConfig *wireguard.Config, wgDevice *wireguard.WireGuardDevice, clientPublicKey wgtypes.Key, clientName string) error {
	// 分配IP地址
	clientIP := allocateIP()

	// 创建允许的IP
	_, ipNet, _ := net.ParseCIDR(fmt.Sprintf("%s/32", clientIP.String()))
	allowedIPs := []net.IPNet{*ipNet}

	// 创建客户端配置
	clientConfig := &wireguard.Config{
		PublicKey:  clientPublicKey,
		AllowedIPs: allowedIPs,
	}

	// 添加客户端到WireGuard设备
	err := wgDevice.AddPeer(clientConfig, clientIP)
	if err != nil {
		return fmt.Errorf("添加客户端失败: %v", err)
	}

	log.Printf("已添加客户端 %s, IP: %s, 公钥: %s", clientName, clientIP, clientPublicKey.String())

	// 更新配置文件
	clientConfigs := []*wireguard.Config{clientConfig}
	configContent := serverConfig.GetWireGuardConfigString(true, clientConfigs)

	err = os.WriteFile(*configFile, []byte(configContent), 0600)
	if err != nil {
		log.Printf("更新配置文件失败: %v", err)
	}

	return nil
}

// generateClientConfig 生成客户端配置
func generateClientConfig(serverConfig *wireguard.Config, clientName string) (*wireguard.Config, error) {
	// 生成客户端密钥
	clientPrivateKey, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("生成客户端私钥失败: %v", err)
	}

	clientPublicKey := wireguard.GeneratePublicKey(clientPrivateKey)

	// 分配IP地址
	clientIP := allocateIP()

	// 创建允许的IP
	_, clientIPNet, _ := net.ParseCIDR(fmt.Sprintf("%s/32", clientIP.String()))
	_, serverIPNet, _ := net.ParseCIDR(*tunIP)

	allowedIPs := []net.IPNet{*serverIPNet}

	// 创建客户端配置
	clientConfig, err := wireguard.NewClientConfig(serverConfig.PublicKey, fmt.Sprintf("%s:%d", getServerIP(), *listenPort), allowedIPs)
	if err != nil {
		return nil, fmt.Errorf("创建客户端配置失败: %v", err)
	}

	// 设置客户端私钥
	clientConfig.PrivateKey = clientPrivateKey

	// 添加客户端到服务器
	serverAllowedIPs := []net.IPNet{*clientIPNet}
	serverPeerConfig := &wireguard.Config{
		PublicKey:  clientPublicKey,
		AllowedIPs: serverAllowedIPs,
	}

	// 保存客户端配置
	clientConfigContent := clientConfig.GetWireGuardConfigString(false, nil)
	clientConfigFile := fmt.Sprintf("wg-client-%s.conf", clientName)

	err = os.WriteFile(clientConfigFile, []byte(clientConfigContent), 0600)
	if err != nil {
		log.Printf("保存客户端配置文件失败: %v", err)
	} else {
		log.Printf("客户端配置已保存到: %s", clientConfigFile)
	}

	return serverPeerConfig, nil
}

// getServerIP 获取服务器IP地址
func getServerIP() string {
	// 尝试获取服务器的公网IP
	switch runtime.GOOS {
	case "linux", "darwin":
		// 使用curl获取公网IP
		cmd := "curl -s https://api.ipify.org"
		output, err := runCommand(cmd)
		if err == nil && output != "" {
			return strings.TrimSpace(output)
		}

		// 如果失败，尝试获取默认网关的IP
		if runtime.GOOS == "linux" {
			cmd = "ip route | grep default | awk '{print $3}'"
		} else {
			cmd = "route -n get default | grep gateway | awk '{print $2}'"
		}
		output, err = runCommand(cmd)
		if err == nil && output != "" {
			return strings.TrimSpace(output)
		}

	case "windows":
		// 使用PowerShell获取公网IP
		cmd := "(Invoke-WebRequest -Uri 'https://api.ipify.org' -UseBasicParsing).Content"
		output, err := runCommand(cmd)
		if err == nil && output != "" {
			return strings.TrimSpace(output)
		}

		// 如果失败，尝试获取默认网关的IP
		cmd = "(Get-NetRoute | Where-Object { $_.DestinationPrefix -eq '0.0.0.0/0' } | Get-NetIPInterface | Where-Object { $_.ConnectionState -eq 'Connected'} | Get-NetAdapter | Get-NetIPAddress -AddressFamily IPv4).IPAddress"
		output, err = runCommand(cmd)
		if err == nil && output != "" {
			return strings.TrimSpace(output)
		}
	}

	// 如果所有方法都失败，返回默认IP
	return "127.0.0.1"
}

// enableIPForwarding 启用IP转发
func enableIPForwarding() error {
	switch runtime.GOOS {
	case "linux":
		cmd := "echo 1 > /proc/sys/net/ipv4/ip_forward"
		_, err := runCommand(cmd)
		if err != nil {
			// 如果使用echo失败，尝试使用sysctl
			cmd = "sysctl -w net.ipv4.ip_forward=1"
			_, err = runCommand(cmd)
		}
		return err

	case "darwin": // macOS
		cmd := "sysctl -w net.inet.ip.forwarding=1"
		_, err := runCommand(cmd)
		return err

	case "windows":
		log.Printf("正在配置Windows IP转发...")

		// 1. 使用注册表启用IP转发
		cmd := "Set-ItemProperty -Path 'HKLM:\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters' -Name 'IPEnableRouter' -Value 1 -Type DWord -ErrorAction SilentlyContinue"
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("通过注册表启用IP转发失败: %v", err)
		} else {
			log.Printf("已通过注册表启用IP转发")
		}

		// 2. 获取所有活跃的网络接口
		cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object ifIndex, Name | Format-Table"
		output, _ := runCommand(cmd)
		log.Printf("活跃的网络接口:\n%s", output)

		// 3. 为所有接口启用IP转发
		// 获取WireGuard接口
		cmd = "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*' -or $_.InterfaceDescription -like '*TAP-Windows*'} | Select-Object -ExpandProperty ifIndex"
		wgIndices, _ := runCommand(cmd)
		wgIndices = strings.TrimSpace(wgIndices)
		if wgIndices != "" {
			for _, index := range strings.Split(wgIndices, "\n") {
				index = strings.TrimSpace(index)
				if index != "" {
					cmd = fmt.Sprintf("Set-NetIPInterface -ifIndex %s -Forwarding Enabled", index)
					_, err = runCommand(cmd)
					if err == nil {
						log.Printf("已为WireGuard接口(索引:%s)启用IP转发", index)
					}
				}
			}
		}

		// 获取外部接口
		cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*' -and $_.InterfaceDescription -notlike '*TAP-Windows*'} | Select-Object -ExpandProperty ifIndex"
		externalIndices, _ := runCommand(cmd)
		externalIndices = strings.TrimSpace(externalIndices)
		if externalIndices != "" {
			for _, index := range strings.Split(externalIndices, "\n") {
				index = strings.TrimSpace(index)
				if index != "" {
					cmd = fmt.Sprintf("Set-NetIPInterface -ifIndex %s -Forwarding Enabled", index)
					_, err = runCommand(cmd)
					if err == nil {
						log.Printf("已为外部接口(索引:%s)启用IP转发", index)
					}
				}
			}
		}

		// 4. 检查RemoteAccess服务是否存在，如果存在则重启
		cmd = "Get-Service RemoteAccess -ErrorAction SilentlyContinue"
		output, err = runCommand(cmd)
		if err == nil && output != "" && !strings.Contains(output, "Cannot find any service") {
			log.Printf("RemoteAccess服务存在，尝试重启...")
			cmd = "Restart-Service RemoteAccess -Force -ErrorAction SilentlyContinue"
			_, err = runCommand(cmd)
			if err != nil {
				log.Printf("重启RemoteAccess服务失败，但这不影响VPN功能")
			} else {
				log.Printf("已重启RemoteAccess服务")
			}
		} else {
			log.Printf("RemoteAccess服务不存在，跳过重启步骤")
		}

		// 5. 验证IP转发状态
		cmd = "Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | Select-Object ifIndex, InterfaceAlias | Format-Table"
		output, _ = runCommand(cmd)
		log.Printf("已启用IP转发的接口:\n%s", output)

		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// configureNAT 配置NAT
func configureNAT(vpnNetwork string) error {
	switch runtime.GOOS {
	case "linux":
		// 获取外网接口
		cmd := "ip route | grep default | awk '{print $5}'"
		output, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("获取外网接口失败: %v", err)
		}

		iface := strings.TrimSpace(output)
		if iface == "" {
			return fmt.Errorf("无法获取外网接口")
		}

		// 配置NAT
		cmd = fmt.Sprintf("iptables -t nat -A POSTROUTING -s %s -o %s -j MASQUERADE", vpnNetwork, iface)
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置NAT失败: %v", err)
		}

		// 允许转发
		cmd = fmt.Sprintf("iptables -A FORWARD -s %s -j ACCEPT", vpnNetwork)
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置转发规则失败: %v", err)
		}

		cmd = fmt.Sprintf("iptables -A FORWARD -d %s -j ACCEPT", vpnNetwork)
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置转发规则失败: %v", err)
		}

		return nil

	case "darwin": // macOS
		// 获取外网接口
		cmd := "route -n get default | grep interface | awk '{print $2}'"
		output, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("获取外网接口失败: %v", err)
		}

		iface := strings.TrimSpace(output)
		if iface == "" {
			return fmt.Errorf("无法获取外网接口")
		}

		// 配置NAT
		cmd = fmt.Sprintf("echo 'nat on %s from %s to any -> (%s)' | sudo pfctl -f -", iface, vpnNetwork, iface)
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置NAT失败: %v", err)
		}

		// 启用pfctl
		cmd = "pfctl -e"
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("启用pfctl失败: %v", err)
		}

		return nil

	case "windows":
		log.Printf("在Windows上配置NAT...")

		// 1. 验证IP转发是否已启用
		cmd := "Get-NetIPInterface | Where-Object {$_.Forwarding -eq 'Enabled'} | Select-Object ifIndex, InterfaceAlias | Format-Table"
		output, _ := runCommand(cmd)
		log.Printf("当前启用IP转发的接口:\n%s", output)

		// 2. 尝试使用Windows内置的NAT功能
		natConfigured := false

		// 先尝试移除现有的NAT
		removeCmd := "Get-NetNat -ErrorAction SilentlyContinue | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue"
		_, _ = runCommand(removeCmd)
		time.Sleep(1 * time.Second)

		// 使用随机名称创建NAT，避免冲突
		natName := fmt.Sprintf("WireGuardNAT_%d", time.Now().Unix())
		log.Printf("尝试创建NAT: %s", natName)

		// 创建NAT
		cmd = fmt.Sprintf("New-NetNat -Name \"%s\" -InternalIPInterfaceAddressPrefix %s -ErrorAction SilentlyContinue", natName, vpnNetwork)
		_, err := runCommand(cmd)
		if err == nil {
			log.Printf("成功创建NAT: %s", natName)
			natConfigured = true

			// 验证NAT配置
			cmd = "Get-NetNat -ErrorAction SilentlyContinue | Format-Table"
			output, _ = runCommand(cmd)
			log.Printf("当前NAT配置:\n%s", output)
		} else {
			log.Printf("使用NetNat失败: %v", err)
		}

		// 3. 如果NetNat失败，尝试使用Internet连接共享(ICS)
		if !natConfigured {
			log.Printf("尝试使用Internet连接共享(ICS)...")

			// 获取外部接口
			cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*'} | Select-Object -First 1 -ExpandProperty Name"
			externalInterface, _ := runCommand(cmd)
			externalInterface = strings.TrimSpace(externalInterface)

			// 获取WireGuard接口
			cmd = "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -First 1 -ExpandProperty Name"
			wgInterface, _ := runCommand(cmd)
			wgInterface = strings.TrimSpace(wgInterface)

			if externalInterface != "" && wgInterface != "" {
				// 使用PowerShell脚本启用ICS
				icsScript := fmt.Sprintf(`
				try {
					$netShare = New-Object -ComObject HNetCfg.HNetShare
					$connection = $netShare.EnumEveryConnection | Where-Object { $netShare.NetConnectionProps.Invoke($_).Name -eq "%s" }
					if ($connection) {
						$config = $netShare.INetSharingConfigurationForINetConnection.Invoke($connection)
						$config.EnableSharing(0)
						Write-Host "Enabled sharing for external interface: %s"
					}

					$wgConnection = $netShare.EnumEveryConnection | Where-Object { $netShare.NetConnectionProps.Invoke($_).Name -eq "%s" }
					if ($wgConnection) {
						$wgConfig = $netShare.INetSharingConfigurationForINetConnection.Invoke($wgConnection)
						$wgConfig.EnableSharing(1)
						Write-Host "Enabled sharing for WireGuard interface: %s"
					}
				} catch {
					Write-Host "Error enabling ICS: $_"
				}
				`, externalInterface, externalInterface, wgInterface, wgInterface)

				// 保存脚本到临时文件
				scriptPath := "enable_ics.ps1"
				err = os.WriteFile(scriptPath, []byte(icsScript), 0644)
				if err == nil {
					// 执行脚本
					cmd = fmt.Sprintf("powershell -ExecutionPolicy Bypass -File %s", scriptPath)
					output, err := runCommand(cmd)
					log.Printf("ICS脚本输出: %s", output)
					if err == nil {
						log.Printf("成功配置Internet连接共享")
						natConfigured = true
					} else {
						log.Printf("配置Internet连接共享失败: %v", err)
					}
					// 删除临时脚本
					os.Remove(scriptPath)
				}
			}
		}

		// 4. 如果以上方法都失败，使用netsh命令配置IP转发
		if !natConfigured {
			log.Printf("尝试使用netsh命令配置IP转发...")

			// 获取所有活跃的网络接口
			cmd = "netsh interface ipv4 show interfaces"
			output, _ = runCommand(cmd)
			log.Printf("网络接口列表:\n%s", output)

			// 获取外部接口索引
			cmd = "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*'} | Select-Object -First 1 -ExpandProperty ifIndex"
			externalIndex, _ := runCommand(cmd)
			externalIndex = strings.TrimSpace(externalIndex)

			// 获取WireGuard接口索引
			cmd = "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -First 1 -ExpandProperty ifIndex"
			wgIndex, _ := runCommand(cmd)
			wgIndex = strings.TrimSpace(wgIndex)

			if externalIndex != "" && wgIndex != "" {
				// 为外部接口启用IP转发
				cmd = fmt.Sprintf("netsh interface ipv4 set interface %s forwarding=enabled", externalIndex)
				_, _ = runCommand(cmd)

				// 为WireGuard接口启用IP转发
				cmd = fmt.Sprintf("netsh interface ipv4 set interface %s forwarding=enabled", wgIndex)
				_, _ = runCommand(cmd)

				log.Printf("已使用netsh命令配置IP转发")
				natConfigured = true
			}
		}

		// 5. 添加路由规则，允许VPN网段流量通过外部接口
		_, vpnNet, _ := net.ParseCIDR(vpnNetwork)
		cmd = fmt.Sprintf("route add %s mask %s 0.0.0.0 metric 1",
			vpnNet.IP.String(),
			net.IP(vpnNet.Mask).String())
		_, _ = runCommand(cmd)

		// 验证路由配置
		cmd = "route print"
		output, _ = runCommand(cmd)
		log.Printf("当前路由表:\n%s", output)

		if natConfigured {
			log.Printf("成功配置NAT")
			return nil
		}

		// 即使所有方法都失败，也不返回错误，因为可能只需要IP转发就足够了
		log.Printf("所有NAT配置方法都失败，但已启用IP转发")
		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// cleanupOrphanedAdapters 清理孤立的WireGuard适配器
func cleanupOrphanedAdapters() {
	// 查找所有WireGuard适配器
	cmd := "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*'} | Select-Object -ExpandProperty Name"
	output, err := runCommand(cmd)
	if err != nil {
		// 如果查询失败，直接返回
		return
	}

	// 如果有适配器，尝试清理
	adapterNames := strings.Split(strings.TrimSpace(output), "\n")
	for _, name := range adapterNames {
		name = strings.TrimSpace(name)
		if name != "" {
			log.Printf("检测到孤立的WireGuard适配器: %s，尝试清理", name)

			// 尝试移除适配器，但不显示错误
			removeCmd := fmt.Sprintf("Remove-NetAdapter -Name \"%s\" -Confirm:$false -ErrorAction SilentlyContinue", name)
			_, _ = runCommand(removeCmd)
		}
	}
}

// addSpecificClient 添加指定公钥的客户端
func addSpecificClient(serverConfig *wireguard.Config, wgDevice *wireguard.WireGuardDevice, clientPubKeyStr string) {
	pubKey, err := wireguard.ParseKey(clientPubKeyStr)
	if err != nil {
		log.Printf("解析客户端公钥失败: %v", err)
		return
	}

	// 创建允许的IP - 允许客户端使用任何源IP地址
	allowedIPs := []net.IPNet{}

	// 分配IP地址
	clientIP := allocateIP()

	// 允许任何IPv4地址
	_, ipv4Net, _ := net.ParseCIDR("0.0.0.0/0")
	allowedIPs = append(allowedIPs, *ipv4Net)

	// 允许任何IPv6地址
	_, ipv6Net, _ := net.ParseCIDR("::/0")
	allowedIPs = append(allowedIPs, *ipv6Net)

	log.Printf("为客户端设置的AllowedIPs: %v", allowedIPs)

	// 创建客户端配置
	clientConfig := &wireguard.Config{
		PublicKey:  pubKey,
		AllowedIPs: allowedIPs,
	}

	// 已经在上面分配了IP地址，这里不需要再分配

	// 添加客户端到WireGuard设备
	err = wgDevice.AddPeer(clientConfig, clientIP)
	if err != nil {
		log.Printf("添加客户端失败: %v", err)
		return
	}

	log.Printf("已添加客户端, IP: %s, 公钥: %s", clientIP.String(), pubKey.String())

	// 更新配置文件
	clientConfigs := []*wireguard.Config{clientConfig}
	configContent := serverConfig.GetWireGuardConfigString(true, clientConfigs)

	// 添加公钥到配置文件
	publicKey := wireguard.GeneratePublicKey(serverConfig.PrivateKey)
	configContent = strings.Replace(configContent, "[Interface]", "[Interface]\nPublicKey = "+publicKey.String(), 1)

	err = os.WriteFile(*configFile, []byte(configContent), 0600)
	if err != nil {
		log.Printf("更新配置文件失败: %v", err)
	}
}

// monitorClientConnections 监控客户端连接状态
func monitorClientConnections(wgDevice *wireguard.WireGuardDevice) {
	// 初始化已知客户端映射
	knownPeers := make(map[string]time.Time)
	// 初始化超时警告映射，记录已经发出警告的客户端
	timeoutWarnings := make(map[string]bool)

	// 计算超时时间
	timeoutDuration := time.Duration(*clientTimeout) * time.Minute
	log.Printf("客户端超时时间设置为 %d 分钟", *clientTimeout)
	log.Printf("自动清理超时客户端: %v", *autoCleanup)

	// 创建一个计数器，用于定期输出服务器公钥
	pubKeyCounter := 0

	// 每5秒检查一次客户端连接状态
	for {
		// 获取当前所有客户端
		peers, err := wgDevice.GetPeers()
		if err != nil {
			log.Printf("获取客户端列表失败: %v", err)
			time.Sleep(5 * time.Second)
			continue
		}

		// 当前活跃的客户端
		currentPeers := make(map[string]bool)

		// 每12次循环（大约60秒）输出一次服务器公钥和客户端数量
		pubKeyCounter++
		if pubKeyCounter >= 12 {
			serverPublicKey := wireguard.GeneratePublicKey(wgDevice.Config.PrivateKey).String()
			log.Printf("服务器公钥: %s", serverPublicKey)
			log.Printf("当前连接的客户端数量: %d", len(peers))
			pubKeyCounter = 0
		}

		// 检查每个客户端
		for _, peer := range peers {
			peerKey := peer.PublicKey.String()
			currentPeers[peerKey] = true

			// 获取客户端IP地址
			ipStr := ""
			// 优先使用peer.IP，因为这是分配给客户端的实际IP地址
			if peer.IP != nil {
				ipStr = peer.IP.String()
			} else if len(peer.AllowedIPs) > 0 && peer.AllowedIPs[0].IP.String() != "0.0.0.0" {
				// 只有当AllowedIPs不是0.0.0.0/0时才使用
				ipStr = peer.AllowedIPs[0].IP.String()
			} else {
				// 如果上述方法都失败，使用默认的VPN客户端IP范围
				ipStr = "10.8.0.x"
			}

			// 检查是否是新连接的客户端
			_, exists := knownPeers[peerKey]
			if !exists {
				// 新客户端连接
				log.Printf("新客户端连接: %s, IP: %s", peerKey, ipStr)
				knownPeers[peerKey] = time.Now()
				// 清除超时警告标记
				delete(timeoutWarnings, peerKey)
			}

			// 检查客户端活跃状态
			if peer.LastHandshakeTime.After(knownPeers[peerKey]) {
				// 客户端有新的握手，更新时间
				log.Printf("客户端活跃: %s, IP: %s, 最后握手时间: %s",
					peerKey, ipStr, peer.LastHandshakeTime.Format("2006-01-02 15:04:05"))
				knownPeers[peerKey] = peer.LastHandshakeTime
				// 清除超时警告标记
				delete(timeoutWarnings, peerKey)
			}

			// 检查客户端是否长时间未活跃
			// 使用最后数据接收时间和最后握手时间的最大值来判断
			lastActiveTime := peer.LastHandshakeTime
			if peer.LastDataReceived.After(lastActiveTime) {
				lastActiveTime = peer.LastDataReceived
			}

			// 检查是否有握手活动
			// WireGuard的握手周期是2分钟，所以如果在最近5分钟内有握手，就认为客户端是活跃的
			recentHandshakeTime := time.Since(peer.LastHandshakeTime) < 5*time.Minute
			if recentHandshakeTime {
				// 如果有最近的握手活动，更新最后活跃时间为当前时间
				log.Printf("客户端有最近的握手活动: %s, IP: %s, 最后握手时间: %s",
					peerKey, ipStr, peer.LastHandshakeTime.Format("2006-01-02 15:04:05"))
				knownPeers[peerKey] = time.Now()
				// 清除超时警告标记
				delete(timeoutWarnings, peerKey)
				continue
			}

			inactiveTime := time.Since(lastActiveTime)

			// 如果超过警告时间（超时时间的50%），发出警告
			warningTime := timeoutDuration / 2
			if inactiveTime > warningTime && !timeoutWarnings[peerKey] {
				log.Printf("警告: 客户端长时间未活跃: %s, IP: %s, 最后活跃时间: %s, 不活跃时间: %s",
					peerKey, ipStr, lastActiveTime.Format("2006-01-02 15:04:05"), inactiveTime.Round(time.Second))
				timeoutWarnings[peerKey] = true
			}

			// 如果超过超时时间且启用了自动清理，则清理客户端
			if inactiveTime > timeoutDuration && *autoCleanup {
				// 添加额外检查：尝试ping客户端
				clientAlive := false
				// 使用与日志显示相同的方式获取客户端IP
				pingIP := ""
				if peer.IP != nil {
					pingIP = peer.IP.String()
				} else if len(peer.AllowedIPs) > 0 && peer.AllowedIPs[0].IP.String() != "0.0.0.0" {
					pingIP = peer.AllowedIPs[0].IP.String()
				}

				// 只有当有有效的IP地址时才尝试ping
				if pingIP != "" && pingIP != "0.0.0.0" && pingIP != "10.8.0.x" {
					cmd := fmt.Sprintf("ping -c 1 -W 2 %s", pingIP)
					if runtime.GOOS == "windows" {
						cmd = fmt.Sprintf("ping -n 1 -w 2000 %s", pingIP)
					}

					_, err := runCommand(cmd)
					clientAlive = (err == nil)
				}

				// 如果ping成功，更新最后活跃时间并跳过清理
				if clientAlive {
					log.Printf("客户端仍然活跃(ping成功): %s, IP: %s", peerKey, ipStr)
					knownPeers[peerKey] = time.Now()
					delete(timeoutWarnings, peerKey)
					continue
				}

				log.Printf("清理超时客户端: %s, IP: %s, 最后活跃时间: %s, 不活跃时间: %s",
					peerKey, ipStr, lastActiveTime.Format("2006-01-02 15:04:05"), inactiveTime.Round(time.Second))

				// 解析公钥
				pubKey, err := wireguard.ParseKey(peerKey)
				if err != nil {
					log.Printf("解析客户端公钥失败: %v", err)
					continue
				}

				// 移除客户端
				err = wgDevice.RemovePeer(pubKey)
				if err != nil {
					log.Printf("移除超时客户端失败: %v", err)
				} else {
					log.Printf("已成功移除超时客户端: %s", peerKey)
					// 从已知客户端列表中移除
					delete(knownPeers, peerKey)
					// 清除超时警告标记
					delete(timeoutWarnings, peerKey)
					// 从当前客户端列表中移除
					delete(currentPeers, peerKey)

					// 更新配置文件，移除超时客户端的配置
					updateConfigFile(wgDevice)
				}
			}
		}

		// 检查断开连接的客户端
		for peerKey := range knownPeers {
			if !currentPeers[peerKey] {
				// 客户端断开连接
				log.Printf("客户端断开连接: %s", peerKey)
				delete(knownPeers, peerKey)
				// 清除超时警告标记
				delete(timeoutWarnings, peerKey)
			}
		}

		// 等待5秒再检查
		time.Sleep(5 * time.Second)
	}
}

// cleanupNAT 清理NAT配置
func cleanupNAT(vpnNetwork string) error {
	switch runtime.GOOS {
	case "linux":
		// 获取外网接口
		cmd := "ip route | grep default | awk '{print $5}'"
		output, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("获取外网接口失败: %v", err)
		}

		iface := strings.TrimSpace(output)
		if iface == "" {
			return fmt.Errorf("无法获取外网接口")
		}

		// 移除NAT规则
		cmd = fmt.Sprintf("iptables -t nat -D POSTROUTING -s %s -o %s -j MASQUERADE", vpnNetwork, iface)
		_, _ = runCommand(cmd)

		// 移除转发规则
		cmd = fmt.Sprintf("iptables -D FORWARD -s %s -j ACCEPT", vpnNetwork)
		_, _ = runCommand(cmd)

		cmd = fmt.Sprintf("iptables -D FORWARD -d %s -j ACCEPT", vpnNetwork)
		_, _ = runCommand(cmd)

		return nil

	case "darwin": // macOS
		// 禁用pfctl
		cmd := "pfctl -d"
		_, _ = runCommand(cmd)
		return nil

	case "windows":
		// 尝试移除所有WireGuard相关的NAT
		// 使用ErrorAction SilentlyContinue来避免在NetNat不可用时报错
		cmd := "Get-NetNat -ErrorAction SilentlyContinue | Where-Object {$_.Name -like 'WireGuard*'} | Remove-NetNat -Confirm:$false -ErrorAction SilentlyContinue"
		_, _ = runCommand(cmd)

		// 等待一下，确保NAT已经被清理
		time.Sleep(1 * time.Second)

		// 如果使用了netsh命令启用IP转发，尝试禁用
		// 获取外网接口名称
		cmd = "cmd.exe /c \"netsh interface show interface | findstr Connected | findstr -v Loopback | findstr -v WireGuard\""
		output, err := runCommand(cmd)
		if err == nil && output != "" {
			// 解析接口名称
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 4 {
					ifName := strings.Join(fields[3:], " ")

					// 获取接口索引
					indexCmd := "cmd.exe /c \"netsh interface ipv4 show interfaces | findstr \\\"" + ifName + "\\\"\""
					indexOutput, _ := runCommand(indexCmd)
					if indexOutput != "" {
						// 解析接口索引
						indexLines := strings.Split(indexOutput, "\n")
						for _, indexLine := range indexLines {
							indexFields := strings.Fields(indexLine)
							if len(indexFields) > 0 {
								// 第一个字段应该是索引
								ifIndex := indexFields[0]

								// 使用索引禁用IP转发
								cmd = "cmd.exe /c \"netsh interface ipv4 set interface " + ifIndex + " forwarding=disabled\""
								_, _ = runCommand(cmd)
								break
							}
						}
					} else {
						// 如果无法获取索引，尝试直接使用名称
						cmd = "cmd.exe /c \"netsh interface ipv4 set interface " + ifName + " forwarding=disabled\""
						_, _ = runCommand(cmd)
					}

					break
				}
			}
		}

		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// startClientRegistrationService 启动客户端注册服务
func startClientRegistrationService(port int, serverConfig *wireguard.Config, wgDevice *wireguard.WireGuardDevice) {
	// 创建UDP地址
	addr := net.UDPAddr{
		Port: port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	// 创建UDP服务
	conn, err := net.ListenUDP("udp", &addr)
	if err != nil {
		log.Printf("启动客户端注册服务失败: %v", err)
		return
	}
	defer conn.Close()

	log.Printf("客户端注册服务已启动，等待客户端连接...")

	// 接收缓冲区
	buffer := make([]byte, 1024)

	for {
		// 接收客户端请求
		n, clientAddr, err := conn.ReadFromUDP(buffer)
		if err != nil {
			log.Printf("接收数据失败: %v", err)
			continue
		}

		// 处理客户端请求
		go handleClientRegistration(conn, clientAddr, buffer[:n], serverConfig, wgDevice)
	}
}

// 客户端注册请求结构
type RegistrationRequest struct {
	Command    string `json:"command"`
	PublicKey  string `json:"public_key"`
	Secret     string `json:"secret"`
	ClientName string `json:"client_name"`
}

// 客户端注册响应结构
type RegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	IP      string `json:"ip,omitempty"`
}

// handleClientRegistration 处理客户端注册请求
func handleClientRegistration(conn *net.UDPConn, clientAddr *net.UDPAddr, data []byte, serverConfig *wireguard.Config, wgDevice *wireguard.WireGuardDevice) {
	// 判断是简单的公钥请求
	if string(data) == "GET_PUBLIC_KEY" {
		// 返回服务器公钥
		publicKey := wireguard.GeneratePublicKey(serverConfig.PrivateKey)
		log.Printf("收到来自 %s 的公钥请求", clientAddr.String())
		conn.WriteToUDP([]byte(publicKey.String()), clientAddr)
		log.Printf("已向客户端 %s 发送服务器公钥: %s", clientAddr.String(), publicKey.String())
		return
	}

	// 尝试解析JSON请求
	var request RegistrationRequest
	if err := json.Unmarshal(data, &request); err != nil {
		log.Printf("解析客户端请求失败: %v, 数据: %s", err, string(data))
		sendRegistrationResponse(conn, clientAddr, false, "无效的请求格式", "")
		return
	}

	// 验证注册密钥
	if request.Secret != *regSecret {
		log.Printf("客户端 %s 注册失败: 无效的注册密钥", clientAddr.String())
		sendRegistrationResponse(conn, clientAddr, false, "无效的注册密钥", "")
		return
	}

	// 处理注册命令
	if request.Command == "REGISTER_CLIENT" {
		log.Printf("收到来自 %s 的客户端注册请求", clientAddr.String())
		// 解析客户端公钥
		clientPublicKey, err := wireguard.ParseKey(request.PublicKey)
		if err != nil {
			log.Printf("解析客户端公钥失败: %v", err)
			sendRegistrationResponse(conn, clientAddr, false, "无效的公钥格式", "")
			return
		}

		// 分配IP地址
		clientIP := allocateIP()

		// 创建允许的IP - 允许客户端使用任何源IP地址
		allowedIPs := []net.IPNet{}

		// 允许任何IPv4地址
		_, ipv4Net, _ := net.ParseCIDR("0.0.0.0/0")
		allowedIPs = append(allowedIPs, *ipv4Net)

		// 允许任何IPv6地址
		_, ipv6Net, _ := net.ParseCIDR("::/0")
		allowedIPs = append(allowedIPs, *ipv6Net)

		log.Printf("为客户端设置的AllowedIPs: %v", allowedIPs)

		// 创建客户端配置
		clientConfig := &wireguard.Config{
			PublicKey:  clientPublicKey,
			AllowedIPs: allowedIPs,
		}

		// 添加客户端到WireGuard设备
		if err := wgDevice.AddPeer(clientConfig, clientIP); err != nil {
			log.Printf("添加客户端失败: %v", err)
			sendRegistrationResponse(conn, clientAddr, false, "添加客户端失败", "")
			return
		}

		// 生成客户端名称（如果未提供）
		clientName := request.ClientName
		if clientName == "" {
			clientName = fmt.Sprintf("client-%s", clientAddr.IP)
		}

		log.Printf("已注册新客户端: %s, IP: %s, 公钥: %s", clientName, clientIP, request.PublicKey)

		// 更新配置文件
		clientConfigs := []*wireguard.Config{clientConfig}
		configContent := serverConfig.GetWireGuardConfigString(true, clientConfigs)

		// 添加公钥到配置文件
		publicKey := wireguard.GeneratePublicKey(serverConfig.PrivateKey)
		configContent = strings.Replace(configContent, "[Interface]", "[Interface]\nPublicKey = "+publicKey.String(), 1)

		// 写入配置文件
		if err := os.WriteFile(*configFile, []byte(configContent), 0600); err != nil {
			log.Printf("更新配置文件失败: %v", err)
		}

		// 返回成功响应
		sendRegistrationResponse(conn, clientAddr, true, "客户端注册成功", clientIP.String())
		return
	}

	// 未知命令
	log.Printf("收到来自 %s 的未知命令: %s", clientAddr.String(), string(data))
	sendRegistrationResponse(conn, clientAddr, false, "未知命令", "")
}

// sendRegistrationResponse 发送注册响应
func sendRegistrationResponse(conn *net.UDPConn, clientAddr *net.UDPAddr, success bool, message string, ip string) {
	response := RegistrationResponse{
		Success: success,
		Message: message,
		IP:      ip,
	}

	responseJSON, err := json.Marshal(response)
	if err != nil {
		log.Printf("序列化响应失败: %v", err)
		return
	}

	if _, err := conn.WriteToUDP(responseJSON, clientAddr); err != nil {
		log.Printf("发送响应失败: %v", err)
	}
}
