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
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/pekhightvpn/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// ERR_ADDRESS_UNREACHABLE
var (
	serverEndpoint = flag.String("server", "120.79.187.148:23456", "服务器地址")
	tunName        = flag.String("tun", "wgc0", "TUN设备名称") // 使用不同的设备名称
	configFile     = flag.String("config", "", "WireGuard配置文件路径")
	serverPubKey   = flag.String("server-pubkey", "", "服务器公钥")
	privateKey     = flag.String("private-key", "", "客户端私钥")
	clientIP       = flag.String("ip", "10.9.0.2/24", "客户端IP地址") // 使用不同的IP地址范围
	listenPort     = flag.Int("listen-port", 51821, "客户端监听端口")   // 使用不同的监听端口
	useAmnezia     = flag.Bool("amnezia", false, "是否使用AmneziaWG修改")
	clientName     = flag.String("client-name", "", "客户端名称")
	regSecret      = flag.String("reg-secret", "vpnsecret", "注册密钥")
	fullTunnel     = flag.Bool("full-tunnel", true, "是否启用全局代理模式")
	useDNSProxy    = flag.Bool("dns-proxy", false, "是否使用DNS代理")

	// 系统信息
	hostname, _ = os.Hostname()
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

		// 清理可能冲突的网络资源
		cleanupNetworkResources()
	}

	log.Printf("启动WireGuard VPN客户端...")

	var config *wireguard.Config
	var err error

	// 如果提供了配置文件，从文件加载配置
	if *configFile != "" {
		config, err = loadConfigFromFile(*configFile)
		if err != nil {
			log.Fatalf("加载配置文件失败: %v", err)
		}
	} else if *serverPubKey != "" && *privateKey != "" {
		// 如果提供了服务器公钥和客户端私钥，创建配置
		config, err = createConfigFromKeys(*serverPubKey, *privateKey, *serverEndpoint, *clientIP)
		if err != nil {
			log.Fatalf("创建配置失败: %v", err)
		}
	} else {
		// 否则，生成新的配置
		config, err = generateNewConfig(*serverEndpoint, *clientIP)
		if err != nil {
			log.Fatalf("生成配置失败: %v", err)
		}
	}

	// 设置客户端监听端口
	config.ListenPort = *listenPort
	log.Printf("客户端监听端口: %d", *listenPort)

	// 如果使用AmneziaWG，应用特定修改
	if *useAmnezia {
		wireguard.AmneziaWGModify(config)
		log.Printf("已应用AmneziaWG特定修改")
	}

	// 创建WireGuard设备
	wgDevice, err := wireguard.NewWireGuardDevice(config, false)
	if err != nil {
		log.Fatalf("创建WireGuard设备失败: %v", err)
	}
	defer wgDevice.Close()

	// 解析IP地址和子网掩码
	ip, ipNet, err := net.ParseCIDR(*clientIP)
	if err != nil {
		log.Fatalf("无效的IP地址: %s, %v", *clientIP, err)
	}

	// 配置TUN设备IP地址
	err = configureTunIP(wgDevice.TunName, ip, ipNet)
	if err != nil {
		log.Fatalf("配置TUN设备IP地址失败: %v", err)
	}

	// 配置DNS
	err = configureDNS(wgDevice.TunName)
	if err != nil {
		log.Printf("配置DNS失败: %v", err)
	}

	// TCP参数优化已禁用
	// optimizeTCPParameters()

	// 路由优化已禁用
	// optimizeRouting(wgDevice.TunName)

	// 添加路由顺序很重要，先添加服务器特殊路由，再添加VPN网段路由，最后添加默认路由

	// 如果启用了全局代理，先添加服务器特殊路由，再添加默认路由
	if *fullTunnel {
		// 添加服务器特殊路由，确保与VPN服务器的通信不通过VPN
		host, _, err := net.SplitHostPort(config.Endpoint)
		if err == nil {
			serverIP := net.ParseIP(host)
			if serverIP != nil && !serverIP.IsLoopback() {
				// 获取默认网关
				defaultGateway := ""

				// 使用route命令获取默认网关
				cmd := "cmd.exe /c \"route print 0.0.0.0 | findstr 0.0.0.0 | findstr /v 127.0.0.1 | findstr /v 0.0.0.0/0\""
				output, _ := runCommand(cmd)
				lines := strings.Split(output, "\n")
				for _, line := range lines {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						defaultGateway = fields[2]
						break
					}
				}

				if defaultGateway != "" {
					// 删除可能存在的路由
					deleteCmd := fmt.Sprintf("route delete %s", serverIP.String())
					_, _ = runCommand(deleteCmd)

					// 添加服务器特殊路由，使用默认网关，使用非常低的metric值
					addCmd := fmt.Sprintf("cmd.exe /c \"route add %s mask 255.255.255.255 %s metric 1\"", serverIP.String(), defaultGateway)
					_, err = runCommand(addCmd)
					if err == nil {
						log.Printf("已添加服务器特殊路由: %s -> %s", serverIP.String(), defaultGateway)
					}
				}
			}
		}

		// 等待一下，确保服务器特殊路由生效
		time.Sleep(500 * time.Millisecond)
	}

	// 添加VPN网段路由
	err = addRoute(config.AllowedIPs[0].String(), wgDevice.TunName)
	if err != nil {
		log.Printf("添加VPN网段路由失败: %v", err)
	} else {
		log.Printf("已添加VPN网段路由: %s", config.AllowedIPs[0].String())
	}

	// 如果启用了全局代理，添加默认路由
	if *fullTunnel {
		// 添加默认路由
		_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
		err = addRoute(defaultNet.String(), wgDevice.TunName)
		if err != nil {
			log.Printf("添加默认路由失败: %v", err)
		} else {
			log.Printf("已添加默认路由，所有流量将通过VPN（除了服务器通信）")
		}
	}

	log.Printf("WireGuard客户端已启动")
	log.Printf("服务器: %s", config.Endpoint)
	log.Printf("服务器公钥: %s", config.PublicKey.String())
	log.Printf("客户端公钥: %s", wireguard.GeneratePublicKey(config.PrivateKey).String())
	log.Printf("TUN设备: %s, IP: %s", wgDevice.TunName, *clientIP)

	// 如果启用DNS代理，启动DNS代理
	var dnsProxy *DNSProxy
	if *useDNSProxy {
		log.Printf("启用DNS代理...")
		dnsProxy = NewDNSProxy()
		err = dnsProxy.Start()
		if err != nil {
			log.Printf("启动DNS代理失败: %v", err)
		} else {
			log.Printf("DNS代理已启动，监听地址: %s", dnsProxy.listenAddr)

			// 如果启用了DNS代理，将DNS服务器设置为127.0.0.1
			if runtime.GOOS == "windows" {
				// 获取TUN接口索引
				cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.Name -eq '%s' -or $_.InterfaceDescription -like '*WireGuard*'} | Select-Object -ExpandProperty ifIndex", wgDevice.TunName)
				output, _ := runCommand(cmd)
				ifIndex := strings.TrimSpace(output)
				if ifIndex != "" {
					// 配置DNS服务器为本地DNS代理
					cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses '127.0.0.1'", ifIndex)
					_, _ = runCommand(cmd)
					log.Printf("已将DNS服务器设置为本地DNS代理")
				}
			}
		}
	}

	// 测试互联网连接
	go func() {
		// 等待一段时间让VPN连接稳定
		time.Sleep(5 * time.Second)
		testInternetConnection()
	}()

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	<-sigCh
	log.Printf("正在关闭WireGuard客户端...")

	// 清理资源
	// 如果启用了DNS代理，停止DNS代理
	if dnsProxy != nil {
		log.Printf("正在停止DNS代理...")
		dnsProxy.Stop()
	}

	log.Printf("正在关闭WireGuard设备...")
	wgDevice.Close()

	// 如果需要，可以清理路由
	if runtime.GOOS == "windows" {
		// 在Windows上清理路由
		_, ipNet, _ := net.ParseCIDR(config.AllowedIPs[0].String())
		ip := ipNet.IP.String()
		mask := net.IP(ipNet.Mask).String()
		cmd := fmt.Sprintf("cmd.exe /c \"route delete %s mask %s\"", ip, mask)
		_, _ = runCommand(cmd)

		// 等待一下，确保资源正确释放
		time.Sleep(500 * time.Millisecond)
	}
}

// loadConfigFromFile 从文件加载WireGuard配置
func loadConfigFromFile(filePath string) (*wireguard.Config, error) {
	// 读取配置文件
	_, err := os.ReadFile(filePath) // 我们先检查文件是否存在
	if err != nil {
		return nil, fmt.Errorf("读取配置文件失败: %v", err)
	}

	// 解析配置文件
	// 这里应该实现解析WireGuard配置文件的逻辑
	// 由于配置文件格式较为复杂，这里只是一个简化的实现

	// 假设我们已经解析出了私钥、服务器公钥、端点和允许的IP
	privateKeyStr := "your_private_key"    // 从配置文件中提取
	serverPubKeyStr := "server_public_key" // 从配置文件中提取
	endpoint := "server_endpoint"          // 从配置文件中提取
	allowedIPStr := "10.8.0.0/24"          // 从配置文件中提取

	// 解析密钥
	privateKey, err := wireguard.ParseKey(privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %v", err)
	}

	serverPubKey, err := wireguard.ParseKey(serverPubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("解析服务器公钥失败: %v", err)
	}

	// 解析允许的IP
	_, allowedIP, err := net.ParseCIDR(allowedIPStr)
	if err != nil {
		return nil, fmt.Errorf("解析允许的IP失败: %v", err)
	}

	// 创建配置
	config := &wireguard.Config{
		PrivateKey: privateKey,
		PublicKey:  serverPubKey,
		Endpoint:   endpoint,
		AllowedIPs: []net.IPNet{*allowedIP},
	}

	return config, nil
}

// createConfigFromKeys 从密钥创建WireGuard配置
func createConfigFromKeys(serverPubKeyStr, privateKeyStr, endpoint, clientIPStr string) (*wireguard.Config, error) {
	// 解析密钥
	privateKey, err := wireguard.ParseKey(privateKeyStr)
	if err != nil {
		return nil, fmt.Errorf("解析私钥失败: %v", err)
	}

	serverPubKey, err := wireguard.ParseKey(serverPubKeyStr)
	if err != nil {
		return nil, fmt.Errorf("解析服务器公钥失败: %v", err)
	}

	// 根据用户选择的代理模式设置允许的IP
	var allowedIP *net.IPNet
	var parseErr error
	if *fullTunnel {
		// 全局代理模式
		_, allowedIP, parseErr = net.ParseCIDR("0.0.0.0/0")
		log.Printf("使用全局代理模式，所有流量将通过VPN")
	} else {
		// 分流模式，只允许VPN网段的流量
		_, allowedIP, parseErr = net.ParseCIDR("10.9.0.0/24")
		log.Printf("使用分流模式，只允许VPN网段的流量")
	}

	if parseErr != nil {
		return nil, fmt.Errorf("解析允许的IP失败: %v", parseErr)
	}

	// 创建配置
	config := &wireguard.Config{
		PrivateKey:          privateKey,
		PublicKey:           serverPubKey,
		Endpoint:            endpoint,
		AllowedIPs:          []net.IPNet{*allowedIP},
		PersistentKeepalive: 25, // 每25秒发送一次keepalive包
	}

	return config, nil
}

// getServerPublicKey 从服务器获取公钥
func getServerPublicKey(endpoint string) (wgtypes.Key, error) {
	// 解析服务器地址和端口
	host, portStr, err := net.SplitHostPort(endpoint)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("解析服务器地址失败: %v", err)
	}

	// WireGuard使用UDP协议，直接尝试UDP连接
	log.Printf("尝试使用UDP协议连接到服务器 %s...", endpoint)

	// 如果用户指定了服务器公钥，直接返回
	if *serverPubKey != "" {
		log.Printf("使用用户指定的服务器公钥: %s", *serverPubKey)
		key, err := wireguard.ParseKey(*serverPubKey)
		if err != nil {
			return wgtypes.Key{}, fmt.Errorf("解析服务器公钥失败: %v", err)
		}
		return key, nil
	}

	// 解析服务器地址
	udpAddr, err := net.ResolveUDPAddr("udp", endpoint)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("解析服务器UDP地址失败: %v", err)
	}

	// 尝试连接
	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("无法连接到服务器UDP端口: %v", err)
	}

	// 设置超时
	udpConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发送测试数据
	_, err = udpConn.Write([]byte("WireGuard Test"))
	if err != nil {
		udpConn.Close()
		return wgtypes.Key{}, fmt.Errorf("发送测试数据失败: %v", err)
	}

	// 关闭连接
	udpConn.Close()
	log.Printf("成功连接到服务器UDP端口")

	// 如果服务器在本地运行，尝试从配置文件获取公钥
	if host == "127.0.0.1" || host == "localhost" {
		// 尝试读取服务器配置文件
		configFile := "wg-server.conf"
		data, err := os.ReadFile(configFile)
		if err == nil {
			// 解析配置文件中的公钥
			content := string(data)
			lines := strings.Split(content, "\n")
			for _, line := range lines {
				line = strings.TrimSpace(line)
				if strings.HasPrefix(line, "PublicKey=") || strings.HasPrefix(line, "PublicKey =") {
					pubKeyStr := strings.TrimPrefix(line, "PublicKey=")
					pubKeyStr = strings.TrimPrefix(pubKeyStr, "PublicKey =")
					pubKeyStr = strings.TrimSpace(pubKeyStr)
					pubKey, err := wireguard.ParseKey(pubKeyStr)
					if err == nil {
						log.Printf("从配置文件获取到服务器公钥: %s", pubKey.String())
						return pubKey, nil
					}
				}
			}
		}
	}

	// 尝试从注册服务获取服务器公钥
	regPort, _ := strconv.Atoi(portStr)
	regPort++ // 注册服务端口 = WireGuard端口 + 1
	regEndpoint := fmt.Sprintf("%s:%d", host, regPort)

	log.Printf("尝试从注册服务获取服务器公钥: %s", regEndpoint)

	// 解析服务器地址
	regAddr, err := net.ResolveUDPAddr("udp", regEndpoint)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("解析注册服务地址失败: %v", err)
	}

	// 尝试连接
	regConn, err := net.DialUDP("udp", nil, regAddr)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("无法连接到注册服务: %v", err)
	}
	defer regConn.Close()

	// 设置超时
	regConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发送公钥请求
	_, err = regConn.Write([]byte("GET_PUBLIC_KEY"))
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("发送公钥请求失败: %v", err)
	}

	// 接收响应
	buf := make([]byte, 1024)
	n, _, err := regConn.ReadFromUDP(buf)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("接收响应失败: %v", err)
	}

	// 解析公钥
	pubKeyStr := string(buf[:n])
	pubKey, err := wireguard.ParseKey(pubKeyStr)
	if err != nil {
		return wgtypes.Key{}, fmt.Errorf("解析服务器公钥失败: %v", err)
	}

	log.Printf("从注册服务获取到服务器公钥: %s", pubKey.String())
	return pubKey, nil
}

// RegistrationRequest 客户端注册请求结构
type RegistrationRequest struct {
	Command    string `json:"command"`
	PublicKey  string `json:"public_key"`
	Secret     string `json:"secret"`
	ClientName string `json:"client_name"`
}

// RegistrationResponse 客户端注册响应结构
type RegistrationResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
	IP      string `json:"ip,omitempty"`
}

// registerClientWithServer 向服务器注册客户端
func registerClientWithServer(serverEndpoint string, clientPublicKey wgtypes.Key) (string, error) {
	// 解析服务器地址和端口
	host, portStr, err := net.SplitHostPort(serverEndpoint)
	if err != nil {
		return "", fmt.Errorf("解析服务器地址失败: %v", err)
	}

	// 注册服务端口 = WireGuard端口 + 1
	regPort, _ := strconv.Atoi(portStr)
	regPort++
	regEndpoint := fmt.Sprintf("%s:%d", host, regPort)

	log.Printf("尝试向注册服务注册客户端: %s", regEndpoint)

	// 解析服务器地址
	regAddr, err := net.ResolveUDPAddr("udp", regEndpoint)
	if err != nil {
		return "", fmt.Errorf("解析注册服务地址失败: %v", err)
	}

	// 尝试连接
	regConn, err := net.DialUDP("udp", nil, regAddr)
	if err != nil {
		return "", fmt.Errorf("无法连接到注册服务: %v", err)
	}
	defer regConn.Close()

	// 设置超时
	regConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 创建注册请求
	request := RegistrationRequest{
		Command:    "REGISTER_CLIENT",
		PublicKey:  clientPublicKey.String(),
		Secret:     *regSecret,
		ClientName: *clientName,
	}

	// 序列化请求
	requestJSON, err := json.Marshal(request)
	if err != nil {
		return "", fmt.Errorf("序列化请求失败: %v", err)
	}

	// 发送注册请求
	_, err = regConn.Write(requestJSON)
	if err != nil {
		return "", fmt.Errorf("发送注册请求失败: %v", err)
	}

	// 接收响应
	buf := make([]byte, 1024)
	n, _, err := regConn.ReadFromUDP(buf)
	if err != nil {
		return "", fmt.Errorf("接收响应失败: %v", err)
	}

	// 解析响应
	var response RegistrationResponse
	if err := json.Unmarshal(buf[:n], &response); err != nil {
		return "", fmt.Errorf("解析响应失败: %v", err)
	}

	// 检查响应
	if !response.Success {
		return "", fmt.Errorf("注册失败: %s", response.Message)
	}

	log.Printf("注册成功: %s", response.Message)
	return response.IP, nil
}

// generateNewConfig 生成新的WireGuard配置
func generateNewConfig(endpoint, clientIPStr string) (*wireguard.Config, error) {
	// 生成客户端私钥
	privateKey, err := wireguard.GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	// 根据用户选择的代理模式设置允许的IP
	var allowedIP *net.IPNet
	var parseErr error
	if *fullTunnel {
		// 全局代理模式
		_, allowedIP, parseErr = net.ParseCIDR("0.0.0.0/0")
		log.Printf("使用全局代理模式，所有流量将通过VPN")
	} else {
		// 分流模式，只允许VPN网段的流量
		_, allowedIP, parseErr = net.ParseCIDR("10.9.0.0/24")
		log.Printf("使用分流模式，只允许VPN网段的流量")
	}

	if parseErr != nil {
		return nil, fmt.Errorf("解析允许的IP失败: %v", parseErr)
	}

	// 尝试从服务器获取公钥
	log.Printf("尝试从服务器获取公钥...")
	log.Printf("连接到服务器: %s", endpoint)
	serverPublicKey, err := getServerPublicKey(endpoint)
	if err != nil {
		log.Printf("无法从服务器获取公钥: %v", err)
		log.Printf("使用占位符公钥，连接可能会失败")

		// 尝试使用默认公钥
		if *serverPubKey != "" {
			log.Printf("尝试使用命令行提供的服务器公钥: %s", *serverPubKey)
			parsedKey, parseErr := wireguard.ParseKey(*serverPubKey)
			if parseErr == nil {
				serverPublicKey = parsedKey
				log.Printf("成功使用命令行提供的服务器公钥")
			} else {
				log.Printf("解析命令行提供的服务器公钥失败: %v", parseErr)
				// 使用占位符公钥
				placeholderKey, _ := wireguard.ParseKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
				serverPublicKey = placeholderKey
			}
		} else {
			// 使用占位符公钥
			placeholderKey, _ := wireguard.ParseKey("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=")
			serverPublicKey = placeholderKey
			log.Printf("请使用 -server-pubkey 参数指定服务器公钥")
		}
	} else {
		log.Printf("成功从服务器获取公钥: %s", serverPublicKey.String())
	}

	// 创建配置
	config := &wireguard.Config{
		PrivateKey:          privateKey,
		PublicKey:           serverPublicKey, // 设置服务器公钥
		Endpoint:            endpoint,
		AllowedIPs:          []net.IPNet{*allowedIP},
		PersistentKeepalive: 25, // 每25秒发送一次keepalive包
	}

	// 生成客户端公钥
	clientPublicKey := wireguard.GeneratePublicKey(privateKey)
	log.Printf("生成的客户端公钥: %s", clientPublicKey.String())

	// 向服务器注册客户端
	assignedIP, err := registerClientWithServer(endpoint, clientPublicKey)
	if err != nil {
		log.Printf("向服务器注册客户端失败: %v", err)
		log.Printf("请手动将公钥添加到服务器配置中")
	} else {
		log.Printf("客户端已成功注册到服务器，分配IP: %s", assignedIP)

		// 如果服务器分配了IP地址，使用这个IP地址
		if assignedIP != "" {
			*clientIP = assignedIP + "/24"
			log.Printf("使用服务器分配的IP地址: %s", *clientIP)
		}
	}

	return config, nil
}

// configureTunIP 配置TUN设备IP地址
func configureTunIP(tunName string, ip net.IP, ipNet *net.IPNet) error {
	// 设置一个适合VPN的MTU值
	mtu := 1380 // 使用更保守的MTU值

	// 根据操作系统配置IP地址和MTU
	switch runtime.GOOS {
	case "linux":
		// 使用ip命令配置
		cmd := fmt.Sprintf("ip addr add %s/%d dev %s", ip.String(), maskBits(ipNet.Mask), tunName)
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置IP地址失败: %v", err)
		}

		// 设置MTU值
		cmd = fmt.Sprintf("ip link set dev %s mtu %d", tunName, mtu)
		_, _ = runCommand(cmd)

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

		// 设置MTU值
		cmd = fmt.Sprintf("ifconfig %s mtu %d", tunName, mtu)
		_, _ = runCommand(cmd)

		return nil

	case "windows":
		// 使用PowerShell命令配置
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

		// 先检查是否有冲突的IP地址 - 使用cmd.exe执行ipconfig命令
		checkCmd := "cmd.exe /c \"ipconfig /all\""
		output, _ = runCommand(checkCmd)
		if strings.Contains(output, ip.String()) {
			log.Printf("发现冲突的IP地址: %s，尝试移除", ip.String())
			// 使用netsh命令删除IP地址
			removeCmd := fmt.Sprintf("cmd.exe /c \"netsh interface ip delete address \\\"%s\\\" %s\"", tunName, ip.String())
			_, _ = runCommand(removeCmd)
			// 等待一下，确保IP地址已经被清理
			time.Sleep(1 * time.Second)
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

		// 设置MTU值
		cmd = fmt.Sprintf("netsh interface ipv4 set subinterface \"%s\" mtu=%d store=persistent", tunName, mtu)
		_, _ = runCommand(cmd)

		// 使用PowerShell设置MTU值（备用方法）
		cmd = fmt.Sprintf("Set-NetIPInterface -InterfaceAlias '%s' -NlMtuBytes %d -ErrorAction SilentlyContinue", tunName, mtu)
		_, _ = runCommand(cmd)
		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// runCommand 运行shell命令
func runCommand(cmd string) (string, error) {
	var command *exec.Cmd

	// 检查是否是静默命令
	isSilentCommand := strings.Contains(cmd, "SilentlyContinue") ||
		strings.Contains(cmd, "Remove-NetAdapter") ||
		strings.Contains(cmd, "route delete") ||
		strings.Contains(cmd, "Remove-NetIPAddress") ||
		strings.Contains(cmd, "Remove-NetRoute")

	// 仅在非静默命令时输出日志
	if !isSilentCommand {
		log.Printf("执行命令: %s", cmd)
	}

	if runtime.GOOS == "windows" {
		command = exec.Command("powershell", "-Command", cmd)
	} else {
		command = exec.Command("sh", "-c", cmd)
	}

	output, err := command.CombinedOutput()
	if err != nil {
		// 仅在非静默命令失败时输出错误日志
		if !isSilentCommand {
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

// addRoute 添加路由
func addRoute(network, tunName string) error {
	log.Printf("正在添加路由: %s 通过 %s", network, tunName)

	// 根据操作系统添加路由
	switch runtime.GOOS {
	case "linux":
		cmd := fmt.Sprintf("ip route add %s dev %s", network, tunName)
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("添加路由失败: %v", err)
		}
		return nil

	case "darwin": // macOS
		cmd := fmt.Sprintf("route add -net %s -interface %s", network, tunName)
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("添加路由失败: %v", err)
		}
		return nil

	case "windows":
		// 解析网络和掩码
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			return fmt.Errorf("解析网络失败: %v", err)
		}

		ip := ipNet.IP.String()
		mask := net.IP(ipNet.Mask).String()

		// 先检查当前路由表
		checkCmd := "route print"
		routeOutput, _ := runCommand(checkCmd)
		log.Printf("当前路由表(摘要):\n%s", truncateOutput(routeOutput, 20))

		// 获取TUN设备的IP地址作为网关
		tunIP, err := getTunIP(tunName)
		if err != nil {
			// 如果无法获取TUN设备IP，尝试使用默认网关
			log.Printf("无法获取TUN设备IP，将使用默认网关: %v", err)

			// 先删除可能存在的路由
			deleteCmd := fmt.Sprintf("route delete %s", ip)
			_, _ = runCommand(deleteCmd)
			time.Sleep(500 * time.Millisecond)

			// 使用非常低的metric值确保优先级最高
			cmd := fmt.Sprintf("route add %s mask %s 0.0.0.0 metric 1", ip, mask)
			_, err = runCommand(cmd)
			if err != nil {
				// 如果失败，尝试使用PowerShell命令
				psCmd := fmt.Sprintf("New-NetRoute -DestinationPrefix %s/%d -NextHop 0.0.0.0 -RouteMetric 1 -ErrorAction SilentlyContinue",
					ip, maskBits(ipNet.Mask))
				_, err = runCommand(psCmd)
				if err != nil {
					return fmt.Errorf("添加路由失败: %v", err)
				}
			}
		} else {
			// 先删除可能存在的路由
			deleteCmd := fmt.Sprintf("route delete %s", ip)
			_, _ = runCommand(deleteCmd)
			time.Sleep(500 * time.Millisecond)

			// 使用TUN设备IP作为网关
			// 使用cmd.exe执行route命令，避免在PowerShell中的转义问题
			cmd := fmt.Sprintf("cmd.exe /c \"route add %s mask %s %s metric 1\"", ip, mask, tunIP)
			_, err = runCommand(cmd)
			if err != nil {
				// 如果失败，尝试使用PowerShell命令
				psCmd := fmt.Sprintf("New-NetRoute -DestinationPrefix %s/%d -InterfaceAlias '%s' -NextHop %s -RouteMetric 1 -ErrorAction SilentlyContinue",
					ip, maskBits(ipNet.Mask), tunName, tunIP)
				_, err = runCommand(psCmd)
				if err != nil {
					return fmt.Errorf("添加路由失败: %v", err)
				}
			}
		}

		// 验证路由是否添加成功
		verifyCmd := fmt.Sprintf("route print %s", ip)
		verifyOutput, _ := runCommand(verifyCmd)
		if strings.Contains(verifyOutput, ip) {
			log.Printf("路由添加成功: %s", ip)
		} else {
			log.Printf("警告: 无法验证路由是否添加成功: %s", ip)
		}

		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// truncateOutput 截断输出，只显示前几行
func truncateOutput(output string, maxLines int) string {
	lines := strings.Split(output, "\n")
	if len(lines) <= maxLines {
		return output
	}

	return strings.Join(lines[:maxLines], "\n") + "\n... (输出已截断)"
}

// getDefaultGateway 获取默认网关
func getDefaultGateway() (string, error) {
	switch runtime.GOOS {
	case "windows":
		// 方法1: 使用PowerShell
		cmd := "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.RouteMetric -ne 1 } | Select-Object -First 1 -ExpandProperty NextHop"
		output, err := runCommand(cmd)
		if err == nil {
			gateway := strings.TrimSpace(output)
			if gateway != "" {
				return gateway, nil
			}
		}

		// 方法2: 使用route命令
		cmd = "cmd.exe /c \"route print 0.0.0.0 | findstr 0.0.0.0 | findstr /v 127.0.0.1 | findstr /v 0.0.0.0/0\""
		output, _ = runCommand(cmd)
		lines := strings.Split(output, "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 {
				return fields[2], nil
			}
		}

		// 方法3: 使用ipconfig
		cmd = "ipconfig | findstr /i \"Default Gateway\""
		output, _ = runCommand(cmd)
		lines = strings.Split(output, "\n")
		for _, line := range lines {
			if strings.Contains(line, "Default Gateway") {
				parts := strings.Split(line, ":")
				if len(parts) >= 2 {
					return strings.TrimSpace(parts[1]), nil
				}
			}
		}

		return "", fmt.Errorf("无法获取默认网关")

	case "linux":
		// 使用ip route命令
		cmd := "ip route | grep default | awk '{print $3}'"
		output, err := runCommand(cmd)
		if err == nil {
			gateway := strings.TrimSpace(output)
			if gateway != "" {
				return gateway, nil
			}
		}

		return "", fmt.Errorf("无法获取默认网关")

	case "darwin": // macOS
		// 使用route命令
		cmd := "route -n get default | grep gateway | awk '{print $2}'"
		output, err := runCommand(cmd)
		if err == nil {
			gateway := strings.TrimSpace(output)
			if gateway != "" {
				return gateway, nil
			}
		}

		return "", fmt.Errorf("无法获取默认网关")

	default:
		return "", fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// cleanupNetworkResources 清理可能冲突的网络资源
func cleanupNetworkResources() {
	// 清理可能冲突的IP地址
	ip, ipNet, err := net.ParseCIDR(*clientIP)
	if err == nil {
		// 在Windows上，我们使用PowerShell命令来清理IP地址
		// 这样可以避免中文和特殊字符的问题
		if runtime.GOOS == "windows" {
			// 获取所有网络接口的索引
			cmd := "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty ifIndex"
			output, _ := runCommand(cmd)
			if output != "" {
				// 遍历所有网络接口索引，尝试删除IP地址
				indices := strings.Split(strings.TrimSpace(output), "\n")
				for _, index := range indices {
					index = strings.TrimSpace(index)
					if index != "" {
						// 使用PowerShell命令删除IP地址
						deleteCmd := fmt.Sprintf("Get-NetIPAddress -InterfaceIndex %s -IPAddress %s -ErrorAction SilentlyContinue | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue", index, ip.String())
						_, _ = runCommand(deleteCmd)
					}
				}
			}

			// 清理路由 - 使用PowerShell命令
			cmd = fmt.Sprintf("Remove-NetRoute -DestinationPrefix %s -Confirm:$false -ErrorAction SilentlyContinue", ipNet.String())
			_, _ = runCommand(cmd)

			// 备用方法：使用route命令
			cmd = fmt.Sprintf("route delete %s", ipNet.IP.String())
			_, _ = runCommand(cmd)
		} else {
			// 在非Windows系统上使用原来的方法
			switch runtime.GOOS {
			case "linux":
				cmd := fmt.Sprintf("ip addr del %s dev $(ip route | grep %s | awk '{print $3}')", ip.String(), ipNet.IP.String())
				_, _ = runCommand(cmd)

				cmd = fmt.Sprintf("ip route del %s", ipNet.String())
				_, _ = runCommand(cmd)
			case "darwin":
				cmd := fmt.Sprintf("ifconfig $(route -n get %s | grep interface | awk '{print $2}') inet %s delete", ipNet.IP.String(), ip.String())
				_, _ = runCommand(cmd)

				cmd = fmt.Sprintf("route delete -net %s", ipNet.String())
				_, _ = runCommand(cmd)
			}
		}
	}

	// 等待一下，确保资源已经被清理
	time.Sleep(1 * time.Second)
}

// cleanupOrphanedAdapters 清理孤立的WireGuard适配器
func cleanupOrphanedAdapters() {
	// 查找客户端的WireGuard适配器，避免清理服务端的适配器
	cmd := "Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*' -and $_.Name -like 'WireGuardClient*'} | Select-Object -ExpandProperty Name"
	output, err := runCommand(cmd)
	if err != nil {
		// 如果查询失败，直接返回
		return
	}

	// 如果有适配器，尝试清理
	adapterNames := strings.Split(strings.TrimSpace(output), "\n")
	for _, name := range adapterNames {
		name = strings.TrimSpace(name)
		if name != "" && name != "WireGuardServer" { // 确保不清理服务端适配器
			log.Printf("检测到孤立的WireGuard客户端适配器: %s，尝试清理", name)

			// 尝试移除适配器，但不显示错误
			removeCmd := fmt.Sprintf("Remove-NetAdapter -Name \"%s\" -Confirm:$false -ErrorAction SilentlyContinue", name)
			_, _ = runCommand(removeCmd)
		}
	}
}

// getTunIP 获取TUN设备的IP地址
func getTunIP(tunName string) (string, error) {
	switch runtime.GOOS {
	case "windows":
		// 获取接口索引
		cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.InterfaceDescription -like '*WireGuard*' -or $_.InterfaceDescription -like '*TAP-Windows*' -or $_.InterfaceAlias -eq '%s'} | Select-Object -ExpandProperty ifIndex", tunName)
		output, err := runCommand(cmd)
		if err != nil {
			return "", fmt.Errorf("获取网络接口失败: %v", err)
		}

		// 解析接口索引
		ifIndex := strings.TrimSpace(output)
		if ifIndex == "" {
			return "", fmt.Errorf("无法找到WireGuard网络接口")
		}

		// 获取IP地址
		cmd = fmt.Sprintf("Get-NetIPAddress -InterfaceIndex %s -AddressFamily IPv4 | Select-Object -ExpandProperty IPAddress", ifIndex)
		output, err = runCommand(cmd)
		if err != nil {
			return "", fmt.Errorf("获取IP地址失败: %v", err)
		}

		// 解析IP地址
		ip := strings.TrimSpace(output)
		if ip == "" {
			return "", fmt.Errorf("无法获取TUN设备IP地址")
		}

		return ip, nil

	case "linux":
		cmd := fmt.Sprintf("ip addr show %s | grep 'inet ' | awk '{print $2}' | cut -d/ -f1", tunName)
		output, err := runCommand(cmd)
		if err != nil {
			return "", fmt.Errorf("获取IP地址失败: %v", err)
		}

		ip := strings.TrimSpace(output)
		if ip == "" {
			return "", fmt.Errorf("无法获取TUN设备IP地址")
		}

		return ip, nil

	case "darwin": // macOS
		cmd := fmt.Sprintf("ifconfig %s | grep 'inet ' | awk '{print $2}'", tunName)
		output, err := runCommand(cmd)
		if err != nil {
			return "", fmt.Errorf("获取IP地址失败: %v", err)
		}

		ip := strings.TrimSpace(output)
		if ip == "" {
			return "", fmt.Errorf("无法获取TUN设备IP地址")
		}

		return ip, nil

	default:
		return "", fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// optimizeRouting 优化路由
func optimizeRouting(tunName string) {
	log.Printf("正在优化路由...")

	// 百度的IP范围
	baiduIPs := []string{
		"39.156.66.0/24",  // 百度部分IP范围
		"220.181.38.0/24", // 百度部分IP范围
	}

	// 阿里云的IP范围
	aliIPs := []string{
		"47.92.0.0/16",  // 阿里云部分IP范围
		"106.11.0.0/16", // 阿里云部分IP范围
	}

	// 腾讯的IP范围
	tencentIPs := []string{
		"119.28.0.0/16",  // 腾讯云部分IP范围
		"123.207.0.0/16", // 腾讯云部分IP范围
	}

	// 合并所有国内IP范围
	chinaIPs := append(baiduIPs, aliIPs...)
	chinaIPs = append(chinaIPs, tencentIPs...)

	switch runtime.GOOS {
	case "windows":
		// 获取默认网关
		cmd := "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Where-Object { $_.RouteMetric -ne 1 } | Select-Object -First 1 -ExpandProperty NextHop"
		defaultGateway, err := runCommand(cmd)
		if err != nil || defaultGateway == "" {
			// 如果上面的方法失败，尝试使用其他方法
			cmd = "cmd.exe /c \"route print 0.0.0.0 | findstr 0.0.0.0 | findstr /v 127.0.0.1 | findstr /v 0.0.0.0/0\""
			output, _ := runCommand(cmd)
			lines := strings.Split(output, "\n")
			for _, line := range lines {
				fields := strings.Fields(line)
				if len(fields) >= 3 {
					defaultGateway = fields[2]
					break
				}
			}
		}

		defaultGateway = strings.TrimSpace(defaultGateway)
		if defaultGateway == "" {
			log.Printf("无法获取默认网关，路由优化失败")
			return
		}

		log.Printf("默认网关: %s", defaultGateway)

		// 为国内网站添加直接路由，不经过VPN
		for _, ipRange := range chinaIPs {
			// 解析IP范围
			_, ipNet, err := net.ParseCIDR(ipRange)
			if err != nil {
				log.Printf("解析IP范围失败: %s, %v", ipRange, err)
				continue
			}

			// 删除可能存在的路由
			deleteCmd := fmt.Sprintf("route delete %s", ipNet.IP.String())
			_, _ = runCommand(deleteCmd)

			// 添加直接路由，使用默认网关，设置较低的metric值
			addCmd := fmt.Sprintf("cmd.exe /c \"route add %s mask %s %s metric 5\"",
				ipNet.IP.String(),
				net.IP(ipNet.Mask).String(),
				defaultGateway)
			_, err = runCommand(addCmd)
			if err != nil {
				log.Printf("添加国内直接路由失败: %s, %v", ipRange, err)
			} else {
				log.Printf("已为 %s 添加直接路由", ipRange)
			}
		}

	case "linux":
		// 获取默认网关
		cmd := "ip route | grep default | awk '{print $3}'"
		defaultGateway, err := runCommand(cmd)
		defaultGateway = strings.TrimSpace(defaultGateway)
		if err != nil || defaultGateway == "" {
			log.Printf("无法获取默认网关，路由优化失败")
			return
		}

		// 为国内网站添加直接路由
		for _, ipRange := range chinaIPs {
			cmd = fmt.Sprintf("ip route add %s via %s", ipRange, defaultGateway)
			_, err = runCommand(cmd)
			if err != nil {
				log.Printf("添加国内直接路由失败: %s, %v", ipRange, err)
			} else {
				log.Printf("已为 %s 添加直接路由", ipRange)
			}
		}

	case "darwin": // macOS
		// 获取默认网关
		cmd := "route -n get default | grep gateway | awk '{print $2}'"
		defaultGateway, err := runCommand(cmd)
		defaultGateway = strings.TrimSpace(defaultGateway)
		if err != nil || defaultGateway == "" {
			log.Printf("无法获取默认网关，路由优化失败")
			return
		}

		// 为国内网站添加直接路由
		for _, ipRange := range chinaIPs {
			cmd = fmt.Sprintf("route add -net %s %s", ipRange, defaultGateway)
			_, err = runCommand(cmd)
			if err != nil {
				log.Printf("添加国内直接路由失败: %s, %v", ipRange, err)
			} else {
				log.Printf("已为 %s 添加直接路由", ipRange)
			}
		}
	}

	log.Printf("路由优化完成")
}

// optimizeTCPParameters 优化TCP参数
func optimizeTCPParameters() {
	log.Printf("正在优化TCP参数...")

	switch runtime.GOOS {
	case "windows":
		// 调整TCP窗口大小
		cmd := "netsh interface tcp set global autotuninglevel=normal"
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("调整TCP自动调优级别失败: %v", err)
		}

		// 调整TCP拥塞控制算法
		cmd = "netsh interface tcp set global congestionprovider=ctcp"
		_, err = runCommand(cmd)
		if err != nil {
			log.Printf("调整TCP拥塞控制算法失败: %v", err)
		}

		// 启用TCP延迟确认
		cmd = "netsh interface tcp set global ecncapability=enabled"
		_, _ = runCommand(cmd)

	case "linux":
		// 调整TCP窗口大小
		cmd := "sysctl -w net.ipv4.tcp_wmem='4096 65536 4194304'"
		_, _ = runCommand(cmd)

		cmd = "sysctl -w net.ipv4.tcp_rmem='4096 87380 4194304'"
		_, _ = runCommand(cmd)

		// 调整TCP拥塞控制算法
		cmd = "sysctl -w net.ipv4.tcp_congestion_control=bbr"
		_, _ = runCommand(cmd)

	case "darwin": // macOS
		// macOS上的TCP参数调整相对有限
		cmd := "sysctl -w net.inet.tcp.win_scale_factor=8"
		_, _ = runCommand(cmd)
	}

	log.Printf("TCP参数优化完成")
}

// configureDNS 配置DNS服务器
func configureDNS(tunName string) error {
	log.Printf("正在配置DNS服务器...")

	switch runtime.GOOS {
	case "windows":
		// 获取TUN接口索引
		cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.Name -eq '%s' -or $_.InterfaceDescription -like '*WireGuard*'} | Select-Object -ExpandProperty ifIndex", tunName)
		output, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("获取TUN接口索引失败: %v", err)
		}

		ifIndex := strings.TrimSpace(output)
		if ifIndex == "" {
			return fmt.Errorf("无法获取TUN接口索引")
		}

		// 配置DNS服务器(使用Google DNS)
		cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ServerAddresses '8.8.8.8','8.8.4.4'", ifIndex) // Google DNS
		_, err = runCommand(cmd)
		if err != nil {
			log.Printf("使用PowerShell配置DNS服务器失败: %v", err)

			// 尝试使用netsh命令配置DNS
			cmd = fmt.Sprintf("netsh interface ip set dns name=\"%s\" static 8.8.8.8 primary", tunName) // Google DNS
			_, err = runCommand(cmd)
			if err != nil {
				return fmt.Errorf("配置DNS服务器失败: %v", err)
			}

			cmd = fmt.Sprintf("netsh interface ip add dns name=\"%s\" 8.8.4.4 index=2", tunName) // Google DNS
			_, _ = runCommand(cmd)
		}

		log.Printf("已为接口%s配置DNS服务器", tunName)

		// 刷新DNS缓存
		cmd = "ipconfig /flushdns"
		_, _ = runCommand(cmd)

		return nil

	case "linux":
		// 在Linux上修改resolv.conf
		cmd := "echo 'nameserver 8.8.8.8\nnameserver 8.8.4.4' > /etc/resolv.conf" // Google DNS
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置DNS服务器失败: %v", err)
		}
		return nil

	case "darwin": // macOS
		// 在macOS上使用networksetup命令
		cmd := fmt.Sprintf("networksetup -setdnsservers %s 8.8.8.8 8.8.4.4", tunName) // Google DNS
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置DNS服务器失败: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// testInternetConnection 测试互联网连接
func testInternetConnection() {
	log.Printf("正在测试互联网连接...")

	// 测试DNS解析 - 使用百度域名
	cmd := "nslookup baidu.com"
	output, err := runCommand(cmd)
	if err != nil {
		log.Printf("DNS解析测试(百度)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("DNS解析测试(百度)成功")
	}

	// 测试DNS解析 - 使用Google域名
	cmd = "nslookup google.com"
	output, err = runCommand(cmd)
	if err != nil {
		log.Printf("DNS解析测试(Google)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("DNS解析测试(Google)成功")
	}

	// 测试ICMP连接 - 使用Google DNS
	cmd = "ping -n 3 8.8.8.8"
	output, err = runCommand(cmd)
	if err != nil {
		log.Printf("ICMP连接测试(Google DNS)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("ICMP连接测试(Google DNS)成功")
	}

	// 测试HTTP连接 - 使用百度
	if runtime.GOOS == "windows" {
		// Windows上使用PowerShell的Invoke-WebRequest
		cmd = "Invoke-WebRequest -Uri 'https://www.baidu.com' -UseBasicParsing -Method Head | Select-Object -ExpandProperty StatusCode"
		output, err = runCommand(cmd)
		if err != nil {
			// 如果失败，尝试使用系统自带的curl
			cmd = "cmd.exe /c curl -s -o nul -w \"HTTP状态码: %{http_code}\" https://www.baidu.com"
			output, err = runCommand(cmd)
		}
	} else {
		// 其他系统使用curl
		cmd = "curl -s -o /dev/null -w \"HTTP状态码: %{http_code}\" https://www.baidu.com"
		output, err = runCommand(cmd)
	}

	if err != nil {
		log.Printf("HTTP连接测试(百度)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("HTTP连接测试(百度)成功: %s", output)
	}

	// 测试HTTP连接 - 使用Google
	if runtime.GOOS == "windows" {
		// Windows上使用PowerShell的Invoke-WebRequest
		cmd = "Invoke-WebRequest -Uri 'https://www.google.com' -UseBasicParsing -Method Head | Select-Object -ExpandProperty StatusCode"
		output, err = runCommand(cmd)
		if err != nil {
			// 如果失败，尝试使用系统自带的curl
			cmd = "cmd.exe /c curl -s -o nul -w \"HTTP状态码: %{http_code}\" https://www.google.com"
			output, err = runCommand(cmd)
		}
	} else {
		// 其他系统使用curl
		cmd = "curl -s -o /dev/null -w \"HTTP状态码: %{http_code}\" https://www.google.com"
		output, err = runCommand(cmd)
	}

	if err != nil {
		log.Printf("HTTP连接测试(Google)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("HTTP连接测试(Google)成功: %s", output)
	}
}
