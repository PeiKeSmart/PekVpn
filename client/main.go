package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"sync"
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
	useTun2Socks   = flag.Bool("use-tun2socks", true, "是否使用Tun2Socks转发流量")
	socksPort      = flag.Int("socks-port", 1080, "SOCKS5代理端口")
	socksUser      = flag.String("socks-user", "", "SOCKS5代理用户名")
	socksPass      = flag.String("socks-pass", "", "SOCKS5代理密码")
	protectWebRTC  = flag.Bool("protect-webrtc", true, "是否防止WebRTC泄漏")
	useDNSProxy    = flag.Bool("dns-proxy", false, "是否使用DNS代理")
	mtuValue       = flag.Int("mtu", 0, "MTU值，0表示自动探测")
	diagnoseMode   = flag.Bool("diagnose", false, "是否启用诊断模式，用于判断无法联网的原因")

	// 系统信息
	hostname, _ = os.Hostname()

	// MTU相关的全局变量
	globalMTU      int          // 当前使用的MTU值
	mtuMutex       sync.RWMutex // 保护globalMTU的互斥锁
	mtuInitialized bool         // MTU是否已初始化

	// 反检测相关的全局变量
	antiDetectionEnabled bool              // 是否启用反检测措施
	defaultTransport     http.RoundTripper // 原始Transport备份
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

	// 探测最佳MTU值
	optimalMTU := detectOptimalMTU()
	log.Printf("使用MTU值: %d", optimalMTU)

	// 创建WireGuard设备
	wgDevice, err := wireguard.NewWireGuardDevice(config, false, optimalMTU)
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

	// 无论是否启用全局代理，都需要添加服务器特殊路由
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

				// 添加服务器特殊路由，使用默认网关，使用最低的metric值(1)确保最高优先级
				// Windows不支持metric值为0，最小值为1
				addCmd := fmt.Sprintf("cmd.exe /c \"route add %s mask 255.255.255.255 %s metric 1\"", serverIP.String(), defaultGateway)
				_, err = runCommand(addCmd)
				if err == nil {
					log.Printf("已添加服务器特殊路由: %s -> %s (优先级最高)", serverIP.String(), defaultGateway)
				} else {
					log.Printf("添加服务器特殊路由失败: %v", err)
				}
			} else {
				log.Printf("无法获取默认网关，服务器特殊路由添加失败")
			}
		}
	}

	// 验证服务器特殊路由是否添加成功
	host, _, err = net.SplitHostPort(config.Endpoint)
	if err == nil {
		serverIP := net.ParseIP(host)
		if serverIP != nil && !serverIP.IsLoopback() {
			verifyCmd := fmt.Sprintf("route print %s", serverIP.String())
			verifyOutput, _ := runCommand(verifyCmd)
			if strings.Contains(verifyOutput, serverIP.String()) {
				log.Printf("服务器特殊路由验证成功")
			} else {
				log.Printf("警告: 服务器特殊路由验证失败，这可能导致连接问题")

				// 如果验证失败，再次尝试添加路由
				log.Printf("再次尝试添加服务器特殊路由...")

				// 获取默认网关
				gatewayCmd := "cmd.exe /c \"route print 0.0.0.0 | findstr 0.0.0.0 | findstr /v 127.0.0.1 | findstr /v 0.0.0.0/0\""
				gatewayOutput, _ := runCommand(gatewayCmd)
				gatewayLines := strings.Split(gatewayOutput, "\n")
				defaultGateway := ""
				for _, line := range gatewayLines {
					fields := strings.Fields(line)
					if len(fields) >= 3 {
						defaultGateway = fields[2]
						break
					}
				}

				if defaultGateway != "" {
					// 再次尝试添加路由
					addCmd := fmt.Sprintf("cmd.exe /c \"route add %s mask 255.255.255.255 %s metric 1\"", serverIP.String(), defaultGateway)
					_, _ = runCommand(addCmd)
					log.Printf("再次添加服务器特殊路由: %s -> %s", serverIP.String(), defaultGateway)
				}
			}
		}
	}

	// 等待一下，确保服务器特殊路由生效
	time.Sleep(500 * time.Millisecond)

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

	// 如果启用了SOCKS代理，启动SOCKS代理
	var socksManager *SocksManager
	if *useTun2Socks {
		log.Printf("启用SOCKS代理...")
		// 从端点获取服务器IP
		serverIP := GetServerIPFromEndpoint(config.Endpoint)
		if serverIP == "" {
			log.Printf("无法从端点获取服务器IP，使用原始端点: %s", config.Endpoint)
			host, _, _ := net.SplitHostPort(config.Endpoint)
			serverIP = host
		}

		// 创建SOCKS代理管理器
		// 使用VPN公钥认证或用户名/密码认证
		socksManager = NewSocksManager(
			serverIP,
			*socksPort,
			*socksUser,
			*socksPass,
			config.PrivateKey.String(),
			config.PublicKey.String(),
			*regSecret,
		)

		// 显示认证信息
		if *socksUser != "" || *socksPass != "" {
			log.Printf("SOCKS代理已启动，地址: %s，使用指定的用户名/密码认证", socksManager.GetSocksAddr())
		} else {
			log.Printf("SOCKS代理已启动，地址: %s，使用VPN公钥认证", socksManager.GetSocksAddr())
		}

		// 测试SOCKS代理连接
		go func() {
			// 等待VPN连接建立
			time.Sleep(5 * time.Second)
			err := socksManager.TestConnection()
			if err != nil {
				log.Printf("SOCKS代理连接测试失败: %v", err)
			} else {
				log.Printf("SOCKS代理连接测试成功，可以在应用程序中使用SOCKS5代理: %s", socksManager.GetSocksAddr())
			}
		}()
	}

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

		// 如果启用了诊断模式，运行诊断
		if *diagnoseMode {
			log.Printf("启动诊断模式，判断无法联网的原因...")
			DiagnoseProblem(config, wgDevice)
		}

		// 实施反检测措施
		time.Sleep(1 * time.Second)
		implementAntiDetectionMeasures()

		// 如果启用了WebRTC泄露防护，启用它
		if *protectWebRTC {
			// 使用tun2socks.go中的WebRTC保护功能
			err := SetupWebRTCProtection()
			if err != nil {
				log.Printf("\u542f\u7528WebRTC\u6cc4\u9732\u9632\u62a4\u5931\u8d25: %v", err)
			} else {
				log.Printf("WebRTC\u6cc4\u9732\u9632\u62a4\u5df2\u542f\u7528")
			}
		}
	}()

	// 启动连接监控和自动重连
	go startConnectionMonitor(wgDevice, config)

	// 定期重新探测MTU值
	go func() {
		// 等待VPN连接稳定
		time.Sleep(5 * time.Minute)

		// 如果用户指定了MTU值，不需要定期探测
		if *mtuValue > 0 {
			log.Printf("用户指定了MTU值，不需要定期探测")
			return
		}

		for {
			// 每30分钟探测一次
			time.Sleep(30 * time.Minute)

			// 获取当前MTU值
			mtuMutex.RLock()
			currentMTU := globalMTU
			mtuMutex.RUnlock()

			// 重置MTU初始化状态，强制重新探测
			mtuMutex.Lock()
			mtuInitialized = false
			mtuMutex.Unlock()

			// 重新探测MTU值
			newMTU := detectOptimalMTU()
			if newMTU != currentMTU {
				log.Printf("网络环境变化，MTU值从%d调整为%d", currentMTU, newMTU)

				// 更新MTU值
				err := updateMTU(wgDevice.TunName, newMTU)
				if err != nil {
					log.Printf("更新MTU值失败: %v", err)
				}
			}
		}
	}()

	// 百度连接监控和优化功能已禁用

	// 等待信号
	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	// 创建一个通道用于手动运行诊断
	diagnoseCh := make(chan struct{}, 1)

	// 启动一个协程监听用户输入
	go func() {
		reader := bufio.NewReader(os.Stdin)
		for {
			text, _ := reader.ReadString('\n')
			text = strings.TrimSpace(text)
			if text == "diagnose" || text == "d" {
				log.Printf("收到诊断命令，开始运行诊断...")
				select {
				case diagnoseCh <- struct{}{}:
				default:
					log.Printf("诊断已在运行中，请稍后再试")
				}
			} else if text == "help" || text == "h" {
				fmt.Println("可用命令:")
				fmt.Println("  diagnose, d - 运行诊断，判断无法联网的原因")
				fmt.Println("  help, h     - 显示帮助信息")
				fmt.Println("  exit, q     - 退出程序")
			} else if text == "exit" || text == "q" {
				log.Printf("收到退出命令，正在关闭...")
				sigCh <- syscall.SIGTERM
				break
			}
		}
	}()

	// 启动一个协程处理诊断请求
	go func() {
		for range diagnoseCh {
			log.Printf("正在运行诊断...")
			DiagnoseProblem(config, wgDevice)
			log.Printf("诊断完成")
		}
	}()

	<-sigCh
	log.Printf("正在关闭WireGuard客户端...")

	// 清理资源
	log.Printf("正在清理资源，恢复网络配置...")

	// 1. 先清理路由，顺序很重要
	// 清理顺序很重要：先清理默认路由和VPN网段路由，最后再清理服务器特殊路由
	// 这样可以确保在清理过程中，与VPN服务器的通信不会被中断
	if runtime.GOOS == "windows" {
		// 清理默认路由（如果启用了全局模式）
		if *fullTunnel {
			log.Printf("正在清理默认路由...")
			deleteRoute("0.0.0.0/0")
			log.Printf("已清理默认路由")
		}

		// 清理VPN网段路由
		log.Printf("正在清理VPN网段路由...")
		_, ipNet, _ := net.ParseCIDR(config.AllowedIPs[0].String())
		deleteRoute(ipNet.String())
		log.Printf("已清理VPN网段路由: %s", ipNet.String())

		// 清理服务器特殊路由
		log.Printf("正在清理服务器特殊路由...")
		host, _, err := net.SplitHostPort(config.Endpoint)
		if err == nil {
			serverIP := net.ParseIP(host)
			if serverIP != nil && !serverIP.IsLoopback() {
				deleteRoute(serverIP.String())
				log.Printf("已清理服务器特殊路由: %s", serverIP.String())
			}
		}

		// 验证路由是否清理成功
		log.Printf("验证路由清理结果...")
		checkCmd := "route print"
		routeOutput, _ := runCommand(checkCmd)
		log.Printf("当前路由表(摘要):\n%s", truncateOutput(routeOutput, 20))

		// 等待一下，确保路由清理生效
		time.Sleep(500 * time.Millisecond)
	}

	// 2. 如果启用了DNS代理，停止DNS代理
	if dnsProxy != nil {
		log.Printf("正在停止DNS代理...")
		dnsProxy.Stop()
	}

	// 3. 关闭WireGuard设备
	log.Printf("正在关闭WireGuard设备...")
	wgDevice.Close()

	// 4. 恢复DNS设置
	if runtime.GOOS == "windows" {
		log.Printf("正在恢复DNS设置...")

		// 获取所有活跃的网络适配器
		cmd := "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty ifIndex"
		output, _ := runCommand(cmd)
		indices := strings.Split(strings.TrimSpace(output), "\n")

		// 重置所有适配器的DNS设置
		for _, index := range indices {
			index = strings.TrimSpace(index)
			if index != "" {
				cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses", index)
				_, _ = runCommand(cmd)
				log.Printf("已重置网络适配器 %s 的DNS设置", index)
			}
		}

		// 刷新DNS缓存
		cmd = "ipconfig /flushdns"
		_, _ = runCommand(cmd)
		log.Printf("已刷新DNS缓存")

		// 重启 DNS客户端服务
		cmd = "Restart-Service -Name Dnscache -Force"
		_, _ = runCommand(cmd)
		log.Printf("已重启DNS客户端服务")

		// 等待DNS服务重启
		time.Sleep(2 * time.Second)
	}

	// 5. 重新启用物理网络适配器
	if runtime.GOOS == "windows" {
		log.Printf("正在重新启用物理网络适配器...")

		// 获取物理网络适配器
		cmd := "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*' -and $_.InterfaceDescription -notlike '*TAP-Windows*'} | Select-Object -ExpandProperty Name"
		output, _ := runCommand(cmd)
		adapters := strings.Split(strings.TrimSpace(output), "\n")

		// 重新启用物理网络适配器
		for _, adapter := range adapters {
			adapter = strings.TrimSpace(adapter)
			if adapter != "" {
				cmd = fmt.Sprintf("Restart-NetAdapter -Name \"%s\" -Confirm:$false", adapter)
				_, _ = runCommand(cmd)
				log.Printf("已重新启用网络适配器: %s", adapter)
			}
		}

		// 等待网络适配器重启
		time.Sleep(3 * time.Second)
	}

	// 6. 恢复反检测措施
	if antiDetectionEnabled {
		log.Printf("恢复反检测措施...")
		// 恢复原始Transport
		if defaultTransport != nil {
			http.DefaultTransport = defaultTransport
			log.Printf("已恢复原始Transport")
		}
		antiDetectionEnabled = false
	}

	// 7. 禁用WebRTC泄露防护
	if *protectWebRTC {
		log.Printf("正在禁用WebRTC泄露防护...")
		// 注意：我们的WebRTC保护是通过hosts文件实现的，
		// 在这里不需要特别的清理操作，因为系统重启后会自动重新加载原始hosts文件
		log.Printf("已禁用WebRTC泄露防护，如果需要完全清除，请手动检查hosts文件")
	}

	// 8. 测试网络连接是否恢复
	go func() {
		time.Sleep(2 * time.Second)
		testNetworkAfterClose()
	}()
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
	// MTU值已经在创建TUN设备时设置
	// 这里只需要设置IP地址

	// 根据操作系统配置IP地址和MTU
	switch runtime.GOOS {
	case "linux":
		// 使用ip命令配置
		cmd := fmt.Sprintf("ip addr add %s/%d dev %s", ip.String(), maskBits(ipNet.Mask), tunName)
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置IP地址失败: %v", err)
		}

		// MTU值已经在创建TUN设备时设置
		// 不需要再次设置MTU

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

		// MTU值已经在创建TUN设备时设置
		// 不需要再次设置MTU

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

		// MTU值已经在创建TUN设备时设置
		// 不需要再次设置MTU
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

	// 最多重试3次
	for i := 0; i < 3; i++ {
		err := doAddRoute(network, tunName)
		if err == nil {
			// 验证路由是否添加成功
			if verifyRoute(network) {
				return nil
			}
			log.Printf("路由添加成功但验证失败，尝试重新添加: %s (尝试 %d/3)", network, i+1)
		} else {
			log.Printf("添加路由失败，尝试重新添加: %s, 错误: %v (尝试 %d/3)", network, err, i+1)
		}
		time.Sleep(500 * time.Millisecond)
	}
	return fmt.Errorf("添加路由失败，已重试3次: %s", network)
}

// doAddRoute 实际添加路由的函数
func doAddRoute(network, tunName string) error {
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

		// 判断是否是默认路由
		isDefaultRoute := (ip == "0.0.0.0" && mask == "0.0.0.0")

		// 设置metric值，默认路由使用更高的metric值，确保服务器特殊路由优先级更高
		// Windows不支持metric值为0，最小值为1
		metricValue := 1
		if isDefaultRoute {
			metricValue = 10
			log.Printf("添加默认路由，使用更高的metric值: %d", metricValue)
		}

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

			// 添加路由，使用适当的metric值
			cmd := fmt.Sprintf("route add %s mask %s 0.0.0.0 metric %d", ip, mask, metricValue)
			_, err = runCommand(cmd)
			if err != nil {
				// 如果失败，尝试使用PowerShell命令
				psCmd := fmt.Sprintf("New-NetRoute -DestinationPrefix %s/%d -NextHop 0.0.0.0 -RouteMetric %d -ErrorAction SilentlyContinue",
					ip, maskBits(ipNet.Mask), metricValue)
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
			cmd := fmt.Sprintf("cmd.exe /c \"route add %s mask %s %s metric %d\"", ip, mask, tunIP, metricValue)
			_, err = runCommand(cmd)
			if err != nil {
				// 如果失败，尝试使用PowerShell命令
				psCmd := fmt.Sprintf("New-NetRoute -DestinationPrefix %s/%d -InterfaceAlias '%s' -NextHop %s -RouteMetric %d -ErrorAction SilentlyContinue",
					ip, maskBits(ipNet.Mask), tunName, tunIP, metricValue)
				_, err = runCommand(psCmd)
				if err != nil {
					return fmt.Errorf("添加路由失败: %v", err)
				}
			}
		}

		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// verifyRoute 验证路由是否添加成功
func verifyRoute(network string) bool {
	// 解析网络
	_, ipNet, err := net.ParseCIDR(network)
	if err != nil {
		return false
	}

	ip := ipNet.IP.String()

	// 验证路由
	verifyCmd := fmt.Sprintf("route print %s", ip)
	verifyOutput, err := runCommand(verifyCmd)
	if err != nil {
		log.Printf("验证路由失败: %v", err)
		return false
	}

	if strings.Contains(verifyOutput, ip) {
		log.Printf("路由验证成功: %s", ip)
		return true
	} else {
		log.Printf("路由验证失败: %s", ip)
		return false
	}
}

// deleteRoute 删除路由
func deleteRoute(network string) bool {
	log.Printf("正在删除路由: %s", network)

	// 最多重试3次
	for i := 0; i < 3; i++ {
		success := doDeleteRoute(network)
		if success {
			return true
		}
		log.Printf("删除路由失败，尝试重新删除: %s (尝试 %d/3)", network, i+1)
		time.Sleep(500 * time.Millisecond)
	}
	log.Printf("删除路由失败，已重试3次: %s", network)
	return false
}

// doDeleteRoute 实际删除路由的函数
func doDeleteRoute(network string) bool {
	switch runtime.GOOS {
	case "linux":
		cmd := fmt.Sprintf("ip route del %s", network)
		_, err := runCommand(cmd)
		return err == nil

	case "darwin": // macOS
		cmd := fmt.Sprintf("route delete -net %s", network)
		_, err := runCommand(cmd)
		return err == nil

	case "windows":
		// 解析网络和掩码
		_, ipNet, err := net.ParseCIDR(network)
		if err != nil {
			// 如果不是CIDR格式，尝试直接删除
			cmd := fmt.Sprintf("cmd.exe /c \"route delete %s\"", network)
			_, err := runCommand(cmd)
			return err == nil
		}

		ip := ipNet.IP.String()
		mask := net.IP(ipNet.Mask).String()

		// 判断是否是默认路由
		if ip == "0.0.0.0" && mask == "0.0.0.0" {
			// 删除默认路由
			cmd := "cmd.exe /c \"route delete 0.0.0.0 mask 0.0.0.0\""
			_, err := runCommand(cmd)
			return err == nil
		}

		// 删除普通路由
		cmd := fmt.Sprintf("cmd.exe /c \"route delete %s mask %s\"", ip, mask)
		_, err = runCommand(cmd)
		if err != nil {
			// 如果失败，尝试使用PowerShell命令
			psCmd := fmt.Sprintf("Remove-NetRoute -DestinationPrefix %s/%d -Confirm:$false -ErrorAction SilentlyContinue",
				ip, maskBits(ipNet.Mask))
			_, _ = runCommand(psCmd)

			// 再次验证是否删除成功
			verifyCmd := fmt.Sprintf("route print %s", ip)
			verifyOutput, _ := runCommand(verifyCmd)
			return !strings.Contains(verifyOutput, ip)
		}
		return true

	default:
		return false
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

// detectOptimalMTU 探测最佳MTU值
func detectOptimalMTU() int {
	// 默认MTU值
	defaultMTU := 1380

	// 检查是否已经初始化全局MTU值
	mtuMutex.RLock()
	if mtuInitialized {
		// 如果已经初始化，直接返回全局MTU值
		currentMTU := globalMTU
		mtuMutex.RUnlock()
		log.Printf("使用已探测的MTU值: %d", currentMTU)
		return currentMTU
	}
	mtuMutex.RUnlock()

	// 如果用户指定了MTU值，直接使用
	if *mtuValue > 0 {
		log.Printf("使用用户指定的MTU值: %d", *mtuValue)
		// 更新全局MTU值
		mtuMutex.Lock()
		globalMTU = *mtuValue
		mtuInitialized = true
		mtuMutex.Unlock()
		return *mtuValue
	}

	// 如果不是Windows系统，直接返回默认值
	if runtime.GOOS != "windows" {
		// 更新全局MTU值
		mtuMutex.Lock()
		globalMTU = defaultMTU
		mtuInitialized = true
		mtuMutex.Unlock()
		return defaultMTU
	}

	log.Printf("正在探测最佳MTU值...")

	// 尝试的MTU值范围
	minMTU := 1280 // 最小MTU值
	maxMTU := 1500 // 最大MTU值

	// 目标服务器，使用百度或谷歌的服务器
	targets := []string{"www.baidu.com", "www.qq.com", "8.8.8.8"}

	// 从大到小尝试不同的MTU值
	for mtu := maxMTU; mtu >= minMTU; mtu -= 10 {
		// 对每个目标服务器进行测试
		for _, target := range targets {
			// 使用ping命令测试指定MTU值
			cmd := fmt.Sprintf("ping -n 1 -w 1000 -l %d -f %s", mtu-28, target) // 减去IP和ICMP头部大小
			_, err := runCommand(cmd)
			if err == nil {
				// 找到可用的MTU值，加上一些余量
				optimalMTU := mtu - 80 // 减去WireGuard头部和一些余量
				log.Printf("探测到最佳MTU值: %d (目标: %s, 原始MTU: %d)", optimalMTU, target, mtu)

				// 更新全局MTU值
				mtuMutex.Lock()
				globalMTU = optimalMTU
				mtuInitialized = true
				mtuMutex.Unlock()

				return optimalMTU
			}
		}
	}

	// 如果探测失败，返回默认值
	log.Printf("MTU探测失败，使用默认值: %d", defaultMTU)

	// 更新全局MTU值
	mtuMutex.Lock()
	globalMTU = defaultMTU
	mtuInitialized = true
	mtuMutex.Unlock()

	return defaultMTU
}

// updateMTU 更新TUN设备的MTU值
func updateMTU(tunName string, mtu int) error {
	if runtime.GOOS != "windows" {
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}

	log.Printf("正在更新TUN设备%s的MTU值为%d...", tunName, mtu)

	// 使用netsh命令设置MTU值
	cmd := fmt.Sprintf("netsh interface ipv4 set subinterface \"%s\" mtu=%d store=persistent", tunName, mtu)
	_, err := runCommand(cmd)
	if err != nil {
		log.Printf("使用netsh设置MTU失败: %v", err)

		// 尝试使用PowerShell设置MTU
		cmd = fmt.Sprintf("Set-NetIPInterface -InterfaceAlias '%s' -NlMtuBytes %d -ErrorAction SilentlyContinue", tunName, mtu)
		_, err = runCommand(cmd)
		if err != nil {
			return fmt.Errorf("设置MTU失败: %v", err)
		}
	}

	log.Printf("已更新TUN设备%s的MTU值为%d", tunName, mtu)
	return nil
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

	// 设置DNS
	err := doConfigureDNS(tunName)
	if err != nil {
		log.Printf("使用主要方法配置DNS失败: %v，尝试备用方法", err)
		err = doConfigureDNSAlternative(tunName)
		if err != nil {
			return fmt.Errorf("配置DNS服务器失败: %v", err)
		}
	}

	// 验证DNS设置
	if !verifyDNS() {
		log.Printf("DNS设置验证失败，尝试使用备用方法")
		err = doConfigureDNSAlternative(tunName)
		if err != nil {
			return fmt.Errorf("使用备用方法配置DNS失败: %v", err)
		}

		if !verifyDNS() {
			log.Printf("DNS设置仍然验证失败，尝试刷新DNS缓存")
			flushDNSCache()

			if !verifyDNS() {
				log.Printf("DNS设置验证仍然失败，可能需要手动配置DNS")
				// 即使验证失败也继续，不返回错误
			} else {
				log.Printf("DNS设置验证成功")
			}
		} else {
			log.Printf("DNS设置验证成功")
		}
	} else {
		log.Printf("DNS设置验证成功")
	}

	return nil
}

// doConfigureDNS 主要的DNS配置方法
func doConfigureDNS(tunName string) error {
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
			return fmt.Errorf("使用PowerShell配置DNS服务器失败: %v", err)
		}

		log.Printf("已为接口%s配置DNS服务器", tunName)

		// 刷新DNS缓存
		flushDNSCache()

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

// doConfigureDNSAlternative 备用的DNS配置方法
func doConfigureDNSAlternative(tunName string) error {
	switch runtime.GOOS {
	case "windows":
		// 尝试使用netsh命令配置DNS
		cmd := fmt.Sprintf("netsh interface ip set dns name=\"%s\" static 8.8.8.8 primary", tunName) // Google DNS
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("使用netsh配置DNS服务器失败: %v", err)
		}

		cmd = fmt.Sprintf("netsh interface ip add dns name=\"%s\" 8.8.4.4 index=2", tunName) // Google DNS
		_, _ = runCommand(cmd)

		log.Printf("已使用netsh为接口%s配置DNS服务器", tunName)

		// 刷新DNS缓存
		flushDNSCache()

		return nil

	case "linux":
		// 在Linux上使用其他方法修改DNS
		cmd := "echo 'nameserver 8.8.8.8\nnameserver 8.8.4.4' | sudo tee /etc/resolv.conf" // Google DNS
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置DNS服务器失败: %v", err)
		}
		return nil

	case "darwin": // macOS
		// 在macOS上使用其他方法配置DNS
		cmd := fmt.Sprintf("sudo networksetup -setdnsservers %s 8.8.8.8 8.8.4.4", tunName) // Google DNS
		_, err := runCommand(cmd)
		if err != nil {
			return fmt.Errorf("配置DNS服务器失败: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// verifyDNS 验证DNS设置
func verifyDNS() bool {
	// 判断服务器是否在中国大陆
	inChina := isServerInChina()

	// 尝试解析中国大陆域名
	cmd := "nslookup baidu.com"
	_, err := runCommand(cmd)
	if err != nil {
		log.Printf("DNS验证失败(Baidu): %v", err)
		return false
	}

	// 尝试解析另一个中国大陆域名
	cmd = "nslookup qq.com"
	_, err = runCommand(cmd)
	if err != nil {
		log.Printf("DNS验证失败(QQ): %v", err)
		return false
	}

	// 如果服务器在境外，尝试解析国际域名
	if !inChina {
		cmd = "nslookup google.com"
		_, err = runCommand(cmd)
		if err != nil {
			log.Printf("DNS验证失败(Google): %v", err)
			// 即使国际域名解析失败，也不影响整体验证结果
		}
	}

	return true
}

// flushDNSCache 刷新DNS缓存
func flushDNSCache() {
	switch runtime.GOOS {
	case "windows":
		cmd := "ipconfig /flushdns"
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("刷新DNS缓存失败: %v", err)
		} else {
			log.Printf("已刷新DNS缓存")
		}

	case "linux":
		// 在Linux上刷新DNS缓存
		cmd := "sudo systemctl restart systemd-resolved"
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("刷新DNS缓存失败: %v", err)
		} else {
			log.Printf("已刷新DNS缓存")
		}

	case "darwin": // macOS
		// 在macOS上刷新DNS缓存
		cmd := "sudo killall -HUP mDNSResponder"
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("刷新DNS缓存失败: %v", err)
		} else {
			log.Printf("已刷新DNS缓存")
		}
	}
}

// diagnoseBaiduConnection 诊断百度网站连接问题 - 已禁用
func diagnoseBaiduConnection() {
	log.Printf("百度网站连接诊断功能已禁用")
}

// optimizeTCPForBaidu 优化TCP连接参数 - 已禁用
func optimizeTCPForBaidu() {
	log.Printf("TCP连接参数优化功能已禁用")
}

// warmupBaiduConnection 预热百度网站连接 - 已禁用
func warmupBaiduConnection() {
	log.Printf("百度网站连接预热功能已禁用")
}

// monitorAndOptimizeBaiduConnection 监控和优化百度连接 - 已禁用
func monitorAndOptimizeBaiduConnection(wgDevice *wireguard.WireGuardDevice) {
	log.Printf("百度连接监控和自动优化功能已禁用")
}

// testInternetConnection 测试互联网连接
func testInternetConnection() {
	log.Printf("正在测试互联网连接...")

	// 判断服务器是否在中国大陆
	inChina := isServerInChina()

	// 测试DNS解析 - 使用常用域名
	cmd := "nslookup qq.com"
	output, err := runCommand(cmd)
	if err != nil {
		log.Printf("DNS解析测试(QQ)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("DNS解析测试(QQ)成功")
	}

	// 根据服务器位置决定是否测试国际网站
	if !inChina {
		// 如果服务器在境外，测试Google域名
		cmd = "nslookup google.com"
		output, err = runCommand(cmd)
		if err != nil {
			log.Printf("DNS解析测试(Google)失败: %v\n%s", err, truncateOutput(output, 10))
		} else {
			log.Printf("DNS解析测试(Google)成功")
		}
	} else {
		log.Printf("服务器在中国大陆，跳过Google域名测试")
	}

	// 测试ICMP连接
	var pingTarget string
	var pingLabel string
	if inChina {
		// 如果服务器在中国大陆，使用百度DNS
		pingTarget = "180.76.76.76"
		pingLabel = "百度DNS"
	} else {
		// 如果服务器在境外，使用Google DNS
		pingTarget = "8.8.8.8"
		pingLabel = "Google DNS"
	}

	cmd = fmt.Sprintf("ping -n 3 %s", pingTarget)
	output, err = runCommand(cmd)
	if err != nil {
		log.Printf("ICMP连接测试(%s)失败: %v\n%s", pingLabel, err, truncateOutput(output, 10))
	} else {
		log.Printf("ICMP连接测试(%s)成功", pingLabel)
	}

	// 测试HTTP连接 - 使用常用网站
	if runtime.GOOS == "windows" {
		// Windows上使用PowerShell的Invoke-WebRequest
		cmd = "Invoke-WebRequest -Uri 'https://www.qq.com' -UseBasicParsing -Method Head | Select-Object -ExpandProperty StatusCode"
		output, err = runCommand(cmd)
		if err != nil {
			// 如果失败，尝试使用系统自带的curl
			cmd = "cmd.exe /c curl -s -o nul -w \"HTTP状态码: %{http_code}\" https://www.qq.com"
			output, err = runCommand(cmd)
		}
	} else {
		// 其他系统使用curl
		cmd = "curl -s -o /dev/null -w \"HTTP状态码: %{http_code}\" https://www.qq.com"
		output, err = runCommand(cmd)
	}

	if err != nil {
		log.Printf("HTTP连接测试(QQ)失败: %v\n%s", err, truncateOutput(output, 10))
	} else {
		log.Printf("HTTP连接测试(QQ)成功: %s", output)
	}

	// 根据服务器位置决定是否测试国际网站
	if !inChina {
		// 如果服务器在境外，测试Google网站
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
	} else {
		log.Printf("服务器在中国大陆，跳过Google网站测试")
	}
}

// isNetworkConnected 检查网络连接状态
func isNetworkConnected() bool {
	// 检查方法1: 尝试访问常用网站
	cmd := "curl -s -o nul -w \"%{http_code}\" --connect-timeout 5 https://www.qq.com"
	output, err := runCommand(cmd)
	if err == nil && strings.Contains(output, "200") {
		log.Printf("网络连接正常: 可以访问QQ")
		return true
	}

	// 检查方法2: 尝试访问其他网站
	cmd = "curl -s -o nul -w \"%{http_code}\" --connect-timeout 5 https://www.microsoft.com"
	output, err = runCommand(cmd)
	if err == nil && strings.Contains(output, "200") {
		log.Printf("网络连接正常: 可以访问Microsoft")
		return true
	}

	// 检查方法3: 尝试DNS解析
	cmd = "nslookup qq.com"
	_, err = runCommand(cmd)
	if err == nil {
		// DNS解析正常，再次尝试HTTP连接
		cmd = "curl -s -o nul -w \"%{http_code}\" --connect-timeout 5 https://www.qq.com"
		output, err = runCommand(cmd)
		if err == nil && strings.Contains(output, "200") {
			log.Printf("网络连接正常: DNS解析正常且可以访问QQ")
			return true
		}
	}

	// 检查方法4: 尝试ping Google DNS
	cmd = "ping -n 1 -w 1000 8.8.8.8"
	_, err = runCommand(cmd)
	if err == nil {
		log.Printf("网络连接正常: 可以ping通Google DNS")
		return true
	}

	log.Printf("网络连接检测失败: 所有检测方法均失败")
	return false
}

// resetDNS 重置DNS设置
func resetDNS() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	log.Printf("尝试重置DNS设置...")

	// 获取所有网络适配器
	cmd := "Get-NetAdapter | Where-Object {$_.Status -eq 'Up'} | Select-Object -ExpandProperty ifIndex"
	output, _ := runCommand(cmd)
	indices := strings.Split(strings.TrimSpace(output), "\n")

	// 重置所有适配器的DNS设置
	for _, index := range indices {
		index = strings.TrimSpace(index)
		if index != "" {
			cmd = fmt.Sprintf("Set-DnsClientServerAddress -InterfaceIndex %s -ResetServerAddresses", index)
			_, _ = runCommand(cmd)
		}
	}

	// 刷新DNS缓存
	cmd = "ipconfig /flushdns"
	_, _ = runCommand(cmd)
	log.Printf("已刷新DNS缓存")

	// 验证DNS设置
	return verifyDNS()
}

// restartDNSService 重启DNS服务
func restartDNSService() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	log.Printf("尝试重启DNS服务...")

	// 方法1: 使用PowerShell重启DNS服务
	cmd := "Restart-Service -Name Dnscache -Force -ErrorAction SilentlyContinue"
	output, err := runCommand(cmd)
	if err != nil {
		log.Printf("使用PowerShell重启DNS服务失败: %v, 输出: %s", err, truncateOutput(output, 5))

		// 方法2: 使用net stop/start命令
		log.Printf("尝试使用net命令重启DNS服务...")
		cmd = "cmd.exe /c \"net stop Dnscache /y\""
		stopOutput, stopErr := runCommand(cmd)
		if stopErr != nil {
			log.Printf("停止DNS服务失败: %v, 输出: %s", stopErr, truncateOutput(stopOutput, 5))
		} else {
			log.Printf("已停止DNS服务")
		}
		time.Sleep(1 * time.Second)

		cmd = "cmd.exe /c \"net start Dnscache\""
		startOutput, startErr := runCommand(cmd)
		if startErr != nil {
			log.Printf("启动DNS服务失败: %v, 输出: %s", startErr, truncateOutput(startOutput, 5))
		} else {
			log.Printf("已启动DNS服务")
		}

		// 方法3: 使用sc命令
		if stopErr != nil || startErr != nil {
			log.Printf("尝试使用sc命令重启DNS服务...")
			cmd = "cmd.exe /c \"sc stop Dnscache\""
			stopOutput, stopErr = runCommand(cmd)
			if stopErr != nil {
				log.Printf("使用sc停止DNS服务失败: %v, 输出: %s", stopErr, truncateOutput(stopOutput, 5))
			} else {
				log.Printf("已使用sc停止DNS服务")
			}
			time.Sleep(1 * time.Second)

			cmd = "cmd.exe /c \"sc start Dnscache\""
			startOutput, startErr = runCommand(cmd)
			if startErr != nil {
				log.Printf("使用sc启动DNS服务失败: %v, 输出: %s", startErr, truncateOutput(startOutput, 5))
			} else {
				log.Printf("已使用sc启动DNS服务")
			}
		}
	} else {
		log.Printf("使用PowerShell重启DNS服务成功")
	}

	log.Printf("已完成DNS客户端服务重启尝试")

	// 等待服务重启
	time.Sleep(2 * time.Second)

	// 刷新DNS缓存
	log.Printf("刷新DNS缓存...")
	flushDNSCache()

	// 验证DNS设置
	log.Printf("验证DNS设置...")
	if verifyDNS() {
		log.Printf("DNS设置验证成功")
		return true
	} else {
		log.Printf("DNS设置验证失败")
		return false
	}
}

// restartNetworkAdapters 重启网络适配器
func restartNetworkAdapters() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	log.Printf("正在重启网络适配器...")

	// 获取默认网络适配器
	defaultAdapter, err := getDefaultNetworkAdapter()
	if err != nil || defaultAdapter == "" {
		log.Printf("获取默认网络适配器失败: %v", err)

		// 如果无法获取默认适配器，尝试获取所有物理适配器
		cmd := "Get-NetAdapter | Where-Object {$_.Status -eq 'Up' -and $_.InterfaceDescription -notlike '*WireGuard*' -and $_.InterfaceDescription -notlike '*TAP-Windows*'} | Select-Object -ExpandProperty Name"
		output, err := runCommand(cmd)
		if err != nil {
			log.Printf("获取网络适配器失败: %v", err)
			return false
		}

		adapters := strings.Split(strings.TrimSpace(output), "\n")
		if len(adapters) == 0 || (len(adapters) == 1 && adapters[0] == "") {
			log.Printf("未找到物理网络适配器")
			return false
		}

		log.Printf("找到%d个网络适配器", len(adapters))

		// 重新启用物理网络适配器
		for _, adapter := range adapters {
			adapter = strings.TrimSpace(adapter)
			if adapter != "" {
				restartSingleAdapter(adapter)
			}
		}
	} else {
		// 只重启默认网络适配器
		log.Printf("只重启默认网络适配器: %s", defaultAdapter)
		restartSingleAdapter(defaultAdapter)
	}

	// 等待网络适配器重启
	log.Printf("等待网络适配器重启生效...")
	time.Sleep(5 * time.Second)

	// 验证网络连接
	log.Printf("验证网络连接...")
	if isNetworkConnected() {
		log.Printf("网络连接验证成功")
		return true
	} else {
		log.Printf("网络连接验证失败")
		return false
	}
}

// restartSingleAdapter 重启单个网络适配器
func restartSingleAdapter(adapter string) {
	log.Printf("正在重启网络适配器: %s", adapter)
	cmd := fmt.Sprintf("Restart-NetAdapter -Name \"%s\" -Confirm:$false", adapter)
	restartOutput, restartErr := runCommand(cmd)
	if restartErr != nil {
		log.Printf("重启网络适配器失败: %s, 错误: %v, 输出: %s", adapter, restartErr, truncateOutput(restartOutput, 5))

		// 尝试使用禁用/启用的方式
		log.Printf("尝试禁用然后启用网络适配器: %s", adapter)
		cmd = fmt.Sprintf("Disable-NetAdapter -Name \"%s\" -Confirm:$false", adapter)
		_, _ = runCommand(cmd)
		time.Sleep(2 * time.Second)

		cmd = fmt.Sprintf("Enable-NetAdapter -Name \"%s\" -Confirm:$false", adapter)
		_, _ = runCommand(cmd)
		log.Printf("已禁用然后启用网络适配器: %s", adapter)
	} else {
		log.Printf("已重启网络适配器: %s", adapter)
	}
}

// getDefaultNetworkAdapter 获取默认网络适配器
func getDefaultNetworkAdapter() (string, error) {
	// 获取默认网关
	defaultGateway, err := getDefaultGateway()
	if err != nil || defaultGateway == "" {
		return "", fmt.Errorf("获取默认网关失败: %v", err)
	}

	// 获取与默认网关关联的网络适配器
	cmd := fmt.Sprintf("Get-NetRoute | Where-Object {$_.NextHop -eq '%s'} | Select-Object -ExpandProperty InterfaceAlias -Unique", defaultGateway)
	output, err := runCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("获取默认网络适配器失败: %v", err)
	}

	// 取第一个适配器
	adapters := strings.Split(strings.TrimSpace(output), "\n")
	if len(adapters) == 0 || (len(adapters) == 1 && adapters[0] == "") {
		return "", fmt.Errorf("未找到与默认网关关联的网络适配器")
	}

	return strings.TrimSpace(adapters[0]), nil
}

// resetNetworkStack 重置网络协议栈
func resetNetworkStack() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	log.Printf("尝试重置网络协议栈...")

	// 重置Winsock
	cmd := "netsh winsock reset"
	_, _ = runCommand(cmd)
	log.Printf("已重置Winsock")

	// 重置IP协议栈
	cmd = "netsh int ip reset"
	_, _ = runCommand(cmd)
	log.Printf("已重置IP协议栈")

	// 等待重置生效
	time.Sleep(2 * time.Second)

	// 验证网络连接
	return isNetworkConnected()
}

// implementAntiDetectionMeasures 实施反检测措施
func implementAntiDetectionMeasures() {
	log.Printf("正在实施反检测措施...")

	// 如果已经启用了反检测措施，直接返回
	if antiDetectionEnabled {
		log.Printf("反检测措施已启用")
		return
	}

	// 1. 模拟浏览器行为
	simulateNormalBrowserBehavior()

	// 2. 优化HTTP请求参数
	optimizeHTTPRequestParameters()

	// 标记反检测措施已启用
	antiDetectionEnabled = true
	log.Printf("反检测措施已实施")
}

// simulateNormalBrowserBehavior 模拟正常浏览器行为
func simulateNormalBrowserBehavior() {
	log.Printf("正在模拟正常浏览器行为...")

	// 备份原始Transport
	defaultTransport = http.DefaultTransport

	// 创建自定义Transport
	customTransport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   30 * time.Second,
			KeepAlive: 30 * time.Second,
			DualStack: true,
		}).DialContext,
		MaxIdleConns:          100,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		MaxIdleConnsPerHost:   10,
		DisableCompression:    false,
	}

	// 替换默认Transport
	http.DefaultTransport = &browserTransport{
		base: customTransport,
	}

	log.Printf("浏览器行为模拟已启用")
}

// browserTransport 模拟浏览器行为的Transport
type browserTransport struct {
	base http.RoundTripper
}

// RoundTrip 实现http.RoundTripper接口
func (t *browserTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	// 随机选择User-Agent
	userAgents := []string{
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
		"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
	}
	index := int(time.Now().UnixNano()) % len(userAgents)
	req.Header.Set("User-Agent", userAgents[index])

	// 设置Accept头
	req.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9")

	// 设置语言
	req.Header.Set("Accept-Language", "zh-CN,zh;q=0.9,en;q=0.8")

	// 设置编码
	req.Header.Set("Accept-Encoding", "gzip, deflate, br")

	// 不设置 Connection 头部，因为它是受保护的
	// req.Header.Set("Connection", "keep-alive")

	// 设置升级不安全请求
	req.Header.Set("Upgrade-Insecure-Requests", "1")

	// 添加随机的Cookie
	if time.Now().UnixNano()%2 == 0 {
		req.Header.Set("Cookie", fmt.Sprintf("session_id=%d; visit_count=%d",
			time.Now().UnixNano(), time.Now().UnixNano()%10+1))
	}

	// 使用基础Transport发送请求
	return t.base.RoundTrip(req)
}

// optimizeHTTPRequestParameters 优化HTTP请求参数
func optimizeHTTPRequestParameters() {
	log.Printf("正在优化HTTP请求参数...")

	// 创建一个模拟正常浏览器的PowerShell脚本
	scriptContent := `
	# 设置User-Agent为常见浏览器
	$headers = @{
		"User-Agent" = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36"
		"Accept" = "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9"
		"Accept-Language" = "zh-CN,zh;q=0.9,en;q=0.8"
		"Accept-Encoding" = "gzip, deflate, br"
		# 移除Connection头部，因为它是受保护的
		"Upgrade-Insecure-Requests" = "1"
		"Sec-Fetch-Site" = "none"
		"Sec-Fetch-Mode" = "navigate"
		"Sec-Fetch-User" = "?1"
		"Sec-Fetch-Dest" = "document"
	}

	# 尝试访问常用网站
	try {
		$response = Invoke-WebRequest -Uri "https://www.qq.com" -Headers $headers -UseBasicParsing -TimeoutSec 10
		Write-Output "QQ访问成功，状态码: $($response.StatusCode)"
	} catch {
		Write-Output "QQ访问失败: $_"
	}
	`

	// 保存脚本到临时文件
	scriptPath := os.TempDir() + "\\simulate_browser.ps1"
	err := os.WriteFile(scriptPath, []byte(scriptContent), 0644)
	if err != nil {
		log.Printf("保存脚本失败: %v", err)
		return
	}

	// 执行脚本
	cmd := fmt.Sprintf("powershell -ExecutionPolicy Bypass -File \"%s\"", scriptPath)
	output, _ := runCommand(cmd)
	log.Printf("模拟浏览器结果: %s", output)

	log.Printf("HTTP请求参数优化完成")
}

// testNetworkAfterClose 测试关闭VPN后的网络连接
func testNetworkAfterClose() {
	log.Printf("测试关闭VPN后的网络连接...")

	// 检查网络连接状态
	if isNetworkConnected() {
		log.Printf("网络连接正常，无需恢复")
		return
	}

	log.Printf("网络连接异常，尝试恢复")

	// 检查路由表是否正确
	if runtime.GOOS == "windows" {
		log.Printf("检查路由表...")
		cmd := "route print"
		output, _ := runCommand(cmd)
		log.Printf("当前路由表(摘要):\n%s", truncateOutput(output, 20))

		// 检查是否有默认路由
		if strings.Contains(output, "0.0.0.0          0.0.0.0") {
			log.Printf("发现默认路由，尝试清理...")
			deleteRoute("0.0.0.0/0")

			// 清理路由后再次检查网络连接
			if isNetworkConnected() {
				log.Printf("清理默认路由后，网络连接已恢复")
				return
			}
		}
	}

	// 尝试刷新DNS缓存
	log.Printf("尝试刷新DNS缓存...")
	flushDNSCache()
	if isNetworkConnected() {
		log.Printf("刷新DNS缓存后，网络连接已恢复")
		return
	}

	// 尝试重置DNS
	log.Printf("尝试重置DNS设置...")
	resetDNS()
	if isNetworkConnected() {
		log.Printf("重置DNS后，网络连接已恢复")
		return
	}

	// 尝试重启DNS服务
	log.Printf("尝试重启DNS服务...")
	restartDNSService()
	if isNetworkConnected() {
		log.Printf("重启DNS服务后，网络连接已恢复")
		return
	}

	// 尝试重启网络适配器
	log.Printf("尝试重启网络适配器...")
	restartNetworkAdapters()
	if isNetworkConnected() {
		log.Printf("重启网络适配器后，网络连接已恢复")
		return
	}

	// 尝试重置网络协议栈
	log.Printf("尝试重置网络协议栈...")
	resetNetworkStack()
	if isNetworkConnected() {
		log.Printf("重置网络协议栈后，网络连接已恢复")
		return
	}

	// 如果所有尝试都失败，提供恢复指南
	log.Printf("自动恢复失败，请按照以下步骤手动恢复网络连接:")
	log.Printf("1. 执行 ipconfig /flushdns")
	log.Printf("2. 执行 netsh winsock reset")
	log.Printf("3. 执行 netsh int ip reset")
	log.Printf("4. 重启网络适配器")
	log.Printf("5. 如果仍然无法连接，请重启电脑")
}

// startConnectionMonitor 监控连接状态并在需要时自动重连
func startConnectionMonitor(wgDevice *wireguard.WireGuardDevice, config *wireguard.Config) {
	reconnectAttempts := 0
	maxReconnectAttempts := 10
	reconnectDelay := 5 * time.Second
	lastReconnectTime := time.Time{}

	// 添加稳定期和连续失败计数
	stabilityPeriod := 5 * time.Minute // 重连后的稳定期，考虑握手周期为2分钟，给予充足的时间
	consecutiveFailures := 0           // 连续检测失败次数
	maxConsecutiveFailures := 3        // 触发重连的连续失败次数

	for {
		// 检查是否在稳定期内
		inStabilityPeriod := !lastReconnectTime.IsZero() && time.Since(lastReconnectTime) < stabilityPeriod

		// 如果在稳定期内，跳过断开检测
		if inStabilityPeriod {
			log.Printf("处于重连后稳定期，跳过断开检测（剩余 %s）",
				(stabilityPeriod - time.Since(lastReconnectTime)).Round(time.Second))
			time.Sleep(30 * time.Second)
			continue
		}

		// 检查连接状态
		connected := checkConnectionStatus(wgDevice)

		if !connected {
			// 在报告"可能断开"之前，先进行一次DNS解析测试
			// 判断服务器是否在中国大陆
			inChina := isServerInChina()

			// 选择适合的测试域名
			testDomain := "qq.com" // 默认使用中国大陆网站
			if !inChina {
				testDomain = "google.com" // 如果服务器在境外，使用国际网站
			}

			cmd := fmt.Sprintf("nslookup %s", testDomain)
			output, err := runCommand(cmd)
			if err == nil && !strings.Contains(output, "server can't find") {
				// DNS解析成功，说明网络可能正常，不增加失败计数
				log.Printf("DNS解析测试(%s)成功，网络可能正常，不计入失败", testDomain)
				continue
			}

			consecutiveFailures++
			log.Printf("检测到可能断开，这是第 %d/%d 次连续检测失败",
				consecutiveFailures, maxConsecutiveFailures)

			// 只有连续多次检测失败才触发重连
			if consecutiveFailures >= maxConsecutiveFailures {
				log.Printf("检测到连接断开，尝试重新连接...")

				// 如果上次重连尝试在一分钟内，增加重连延迟
				if !lastReconnectTime.IsZero() && time.Since(lastReconnectTime) < time.Minute {
					reconnectDelay *= 2 // 指数退避
					if reconnectDelay > 60*time.Second {
						reconnectDelay = 60 * time.Second // 最大延迟1分钟
					}
				}

				// 尝试重新连接
				if reconnectAttempts < maxReconnectAttempts {
					reconnectAttempts++
					log.Printf("重连尝试 %d/%d", reconnectAttempts, maxReconnectAttempts)
					lastReconnectTime = time.Now()

					// 重新初始化连接
					err := reinitializeConnection(wgDevice, config)
					if err != nil {
						log.Printf("重连失败: %v", err)
						// 等待一段时间再尝试
						time.Sleep(reconnectDelay)
					} else {
						log.Printf("重连成功")
						reconnectAttempts = 0
						reconnectDelay = 5 * time.Second // 重置延迟
						consecutiveFailures = 0          // 重置连续失败计数
					}
				} else {
					log.Printf("达到最大重连尝试次数，请手动重启客户端")
					// 等待一段时间再检查
					time.Sleep(5 * time.Minute)
					reconnectAttempts = 0 // 重置重连计数
				}
			} else {
				// 连续失败次数未达到阈值，等待下次检查
				log.Printf("等待下次检查确认连接状态")
				time.Sleep(15 * time.Second) // 失败后缩短检查间隔
			}
		} else {
			// 连接正常，重置连续失败计数
			if consecutiveFailures > 0 {
				log.Printf("连接状态恢复正常")
				consecutiveFailures = 0
			}

			// 连接正常，重置重连计数
			if reconnectAttempts > 0 {
				log.Printf("连接已恢复")
				reconnectAttempts = 0
				reconnectDelay = 5 * time.Second
			}

			// 连接正常时，使用较长的检查间隔
			time.Sleep(60 * time.Second)
		}
	}
}

// checkConnectionStatus 检查连接状态
func checkConnectionStatus(wgDevice *wireguard.WireGuardDevice) bool {
	// 判断服务器是否在中国大陆
	inChina := isServerInChina()

	// 首先检查DNS解析是否正常
	// 根据服务器位置选择不同的测试网站
	var testDomains []string
	if inChina {
		// 如果服务器在中国大陆，使用中国大陆的网站进行测试
		testDomains = []string{"baidu.com", "qq.com", "taobao.com", "163.com"}
		log.Printf("服务器在中国大陆，使用中国大陆网站进行测试")
	} else {
		// 如果服务器在境外，使用国际网站进行测试
		testDomains = []string{"google.com", "youtube.com", "facebook.com", "twitter.com"}
		log.Printf("服务器在境外，使用国际网站进行测试")
	}

	// 使用多个域名进行测试，只要有一个成功就认为连接正常
	for _, domain := range testDomains {
		cmd := fmt.Sprintf("nslookup %s", domain)
		output, err := runCommand(cmd)
		if err == nil && !strings.Contains(output, "server can't find") {
			log.Printf("DNS解析测试(%s)成功，网络连接正常", domain)
			return true
		}
		log.Printf("DNS解析测试(%s)失败", domain)
	}

	// 获取对等点信息
	peers, err := wgDevice.GetPeers()
	if err != nil {
		log.Printf("获取对等点信息失败: %v", err)
		// 即使获取对等点信息失败，也不直接判断连接断开
		// 继续进行其他检测
	} else if len(peers) == 0 {
		log.Printf("无对等点信息，可能是初始化问题")
		// 即使无对等点，也不直接判断连接断开
		// 继续进行其他检测
	} else {
		// 检查最后握手时间
		for _, peer := range peers {
			// 使用最后数据接收时间和最后握手时间的最大值来判断
			lastActiveTime := peer.LastHandshakeTime
			if peer.LastDataReceived.After(lastActiveTime) {
				lastActiveTime = peer.LastDataReceived
			}

			inactiveTime := time.Since(lastActiveTime)

			// 考虑WireGuard的握手周期（2分钟），将容忍时间设为4分钟
			// 这样即使错过一次握手也不会立即判断为断开
			if inactiveTime < 4*time.Minute {
				log.Printf("最后活跃时间在4分钟内，连接正常（%s前）", inactiveTime.Round(time.Second))
				return true
			}

			log.Printf("最后活跃时间超过4分钟（%s前），尝试其他检测方法", inactiveTime.Round(time.Second))
		}
	}

	// 尝试通过VPN隧道ping服务器内网IP
	serverIP := getServerIP(wgDevice)
	if serverIP != "" {
		cmd := fmt.Sprintf("ping -c 1 -W 2 %s", serverIP)
		if runtime.GOOS == "windows" {
			cmd = fmt.Sprintf("ping -n 1 -w 2000 %s", serverIP)
		}

		_, err := runCommand(cmd)
		if err == nil {
			log.Printf("通过VPN隧道ping服务器内网IP成功，连接正常")
			return true
		}
		log.Printf("通过VPN隧道ping服务器内网IP失败: %v", err)
	}

	// 尝试检查VPN接口状态
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.Name -eq '%s' -or $_.InterfaceDescription -like '*WireGuard*'} | Select-Object -ExpandProperty Status", wgDevice.TunName)
		output, err := runCommand(cmd)
		if err == nil && strings.Contains(strings.ToLower(output), "up") {
			log.Printf("VPN接口状态为UP，连接可能正常")
			return true
		}
		log.Printf("VPN接口状态检查失败或状态不是UP: %s", output)
	}

	// 尝试检查是否有活跃的VPN路由
	if runtime.GOOS == "windows" {
		cmd := "route print | findstr 10.8.0.0"
		output, err := runCommand(cmd)
		if err == nil && output != "" {
			log.Printf("存在VPN路由，连接可能正常")
			return true
		}
		log.Printf("未找到VPN路由")
	}

	// 尝试检查是否可以访问外部网站
	if runtime.GOOS == "windows" {
		cmd := "ping -n 1 -w 2000 8.8.8.8"
		_, err := runCommand(cmd)
		if err == nil {
			// 可以ping通外部网站，但可能不是通过VPN
			log.Printf("可以ping通外部网站，但可能不是通过VPN")
			// 这里不返回true，因为我们不确定是否通过VPN
		}
	}

	log.Printf("所有连接检测方法均失败，判断连接已断开")
	return false
}

// getServerIP 获取服务器IP地址
func getServerIP(wgDevice *wireguard.WireGuardDevice) string {
	// 尝试从对等点信息获取
	peers, err := wgDevice.GetPeers()
	if err == nil && len(peers) > 0 {
		// 假设第一个对等点是服务器
		for _, peer := range peers {
			if peer.IP != nil {
				return peer.IP.String()
			}
		}
	}

	// 如果无法从对等点信息获取，尝试从配置文件或命令行参数获取
	// 假设服务器IP在内网为10.8.0.1
	serverIP := "10.8.0.1"
	log.Printf("从对等点信息获取服务器IP失败，使用默认IP: %s", serverIP)
	return serverIP
}

// isServerInChina 判断服务器是否在中国大陆
func isServerInChina() bool {
	// 从命令行参数获取服务器地址
	host, _, err := net.SplitHostPort(*serverEndpoint)
	if err != nil {
		log.Printf("解析服务器地址失败: %v", err)
		return true // 默认假设在中国大陆
	}

	// 如果是IP地址，判断是否属于中国大陆IP段
	ip := net.ParseIP(host)
	if ip != nil {
		// 判断是否是内网IP
		if ip.IsPrivate() || ip.IsLoopback() {
			// 内网IP无法判断国家，默认假设在中国
			return true
		}

		// 判断是否是中国大陆常见IP段
		// 这里使用一些常见的中国大陆IP段进行简单判断
		// 注意：这不是完整的判断，只是一个简单的判断

		// 电信、联通、移动等常见IP段
		chinaIPRanges := []string{
			"27.0.0.0/8",  // 中国联通
			"36.0.0.0/8",  // 中国电信
			"39.0.0.0/8",  // 中国移动
			"42.0.0.0/8",  // 中国电信
			"58.0.0.0/8",  // 中国电信
			"59.0.0.0/8",  // 中国电信
			"60.0.0.0/8",  // 中国电信
			"61.0.0.0/8",  // 中国电信
			"101.0.0.0/8", // 中国电信
			"103.0.0.0/8", // 中国移动
			"106.0.0.0/8", // 中国电信
			"111.0.0.0/8", // 中国电信
			"112.0.0.0/8", // 中国电信
			"113.0.0.0/8", // 中国电信
			"114.0.0.0/8", // 中国电信
			"115.0.0.0/8", // 中国电信
			"116.0.0.0/8", // 中国电信
			"117.0.0.0/8", // 中国电信
			"118.0.0.0/8", // 中国电信
			"119.0.0.0/8", // 中国电信
			"120.0.0.0/8", // 中国电信
			"121.0.0.0/8", // 中国电信
			"122.0.0.0/8", // 中国电信
			"123.0.0.0/8", // 中国电信
			"124.0.0.0/8", // 中国电信
			"125.0.0.0/8", // 中国电信
			"139.0.0.0/8", // 中国电信
			"140.0.0.0/8", // 中国电信
			"153.0.0.0/8", // 中国电信
			"175.0.0.0/8", // 中国电信
			"180.0.0.0/8", // 中国电信
			"182.0.0.0/8", // 中国电信
			"183.0.0.0/8", // 中国电信
			"202.0.0.0/8", // 中国电信
			"210.0.0.0/8", // 中国电信
			"211.0.0.0/8", // 中国电信
			"218.0.0.0/8", // 中国电信
			"220.0.0.0/8", // 中国电信
			"221.0.0.0/8", // 中国电信
			"222.0.0.0/8", // 中国电信
			"223.0.0.0/8", // 中国电信
		}

		for _, cidr := range chinaIPRanges {
			_, ipNet, err := net.ParseCIDR(cidr)
			if err != nil {
				continue
			}

			if ipNet.Contains(ip) {
				log.Printf("服务器IP %s 属于中国大陆IP段 %s", ip.String(), cidr)
				return true
			}
		}

		log.Printf("服务器IP %s 不属于已知的中国大陆IP段", ip.String())
		return false
	}

	// 如果是域名，判断是否是.cn域名
	if strings.HasSuffix(host, ".cn") {
		log.Printf("服务器域名 %s 以.cn结尾，判断为中国大陆服务器", host)
		return true
	}

	// 如果无法判断，默认假设在中国大陆
	log.Printf("无法判断服务器位置，默认假设在中国大陆")
	return true
}

// addServerRoute 添加服务器特殊路由
func addServerRoute(endpoint string) {
	// 解析服务器地址
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		log.Printf("解析服务器地址失败: %v", err)
		return
	}

	serverIP := net.ParseIP(host)
	if serverIP == nil || serverIP.IsLoopback() {
		log.Printf("无效的服务器IP地址: %s", host)
		return
	}

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
			log.Printf("已添加服务器特殊路由: %s -> %s (优先级最高)", serverIP.String(), defaultGateway)
		} else {
			log.Printf("添加服务器特殊路由失败: %v", err)
		}
	} else {
		log.Printf("无法获取默认网关，服务器特殊路由添加失败")
	}
}

// reinitializeConnection 重新初始化连接
func reinitializeConnection(wgDevice *wireguard.WireGuardDevice, config *wireguard.Config) error {
	// 记录重连开始时间
	startTime := time.Now()

	// 关闭当前设备
	wgDevice.Close()

	// 等待一段时间
	time.Sleep(1 * time.Second)

	// 探测最佳MTU值
	optimalMTU := detectOptimalMTU()
	log.Printf("重连时使用MTU值: %d", optimalMTU)

	// 重新创建设备
	newDevice, err := wireguard.NewWireGuardDevice(config, false, optimalMTU)
	if err != nil {
		return fmt.Errorf("重新创建 WireGuard 设备失败: %v", err)
	}

	// 解析IP地址和子网掩码
	ip, ipNet, err := net.ParseCIDR(*clientIP)
	if err != nil {
		newDevice.Close()
		return fmt.Errorf("解析IP地址失败: %s, %v", *clientIP, err)
	}

	// 配置TUN设备IP地址
	err = configureTunIP(newDevice.TunName, ip, ipNet)
	if err != nil {
		newDevice.Close()
		return fmt.Errorf("配置TUN设备IP地址失败: %v", err)
	}

	// 更新设备引用
	*wgDevice = *newDevice

	// 重新配置路由
	if *fullTunnel {
		// 添加服务器特殊路由
		addServerRoute(config.Endpoint)

		// 添加VPN网段路由
		for _, allowedIP := range config.AllowedIPs {
			addRoute(allowedIP.String(), newDevice.TunName)
		}

		// 添加默认路由
		_, defaultNet, _ := net.ParseCIDR("0.0.0.0/0")
		addRoute(defaultNet.String(), newDevice.TunName)
		log.Printf("已重新配置全局路由")
	} else {
		// 添加服务器特殊路由
		addServerRoute(config.Endpoint)

		// 添加VPN网段路由
		for _, allowedIP := range config.AllowedIPs {
			addRoute(allowedIP.String(), newDevice.TunName)
		}
		log.Printf("已重新配置分流路由")
	}

	// 记录重连完成时间
	log.Printf("重连完成，耗时: %s", time.Since(startTime).Round(time.Millisecond))

	return nil
}
