package main

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pekhightvpn/wireguard"
	"golang.org/x/net/proxy"
)

// SocksManager 管理SOCKS代理
type SocksManager struct {
	socksAddr   string
	serverIP    string
	running     bool
	logger      *log.Logger
	username    string
	password    string
	monitorChan chan struct{}
	stopChan    chan struct{}
}

// NewSocksManager 创建一个新的SOCKS代理管理器
func NewSocksManager(serverIP string, socksPort int, username, password string, privateKey, serverPubKey string, regSecret string) *SocksManager {
	// 创建日志记录器
	logger := log.New(os.Stdout, "[SOCKS] ", log.LstdFlags)

	// 创建SOCKS地址
	socksAddr := fmt.Sprintf("%s:%d", serverIP, socksPort)

	// 如果没有提供用户名和密码，但提供了私钥和服务器公钥，生成认证信息
	if (username == "" || password == "") && privateKey != "" && serverPubKey != "" && regSecret != "" {
		// 生成客户端公钥
		clientPrivKey, err := wireguard.ParseKey(privateKey)
		if err == nil {
			clientPubKey := wireguard.GeneratePublicKey(clientPrivKey)
			// 生成认证信息
			username, password = GenerateAuthInfo(clientPubKey.String(), regSecret)
			logger.Printf("使用VPN公钥生成的SOCKS5认证信息: 用户名=%s", username)
		} else {
			logger.Printf("解析私钥失败，无法生成SOCKS5认证信息: %v", err)
		}
	}

	// 创建SOCKS管理器
	manager := &SocksManager{
		socksAddr:   socksAddr,
		serverIP:    serverIP,
		running:     false,
		logger:      logger,
		username:    username,
		password:    password,
		monitorChan: make(chan struct{}, 1),
		stopChan:    make(chan struct{}),
	}

	// 启动监控协程
	go manager.monitorConnection()

	return manager
}

// monitorConnection 监控SOCKS代理连接状态
func (s *SocksManager) monitorConnection() {
	// 创建定时器，每30秒检查一次连接状态
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// 设置连续失败计数器
	failureCount := 0
	const maxFailures = 3 // 最大连续失败次数

	for {
		select {
		case <-ticker.C:
			// 定期测试连接
			err := s.TestConnection()
			if err != nil {
				failureCount++
				s.logger.Printf("警告: SOCKS代理连接测试失败 (%d/%d): %v", failureCount, maxFailures, err)

				// 如果连续失败超过最大次数，设置为非运行状态
				if failureCount >= maxFailures {
					s.running = false
					s.logger.Printf("警告: SOCKS代理连续%d次连接失败，已标记为非运行状态", maxFailures)
					s.logger.Printf("注意: 这不会影响VPN的基本功能，只是无法使用SOCKS代理")
				}
			} else {
				// 测试成功，重置失败计数器
				failureCount = 0

				// 如果之前不是运行状态，输出日志
				if !s.running {
					s.logger.Printf("SOCKS代理连接恢复正常")
				}

				s.running = true
			}
		case <-s.monitorChan:
			// 手动触发测试
			err := s.TestConnection()
			if err != nil {
				s.logger.Printf("警告: SOCKS代理连接测试失败: %v", err)
				s.logger.Printf("注意: 这不会影响VPN的基本功能，只是无法使用SOCKS代理")
				s.running = false
			} else {
				s.running = true
				s.logger.Printf("SOCKS代理连接测试成功")
				// 重置失败计数器
				failureCount = 0
			}
		case <-s.stopChan:
			// 停止监控
			s.logger.Printf("SOCKS代理连接监控已停止")
			return
		}
	}
}

// TestConnection 测试SOCKS代理连接
func (s *SocksManager) TestConnection() error {
	// 创建SOCKS5代理认证
	var auth *proxy.Auth
	if s.username != "" || s.password != "" {
		auth = &proxy.Auth{
			User:     s.username,
			Password: s.password,
		}
	}

	// 创建SOCKS5代理拨号器
	dialer, err := proxy.SOCKS5("tcp", s.socksAddr, auth, proxy.Direct)
	if err != nil {
		return fmt.Errorf("创建SOCKS5代理拨号器失败: %v", err)
	}

	// 创建一个带超时的上下文
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// 使用通道来控制超时
	resultChan := make(chan error, 1)

	// 在单独的goroutine中执行连接测试
	go func() {
		// 尝试连接到一个测试网站（使用百度而非Google，因为在中国大陆可以访问）
		conn, err := dialer.Dial("tcp", "www.baidu.com:80")
		if err != nil {
			resultChan <- fmt.Errorf("通过SOCKS5代理连接失败: %v", err)
			return
		}
		defer conn.Close()

		// 发送简单的HTTP请求来确认连接成功
		_, err = conn.Write([]byte("GET / HTTP/1.1\r\nHost: www.baidu.com\r\nConnection: close\r\n\r\n"))
		if err != nil {
			resultChan <- fmt.Errorf("发送HTTP请求失败: %v", err)
			return
		}

		// 设置读取超时
		conn.SetReadDeadline(time.Now().Add(3 * time.Second))

		// 读取响应头部
		buf := make([]byte, 1024)
		_, err = conn.Read(buf)
		if err != nil {
			resultChan <- fmt.Errorf("读取HTTP响应失败: %v", err)
			return
		}

		// 检查是否收到HTTP响应
		if !strings.Contains(string(buf), "HTTP/1.") {
			resultChan <- fmt.Errorf("收到的响应不是有效的HTTP响应")
			return
		}

		// 测试成功
		resultChan <- nil
	}()

	// 等待测试结果或超时
	select {
	case err := <-resultChan:
		return err
	case <-ctx.Done():
		return fmt.Errorf("测试SOCKS代理连接超时，请检查服务器是否已启用SOCKS代理")
	}
}

// TriggerTest 触发连接测试
func (s *SocksManager) TriggerTest() {
	select {
	case s.monitorChan <- struct{}{}:
		// 成功发送测试信号
	default:
		// 通道已满，忽略
	}
}

// Stop 停止SOCKS代理管理器
func (s *SocksManager) Stop() {
	close(s.stopChan)
	s.running = false
	s.logger.Printf("SOCKS代理管理器已停止")
}

// GetSocksAddr 获取SOCKS代理地址
func (s *SocksManager) GetSocksAddr() string {
	return s.socksAddr
}

// GetServerIP 获取服务器IP
func (s *SocksManager) GetServerIP() string {
	return s.serverIP
}

// GenerateAuthInfo 根据公钥和注册密钥生成认证信息
func GenerateAuthInfo(publicKey string, regSecret string) (string, string) {
	// 使用公钥和注册密钥生成唯一的用户名和密码
	hash := sha256.Sum256([]byte(publicKey + regSecret))
	username := "vpn_" + base64.RawURLEncoding.EncodeToString(hash[:8])
	password := base64.RawURLEncoding.EncodeToString(hash[8:24])

	return username, password
}

// GetServerIPFromEndpoint 从端点获取服务器IP
func GetServerIPFromEndpoint(endpoint string) string {
	// 解析端点
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return ""
	}

	// 如果是IP地址，直接返回
	if net.ParseIP(host) != nil {
		return host
	}

	// 如果是域名，尝试解析
	ips, err := net.LookupIP(host)
	if err != nil || len(ips) == 0 {
		return ""
	}

	// 返回第一个IP
	return ips[0].String()
}

// SetupWebRTCProtection 设置WebRTC保护
func SetupWebRTCProtection(mode string, customStunServer string) error {
	log.Printf("设置WebRTC保护，模式: %s...", mode)

	// 常见STUN服务器列表
	stunServers := []string{
		"stun.l.google.com",
		"stun1.l.google.com",
		"stun2.l.google.com",
		"stun3.l.google.com",
		"stun4.l.google.com",
		"stun.ekiga.net",
		"stun.ideasip.com",
		"stun.schlund.de",
		"stun.stunprotocol.org",
		"stun.voiparound.com",
		"stun.voipbuster.com",
		"stun.voipstunt.com",
		"stun.voxgratia.org",
	}

	// 构建hosts文件条目
	var hostsEntries strings.Builder

	// 根据模式选择不同的处理方式
	if mode == "block" {
		// 阻止模式: 将STUN服务器指向127.0.0.1
		log.Printf("使用阻止模式，将STUN服务器指向127.0.0.1")
		for _, server := range stunServers {
			hostsEntries.WriteString("127.0.0.1 " + server + "\n")
		}
	} else if mode == "spoof" {
		// 模拟模式: 将STUN服务器指向VPN服务器或自定义STUN服务器
		// 确定要使用的STUN服务器地址
		stunServerIP := customStunServer
		if stunServerIP == "" {
			// 如果没有指定自定义STUN服务器，使用VPN服务器地址
			// 从环境变量中获取服务器地址
			serverEndpoint := os.Getenv("VPN_SERVER_ENDPOINT")
			if serverEndpoint != "" {
				// 从端点提取服务器IP
				stunServerIP = GetServerIPFromEndpoint(serverEndpoint)
			}

			// 如果仍然无法获取服务器IP，使用默认端口
			if stunServerIP == "" {
				log.Printf("无法获取VPN服务器IP，将使用阻止模式")
				// 回退到阻止模式
				for _, server := range stunServers {
					hostsEntries.WriteString("127.0.0.1 " + server + "\n")
				}
			} else {
				log.Printf("使用模拟模式，将STUN服务器指向VPN服务器: %s", stunServerIP)
				for _, server := range stunServers {
					hostsEntries.WriteString(stunServerIP + " " + server + "\n")
				}
			}
		} else {
			log.Printf("使用模拟模式，将STUN服务器指向自定义服务器: %s", stunServerIP)
			for _, server := range stunServers {
				hostsEntries.WriteString(stunServerIP + " " + server + "\n")
			}
		}
	} else {
		return fmt.Errorf("无效的WebRTC保护模式: %s", mode)
	}

	// 添加条目到hosts文件
	// 注意：这需要管理员权限
	err := appendToHostsFile(hostsEntries.String())
	if err != nil {
		log.Printf("修改hosts文件失败: %v", err)
		log.Printf("请手动修改hosts文件，添加以下条目:\n%s", hostsEntries.String())
		return err
	}

	log.Printf("WebRTC保护已设置，模式: %s", mode)
	return nil
}

// appendToHostsFile 添加条目到hosts文件
func appendToHostsFile(entries string) error {
	// 获取hosts文件路径
	hostsPath := getHostsFilePath()

	// 读取现有内容
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return err
	}

	// 检查是否已经包含这些条目
	if strings.Contains(string(content), "# PekHight VPN WebRTC Protection") {
		// 已经包含，不需要再添加
		return nil
	}

	// 添加注释和条目
	newContent := string(content)
	if !strings.HasSuffix(newContent, "\n") {
		newContent += "\n"
	}
	newContent += "\n# PekHight VPN WebRTC Protection\n" + entries

	// 写入文件
	return os.WriteFile(hostsPath, []byte(newContent), 0644)
}

// getHostsFilePath 获取hosts文件路径
func getHostsFilePath() string {
	if isWindows() {
		return os.Getenv("SystemRoot") + "\\System32\\drivers\\etc\\hosts"
	}
	return "/etc/hosts"
}

// isWindows 检查是否是Windows系统
func isWindows() bool {
	return os.PathSeparator == '\\' && os.PathListSeparator == ';'
}

// CleanupWebRTCProtection 清理WebRTC保护设置
func CleanupWebRTCProtection() error {
	log.Printf("正在清理WebRTC保护设置...")

	// 获取hosts文件路径
	hostsPath := getHostsFilePath()

	// 读取现有内容
	content, err := os.ReadFile(hostsPath)
	if err != nil {
		return fmt.Errorf("读取hosts文件失败: %v", err)
	}

	// 将内容转换为字符串
	hostsContent := string(content)

	// 检查是否包含WebRTC保护标记
	if !strings.Contains(hostsContent, "# PekHight VPN WebRTC Protection") {
		// 没有找到标记，不需要清理
		log.Printf("未找到WebRTC保护设置，无需清理")
		return nil
	}

	// 分割文件内容
	parts := strings.Split(hostsContent, "# PekHight VPN WebRTC Protection")
	if len(parts) < 2 {
		return fmt.Errorf("无法解析hosts文件")
	}

	// 找到下一个注释或文件结尾
	newContent := parts[0]
	for i := 1; i < len(parts); i++ {
		part := parts[i]
		// 如果这部分包含另一个注释，保留该注释及之后的内容
		commentPos := strings.Index(part, "#")
		if commentPos >= 0 {
			newContent += part[commentPos:]
		}
	}

	// 写回文件
	err = os.WriteFile(hostsPath, []byte(newContent), 0644)
	if err != nil {
		return fmt.Errorf("写入hosts文件失败: %v", err)
	}

	log.Printf("WebRTC保护设置已清理")
	return nil
}
