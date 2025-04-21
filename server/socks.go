package main

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/armon/go-socks5"
	"github.com/pekhightvpn/wireguard"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// SocksServer 表示SOCKS5代理服务器
type SocksServer struct {
	server   *socks5.Server
	bindAddr string
	logger   *log.Logger
	running  bool
}

// CredentialStore 实现用户名/密码认证
type CredentialStore struct {
	username  string
	password  string
	authStore *AuthStore                          // 认证信息存储
	clients   map[wgtypes.Key]*wireguard.PeerInfo // 客户端信息
}

// Valid 验证用户名和密码
func (c *CredentialStore) Valid(user, password string) bool {
	// 如果没有设置用户名和密码，允许任何认证
	if c.username == "" && c.password == "" {
		return true
	}

	// 先检查是否与指定的用户名和密码匹配
	if user == c.username && password == c.password {
		return true
	}

	// 如果有认证存储，检查是否与任何客户端的认证信息匹配
	if c.authStore != nil {
		// 遍历所有客户端
		for pubKey := range c.clients {
			// 获取该客户端的认证信息
			info, exists := c.authStore.Get(pubKey.String())
			if exists && info.Username == user && info.Password == password {
				return true
			}
		}
	}

	return false
}

// NewSocksServer 创建一个新的SOCKS5代理服务器
func NewSocksServer(bindAddr string, username, password string, authStore *AuthStore, clients map[wgtypes.Key]*wireguard.PeerInfo) (*SocksServer, error) {
	// 创建日志记录器
	logger := log.New(os.Stdout, "[SOCKS5] ", log.LstdFlags)

	// 创建认证存储
	creds := &CredentialStore{
		username:  username,
		password:  password,
		authStore: authStore,
		clients:   clients,
	}

	// 创建SOCKS5配置
	conf := &socks5.Config{
		Logger: logger,
		// 添加DNS解析器，确保DNS请求也通过VPN
		Resolver: &socks5.DNSResolver{},
	}

	// 启用认证
	conf.Credentials = creds
	logger.Printf("启用SOCKS5认证，支持VPN公钥认证和用户名/密码认证")

	// 创建SOCKS5服务器
	server, err := socks5.New(conf)
	if err != nil {
		return nil, fmt.Errorf("创建SOCKS5服务器失败: %v", err)
	}

	return &SocksServer{
		server:   server,
		bindAddr: bindAddr,
		logger:   logger,
		running:  false,
	}, nil
}

// Start 启动SOCKS5代理服务器
func (s *SocksServer) Start() error {
	if s.running {
		return fmt.Errorf("SOCKS5服务器已经在运行")
	}

	// 启动服务器
	s.logger.Printf("启动SOCKS5代理服务器在 %s", s.bindAddr)
	go func() {
		if err := s.server.ListenAndServe("tcp", s.bindAddr); err != nil {
			s.logger.Printf("SOCKS5服务器错误: %v", err)
		}
	}()

	s.running = true
	return nil
}

// Stop 停止SOCKS5代理服务器
func (s *SocksServer) Stop() {
	// 目前go-socks5库没有提供优雅关闭的方法
	// 这里只是标记服务器已停止
	s.running = false
	s.logger.Printf("SOCKS5代理服务器已停止")
}

// IsRunning 检查SOCKS5代理服务器是否正在运行
func (s *SocksServer) IsRunning() bool {
	return s.running
}

// GetBindAddr 获取SOCKS5代理服务器的绑定地址
func (s *SocksServer) GetBindAddr() string {
	return s.bindAddr
}

// StartSocksServer 启动SOCKS5代理服务器
// 这是一个便捷函数，用于在主程序中启动SOCKS5代理服务器
func StartSocksServer(tunIP string, socksPort int, username, password string, regSecret string, clients map[wgtypes.Key]*wireguard.PeerInfo) (*SocksServer, error) {
	// 从tunIP中提取IP地址
	ip := strings.Split(tunIP, "/")[0]

	// 创建绑定地址 - 同时绑定到TUN接口和所有接口
	// 这样可以从外部和内部网络访问
	bindAddrTun := fmt.Sprintf("%s:%d", ip, socksPort)
	bindAddrAll := fmt.Sprintf("0.0.0.0:%d", socksPort)

	// 创建认证存储
	authStore := NewAuthStore()

	// 为每个客户端生成认证信息
	for pubKey, _ := range clients {
		// 生成认证信息
		info := GenerateAuthInfo(pubKey.String(), regSecret)
		// 存储认证信息
		authStore.AddOrUpdate(pubKey.String(), info.Username, info.Password)
		// 记录日志
		clientID := fmt.Sprintf("%s...", pubKey.String()[:8])
		log.Printf("为客户端 %s 生成SOCKS5认证信息: %s", clientID, info.String())
	}

	// 创建SOCKS5代理服务器 - 绑定到TUN接口
	socksServer, err := NewSocksServer(bindAddrTun, username, password, authStore, clients)
	if err != nil {
		return nil, fmt.Errorf("创建SOCKS5代理服务器失败: %v", err)
	}

	// 启动SOCKS5代理服务器 - 绑定到TUN接口
	err = socksServer.Start()
	if err != nil {
		return nil, fmt.Errorf("启动SOCKS5代理服务器失败: %v", err)
	}

	// 创建SOCKS5代理服务器 - 绑定到所有接口
	socksServerAll, err := NewSocksServer(bindAddrAll, username, password, authStore, clients)
	if err != nil {
		// 如果绑定到所有接口失败，不影响主要功能，只记录日志
		log.Printf("警告: 绑定到所有接口失败: %v", err)
	} else {
		// 启动SOCKS5代理服务器 - 绑定到所有接口
		err = socksServerAll.Start()
		if err != nil {
			log.Printf("警告: 启动绑定到所有接口的SOCKS5服务器失败: %v", err)
		} else {
			log.Printf("SOCKS5代理服务器已启动在 %s", bindAddrAll)
		}
	}

	// 显示认证信息
	log.Printf("SOCKS5代理服务器已启用VPN公钥认证，客户端可使用自动生成的认证信息")
	if username != "" || password != "" {
		log.Printf("SOCKS5代理服务器也支持用户名/密码认证，用户名: %s", username)
	}

	log.Printf("SOCKS5代理服务器已启动在 %s", bindAddrTun)
	return socksServer, nil
}
