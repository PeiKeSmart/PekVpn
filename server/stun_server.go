package main

import (
	"log"
	"net"
	"time"

	"github.com/pion/stun"
)

// STUNServer 实现一个简单的STUN服务器
type STUNServer struct {
	conn      *net.UDPConn
	publicIP  net.IP
	port      int
	running   bool
	stopChan  chan struct{}
	logger    *log.Logger
}

// NewSTUNServer 创建一个新的STUN服务器
func NewSTUNServer(publicIP string, port int) (*STUNServer, error) {
	// 解析公共IP
	ip := net.ParseIP(publicIP)
	if ip == nil {
		return nil, stun.ErrNoIPv4Address
	}

	// 创建日志记录器
	logger := log.New(log.Writer(), "[STUN] ", log.LstdFlags)

	return &STUNServer{
		publicIP:  ip,
		port:      port,
		running:   false,
		stopChan:  make(chan struct{}),
		logger:    logger,
	}, nil
}

// Start 启动STUN服务器
func (s *STUNServer) Start() error {
	if s.running {
		return nil
	}

	// 创建UDP监听
	addr := &net.UDPAddr{
		IP:   net.IPv4zero,
		Port: s.port,
	}

	var err error
	s.conn, err = net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	s.running = true
	s.logger.Printf("STUN服务器已启动，监听端口: %d, 公共IP: %s", s.port, s.publicIP.String())

	// 启动处理协程
	go s.serve()

	return nil
}

// Stop 停止STUN服务器
func (s *STUNServer) Stop() {
	if !s.running {
		return
	}

	close(s.stopChan)
	if s.conn != nil {
		s.conn.Close()
	}
	s.running = false
	s.logger.Printf("STUN服务器已停止")
}

// serve 处理STUN请求
func (s *STUNServer) serve() {
	buffer := make([]byte, 1024)

	for {
		select {
		case <-s.stopChan:
			return
		default:
			// 设置读取超时，以便能够检查停止信号
			s.conn.SetReadDeadline(time.Now().Add(1 * time.Second))

			n, addr, err := s.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					// 超时，继续循环
					continue
				}
				s.logger.Printf("读取STUN请求失败: %v", err)
				continue
			}

			// 解析STUN消息
			message := &stun.Message{Raw: buffer[:n]}
			if err := message.Decode(); err != nil {
				s.logger.Printf("解析STUN消息失败: %v", err)
				continue
			}

			// 检查是否是绑定请求
			if message.Type != stun.BindingRequest {
				continue
			}

			// 创建响应
			response := &stun.Message{
				Type: stun.BindingSuccess,
			}

			// 添加XOR-MAPPED-ADDRESS属性，使用VPN服务器的公共IP
			xorAddr := &stun.XORMappedAddress{
				IP:   s.publicIP,
				Port: addr.Port,
			}
			if err := xorAddr.AddTo(response); err != nil {
				s.logger.Printf("添加XOR-MAPPED-ADDRESS失败: %v", err)
				continue
			}

			// 添加SOFTWARE属性
			software := stun.NewSoftware("PekHight VPN STUN Server")
			if err := software.AddTo(response); err != nil {
				s.logger.Printf("添加SOFTWARE失败: %v", err)
				continue
			}

			// 发送响应
			if _, err := s.conn.WriteToUDP(response.Raw, addr); err != nil {
				s.logger.Printf("发送STUN响应失败: %v", err)
				continue
			}

			s.logger.Printf("已向 %s 发送STUN响应，返回IP: %s", addr.String(), s.publicIP.String())
		}
	}
}

// StartSTUNServer 启动STUN服务器的便捷函数
func StartSTUNServer(publicIP string, port int) (*STUNServer, error) {
	server, err := NewSTUNServer(publicIP, port)
	if err != nil {
		return nil, err
	}

	if err := server.Start(); err != nil {
		return nil, err
	}

	return server, nil
}
