package main

import (
	"log"
	"net"
	"strings"
	"sync"
	"time"
)

// DNSProxy 实现一个简单的DNS代理，根据域名选择不同的DNS服务器
type DNSProxy struct {
	listenAddr     string
	chinaDNS       []string
	foreignDNS     []string
	chinaDomains   []string
	mutex          sync.RWMutex
	running        bool
	conn           *net.UDPConn
	stopChan       chan struct{}
}

// NewDNSProxy 创建一个新的DNS代理
func NewDNSProxy() *DNSProxy {
	// 常见的中国域名后缀
	chinaDomains := []string{
		".cn", ".com.cn", ".net.cn", ".org.cn", ".gov.cn",
		"baidu.com", "alibaba.com", "tencent.com", "jd.com", "taobao.com",
		"qq.com", "weibo.com", "163.com", "126.com", "sina.com.cn",
		"sohu.com", "youku.com", "iqiyi.com", "bilibili.com", "douyin.com",
	}

	return &DNSProxy{
		listenAddr:   "127.0.0.1:53",
		chinaDNS:     []string{"114.114.114.114:53", "1.2.4.8:53"},
		foreignDNS:   []string{"8.8.8.8:53", "1.1.1.1:53"},
		chinaDomains: chinaDomains,
		stopChan:     make(chan struct{}),
	}
}

// Start 启动DNS代理
func (p *DNSProxy) Start() error {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if p.running {
		return nil
	}

	addr, err := net.ResolveUDPAddr("udp", p.listenAddr)
	if err != nil {
		return err
	}

	conn, err := net.ListenUDP("udp", addr)
	if err != nil {
		return err
	}

	p.conn = conn
	p.running = true

	go p.handleRequests()

	log.Printf("DNS代理已启动，监听地址: %s", p.listenAddr)
	return nil
}

// Stop 停止DNS代理
func (p *DNSProxy) Stop() {
	p.mutex.Lock()
	defer p.mutex.Unlock()

	if !p.running {
		return
	}

	close(p.stopChan)
	if p.conn != nil {
		p.conn.Close()
		p.conn = nil
	}
	p.running = false

	log.Printf("DNS代理已停止")
}

// handleRequests 处理DNS请求
func (p *DNSProxy) handleRequests() {
	buffer := make([]byte, 4096)

	for {
		select {
		case <-p.stopChan:
			return
		default:
			p.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, clientAddr, err := p.conn.ReadFromUDP(buffer)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				log.Printf("读取DNS请求失败: %v", err)
				continue
			}

			// 解析DNS请求，提取域名
			domain := p.extractDomain(buffer[:n])
			
			// 根据域名选择DNS服务器
			var dnsServer string
			if p.isChinaDomain(domain) {
				dnsServer = p.chinaDNS[0]
				log.Printf("域名 %s 使用中国DNS服务器 %s", domain, dnsServer)
			} else {
				dnsServer = p.foreignDNS[0]
				log.Printf("域名 %s 使用国外DNS服务器 %s", domain, dnsServer)
			}

			// 转发请求到选定的DNS服务器
			go p.forwardRequest(buffer[:n], clientAddr, dnsServer)
		}
	}
}

// extractDomain 从DNS请求中提取域名
func (p *DNSProxy) extractDomain(request []byte) string {
	// 这是一个简化的实现，实际上需要解析DNS协议
	// 这里仅作为示例，实际使用时需要完整解析DNS请求
	if len(request) < 12 {
		return ""
	}

	// 跳过DNS头部(12字节)
	pos := 12

	// 读取查询部分
	for pos < len(request) {
		// 读取标签长度
		labelLen := int(request[pos])
		if labelLen == 0 {
			break
		}

		// 移动到下一个标签
		pos += labelLen + 1
	}

	// 简单返回一个占位符
	return "example.com"
}

// isChinaDomain 判断是否为中国域名
func (p *DNSProxy) isChinaDomain(domain string) bool {
	domain = strings.ToLower(domain)
	for _, suffix := range p.chinaDomains {
		if strings.HasSuffix(domain, suffix) {
			return true
		}
	}
	return false
}

// forwardRequest 转发DNS请求到指定的DNS服务器
func (p *DNSProxy) forwardRequest(request []byte, clientAddr *net.UDPAddr, dnsServer string) {
	serverAddr, err := net.ResolveUDPAddr("udp", dnsServer)
	if err != nil {
		log.Printf("解析DNS服务器地址失败: %v", err)
		return
	}

	conn, err := net.DialUDP("udp", nil, serverAddr)
	if err != nil {
		log.Printf("连接DNS服务器失败: %v", err)
		return
	}
	defer conn.Close()

	// 发送请求
	_, err = conn.Write(request)
	if err != nil {
		log.Printf("发送DNS请求失败: %v", err)
		return
	}

	// 接收响应
	buffer := make([]byte, 4096)
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buffer)
	if err != nil {
		log.Printf("接收DNS响应失败: %v", err)
		return
	}

	// 将响应发送回客户端
	p.mutex.RLock()
	defer p.mutex.RUnlock()
	if p.running && p.conn != nil {
		_, err = p.conn.WriteToUDP(buffer[:n], clientAddr)
		if err != nil {
			log.Printf("发送DNS响应到客户端失败: %v", err)
		}
	}
}
