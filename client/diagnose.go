package main

import (
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strings"
	"time"

	"github.com/pekhightvpn/wireguard"
)

// DiagnoseProblem 诊断VPN连接问题
// 此函数可以帮助确定无法联网是客户端连接问题还是服务端转发问题
func DiagnoseProblem(config *wireguard.Config, wgDevice *wireguard.WireGuardDevice) {
	log.Printf("开始连接诊断...")

	// 1. 测试与服务器的直接连接
	log.Printf("测试与服务器的直接连接...")
	host, _, err := net.SplitHostPort(config.Endpoint)
	if err != nil {
		log.Printf("解析服务器地址失败: %v", err)
		return
	}

	// 测试ICMP ping
	pingCmd := fmt.Sprintf("ping -n 3 -w 1000 %s", host)
	pingOutput, _ := runCommand(pingCmd) // 使用main包中的runCommand函数
	if strings.Contains(pingOutput, "TTL=") || strings.Contains(pingOutput, "字节=") {
		log.Printf("服务器PING测试成功: %s", host)
	} else {
		log.Printf("服务器PING测试失败: %s", host)
		log.Printf("诊断结果: 无法连接到VPN服务器，请检查网络连接或服务器是否在线")
		return
	}

	// 测试UDP端口
	udpAddr, err := net.ResolveUDPAddr("udp", config.Endpoint)
	if err != nil {
		log.Printf("解析服务器UDP地址失败: %v", err)
		return
	}

	udpConn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		log.Printf("无法连接到服务器UDP端口: %v", err)
		log.Printf("诊断结果: 服务器的UDP端口可能被阻止，请检查防火墙设置")
		return
	}
	udpConn.Close()
	log.Printf("服务器UDP端口连接成功: %s", config.Endpoint)

	// 2. 测试VPN隧道是否建立
	log.Printf("测试VPN隧道是否建立...")

	// 检查TUN设备是否存在并正常工作
	if wgDevice == nil || wgDevice.TunName == "" {
		log.Printf("诊断结果: TUN设备创建失败或未初始化")
		return
	}

	// 检查TUN设备是否正常工作
	if runtime.GOOS == "windows" {
		cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.Name -eq '%s' -or $_.InterfaceDescription -like '*WireGuard*'} | Select-Object -ExpandProperty Status", wgDevice.TunName)
		output, _ := runCommand(cmd)
		if strings.Contains(output, "Up") {
			log.Printf("TUN设备状态正常: %s", wgDevice.TunName)
		} else {
			log.Printf("诊断结果: TUN设备状态异常: %s", output)
			return
		}
	}

	// 3. 测试数据包是否能通过VPN隧道
	log.Printf("测试数据包是否能通过VPN隧道...")

	// 获取VPN网段的第一个IP地址（通常是服务器地址）
	_, ipNet, _ := net.ParseCIDR(config.AllowedIPs[0].String())
	if ipNet == nil {
		log.Printf("无法解析VPN网段: %s", config.AllowedIPs[0].String())
		return
	}

	// 将IP网段转换为第一个IP地址
	firstIP := ipNet.IP
	// 如果是0.0.0.0/0，使用服务器的内网IP
	if firstIP.IsUnspecified() {
		firstIP = net.ParseIP("10.9.0.1") // 假设服务器内网IP是10.9.0.1
	}

	// 测试ping VPN内网地址
	pingVpnCmd := fmt.Sprintf("ping -n 3 -w 1000 %s", firstIP.String())
	pingVpnOutput, _ := runCommand(pingVpnCmd)
	if strings.Contains(pingVpnOutput, "TTL=") || strings.Contains(pingVpnOutput, "字节=") {
		log.Printf("VPN内网PING测试成功: %s", firstIP.String())
	} else {
		log.Printf("VPN内网PING测试失败: %s", firstIP.String())
		log.Printf("诊断结果: VPN隧道已建立，但无法与服务器通信，可能是服务器配置问题")
		return
	}

	// 4. 测试DNS解析
	log.Printf("测试DNS解析...")
	domains := []string{"www.baidu.com", "www.google.com"}
	dnsSuccess := false
	for _, domain := range domains {
		start := time.Now()
		ips, err := net.LookupIP(domain)
		if err != nil {
			log.Printf("DNS解析失败: %s: %v", domain, err)
			continue
		}
		elapsed := time.Since(start)
		log.Printf("DNS解析成功: %s -> %v, 耗时: %v", domain, ips, elapsed)
		dnsSuccess = true
		break
	}

	if !dnsSuccess {
		log.Printf("诊断结果: VPN隧道工作正常，但DNS解析失败，可能是DNS配置问题")
		return
	}

	// 5. 测试HTTP访问
	log.Printf("测试HTTP访问...")
	sites := []string{
		"https://www.baidu.com",
		"https://www.google.com",
	}

	httpSuccess := false
	for _, site := range sites {
		start := time.Now()
		client := &http.Client{
			Timeout: 5 * time.Second,
		}
		req, _ := http.NewRequest("GET", site, nil)
		req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36")
		resp, err := client.Do(req)
		if err != nil {
			log.Printf("HTTP访问失败: %s: %v", site, err)
			continue
		}
		defer resp.Body.Close()
		elapsed := time.Since(start)
		log.Printf("HTTP访问成功: %s, 状态码: %d, 耗时: %v", site, resp.StatusCode, elapsed)
		httpSuccess = true
		break
	}

	if !httpSuccess {
		log.Printf("诊断结果: VPN隧道和DNS工作正常，但HTTP访问失败，可能是服务器转发问题")
		return
	}

	// 6. 测试路由表
	log.Printf("检查路由表...")
	routeCmd := "route print"
	routeOutput, _ := runCommand(routeCmd)

	// 检查是否有默认路由指向TUN设备
	if strings.Contains(routeOutput, "0.0.0.0") {
		log.Printf("存在默认路由，检查是否指向TUN设备")

		// 获取TUN设备的接口索引
		cmd := fmt.Sprintf("Get-NetAdapter | Where-Object {$_.Name -eq '%s' -or $_.InterfaceDescription -like '*WireGuard*'} | Select-Object -ExpandProperty ifIndex", wgDevice.TunName)
		ifIndex, _ := runCommand(cmd)
		ifIndex = strings.TrimSpace(ifIndex)

		if strings.Contains(routeOutput, fmt.Sprintf("0.0.0.0.*%s", ifIndex)) {
			log.Printf("默认路由正确指向TUN设备: %s", ifIndex)
		} else {
			log.Printf("诊断结果: 默认路由可能未正确指向TUN设备")
			return
		}
	}

	// 检查服务器特殊路由
	serverIP := net.ParseIP(host)
	if serverIP != nil {
		if strings.Contains(routeOutput, serverIP.String()) {
			log.Printf("服务器特殊路由存在: %s", serverIP.String())
		} else {
			log.Printf("诊断结果: 服务器特殊路由不存在，可能导致路由循环")
			return
		}
	}

	log.Printf("诊断完成: 所有测试通过，VPN连接正常工作")
}

// RunDiagnosis 运行诊断并返回结果
func RunDiagnosis(config *wireguard.Config, wgDevice *wireguard.WireGuardDevice) string {
	// 捕获日志输出
	var logBuffer strings.Builder
	originalOutput := log.Writer()
	log.SetOutput(&logBuffer)

	// 运行诊断
	DiagnoseProblem(config, wgDevice)

	// 恢复原始日志输出
	log.SetOutput(originalOutput)

	// 返回诊断结果
	return logBuffer.String()
}
