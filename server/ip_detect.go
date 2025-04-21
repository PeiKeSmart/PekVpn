package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// 用于探测公网IP的API列表
var ipDetectionAPIs = []string{
	"https://api.ipify.org?format=json",
	"https://ipinfo.io/json",
	"https://api.ip.sb/jsonip",
	"https://api.myip.com",
}

// DetectPublicIP 探测服务器的公网IP
func DetectPublicIP() (string, error) {
	// 创建HTTP客户端，设置超时
	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	// 尝试使用多个API探测公网IP
	var lastErr error
	for _, api := range ipDetectionAPIs {
		ip, err := getPublicIPFromAPI(client, api)
		if err != nil {
			lastErr = err
			continue
		}
		if ip != "" {
			return ip, nil
		}
	}

	// 如果所有API都失败，尝试使用本地网络接口
	ip, err := getPublicIPFromInterfaces()
	if err != nil {
		if lastErr != nil {
			return "", fmt.Errorf("API探测失败: %v, 接口探测失败: %v", lastErr, err)
		}
		return "", err
	}

	return ip, nil
}

// getPublicIPFromAPI 从指定的API获取公网IP
func getPublicIPFromAPI(client *http.Client, apiURL string) (string, error) {
	// 发送HTTP请求
	resp, err := client.Get(apiURL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	// 读取响应内容
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}

	// 解析JSON响应
	var result map[string]interface{}
	if err := json.Unmarshal(body, &result); err != nil {
		return "", err
	}

	// 尝试从不同的字段获取IP
	for _, field := range []string{"ip", "IP", "query"} {
		if ip, ok := result[field].(string); ok && ip != "" {
			return ip, nil
		}
	}

	return "", fmt.Errorf("无法从API响应中解析IP地址")
}

// getPublicIPFromInterfaces 从本地网络接口获取可能的公网IP
func getPublicIPFromInterfaces() (string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "", err
	}

	for _, iface := range ifaces {
		// 跳过回环接口和非活动接口
		if iface.Flags&net.FlagLoopback != 0 || iface.Flags&net.FlagUp == 0 {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}

			// 跳过IPv6地址和私有IP
			if ip == nil || ip.IsLoopback() || ip.To4() == nil {
				continue
			}

			// 检查是否是私有IP
			if isPrivateIP(ip) {
				continue
			}

			return ip.String(), nil
		}
	}

	return "", fmt.Errorf("无法找到公网IP地址")
}

// isPrivateIP 检查IP是否是私有IP
func isPrivateIP(ip net.IP) bool {
	// 检查是否是私有IP范围
	privateIPBlocks := []string{
		"10.0.0.0/8",     // RFC1918
		"172.16.0.0/12",  // RFC1918
		"192.168.0.0/16", // RFC1918
		"169.254.0.0/16", // RFC3927 - 链路本地地址
		"127.0.0.0/8",    // RFC1122 - 本地回环
	}

	for _, block := range privateIPBlocks {
		_, ipnet, err := net.ParseCIDR(block)
		if err != nil {
			continue
		}
		if ipnet.Contains(ip) {
			return true
		}
	}
	return false
}

// GetOutboundIP 获取用于出站连接的本地IP
func GetOutboundIP() (net.IP, error) {
	// 使用UDP连接到一个公共IP（不需要真正建立连接）
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	// 获取本地地址
	localAddr := conn.LocalAddr().(*net.UDPAddr)
	return localAddr.IP, nil
}

// GetServerIP 获取服务器IP，优先使用用户指定的IP，否则自动探测
func GetServerIP(userSpecifiedIP string) (string, error) {
	if userSpecifiedIP != "" {
		// 验证用户指定的IP是否有效
		ip := net.ParseIP(userSpecifiedIP)
		if ip == nil {
			return "", fmt.Errorf("指定的IP地址无效: %s", userSpecifiedIP)
		}
		return userSpecifiedIP, nil
	}

	// 尝试探测公网IP
	ip, err := DetectPublicIP()
	if err != nil {
		// 如果探测失败，尝试获取出站IP
		outIP, outErr := GetOutboundIP()
		if outErr != nil {
			return "", fmt.Errorf("探测公网IP失败: %v, 获取出站IP失败: %v", err, outErr)
		}
		return outIP.String(), nil
	}

	return ip, nil
}
