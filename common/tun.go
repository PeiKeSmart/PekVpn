package common

import (
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"

	"github.com/songgao/water"
)

// SetupTun 创建并配置TUN设备
func SetupTun(name string, ipNet *net.IPNet, mtu int) (*water.Interface, error) {
	config := water.Config{
		DeviceType: water.TUN,
	}
	
	// 在Windows上，我们需要指定网络组件名称
	if runtime.GOOS == "windows" {
		config.PlatformSpecificParams = water.PlatformSpecificParams{
			ComponentID: "tap0901",
			Network:     "192.168.1.0/24",
		}
	} else if name != "" {
		config.Name = name
	}

	// 创建TUN设备
	ifce, err := water.New(config)
	if err != nil {
		return nil, fmt.Errorf("创建TUN设备失败: %v", err)
	}

	// 配置TUN设备
	err = configureTun(ifce.Name(), ipNet, mtu)
	if err != nil {
		return nil, fmt.Errorf("配置TUN设备失败: %v", err)
	}

	return ifce, nil
}

// configureTun 根据操作系统配置TUN设备
func configureTun(name string, ipNet *net.IPNet, mtu int) error {
	var err error
	
	switch runtime.GOOS {
	case "linux":
		// 设置IP地址
		cmd := exec.Command("ip", "addr", "add", ipNet.String(), "dev", name)
		if err = cmd.Run(); err != nil {
			return err
		}
		
		// 设置MTU
		cmd = exec.Command("ip", "link", "set", "dev", name, "mtu", fmt.Sprintf("%d", mtu))
		if err = cmd.Run(); err != nil {
			return err
		}
		
		// 启用设备
		cmd = exec.Command("ip", "link", "set", "dev", name, "up")
		if err = cmd.Run(); err != nil {
			return err
		}
		
	case "darwin": // macOS
		// 设置IP地址
		cmd := exec.Command("ifconfig", name, "inet", ipNet.IP.String(), ipNet.IP.String(), "netmask", "255.255.255.0", "mtu", fmt.Sprintf("%d", mtu), "up")
		if err = cmd.Run(); err != nil {
			return err
		}
		
	case "windows":
		// 在Windows上，我们需要使用netsh命令
		ip := ipNet.IP.String()
		mask := net.IP(ipNet.Mask).String()
		
		// 设置IP地址
		cmd := exec.Command("netsh", "interface", "ip", "set", "address", name, "static", ip, mask)
		if err = cmd.Run(); err != nil {
			return err
		}
		
		// 设置MTU
		cmd = exec.Command("netsh", "interface", "ipv4", "set", "subinterface", name, fmt.Sprintf("mtu=%d", mtu))
		if err = cmd.Run(); err != nil {
			return err
		}
		
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
	
	return nil
}

// AddRoute 添加路由
func AddRoute(network, tunName string) error {
	var cmd *exec.Cmd
	
	switch runtime.GOOS {
	case "linux":
		cmd = exec.Command("ip", "route", "add", network, "dev", tunName)
	case "darwin": // macOS
		cmd = exec.Command("route", "add", "-net", network, "-interface", tunName)
	case "windows":
		// 解析网络和掩码
		parts := strings.Split(network, "/")
		if len(parts) != 2 {
			return fmt.Errorf("无效的网络格式: %s", network)
		}
		
		ip := parts[0]
		maskLen := parts[1]
		
		// 计算子网掩码
		mask := ""
		switch maskLen {
		case "8":
			mask = "255.0.0.0"
		case "16":
			mask = "255.255.0.0"
		case "24":
			mask = "255.255.255.0"
		default:
			return fmt.Errorf("不支持的掩码长度: %s", maskLen)
		}
		
		cmd = exec.Command("route", "add", ip, "mask", mask, "0.0.0.0", "metric", "1")
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
	
	return cmd.Run()
}
