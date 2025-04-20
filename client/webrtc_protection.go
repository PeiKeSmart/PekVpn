package main

import (
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// WebRTCProtection 实现WebRTC泄露防护
type WebRTCProtection struct {
	enabled       bool
	firewallRules []string // 存储添加的防火墙规则，以便后续清理
}

// NewWebRTCProtection 创建一个新的WebRTC泄露防护实例
func NewWebRTCProtection() *WebRTCProtection {
	return &WebRTCProtection{
		enabled:       false,
		firewallRules: []string{},
	}
}

// Enable 启用WebRTC泄露防护
func (p *WebRTCProtection) Enable() error {
	if p.enabled {
		log.Printf("WebRTC泄露防护已经启用")
		return nil
	}

	log.Printf("正在启用WebRTC泄露防护...")

	// 1. 添加防火墙规则阻止STUN/TURN请求
	err := p.addFirewallRules()
	if err != nil {
		return fmt.Errorf("添加防火墙规则失败: %v", err)
	}

	// 2. 创建浏览器配置文件
	err = p.createBrowserConfig()
	if err != nil {
		log.Printf("创建浏览器配置文件失败: %v", err)
		// 这不是致命错误，继续执行
	}

	// 3. 阻止常见的STUN服务器
	err = p.blockSTUNServers()
	if err != nil {
		log.Printf("阻止STUN服务器失败: %v", err)
		// 这不是致命错误，继续执行
	}

	p.enabled = true
	log.Printf("WebRTC泄露防护已启用")
	return nil
}

// Disable 禁用WebRTC泄露防护
func (p *WebRTCProtection) Disable() error {
	if !p.enabled {
		return nil
	}

	log.Printf("正在禁用WebRTC泄露防护...")

	// 移除防火墙规则
	err := p.removeFirewallRules()
	if err != nil {
		return fmt.Errorf("移除防火墙规则失败: %v", err)
	}

	p.enabled = false
	log.Printf("WebRTC泄露防护已禁用")
	return nil
}

// addFirewallRules 添加防火墙规则阻止WebRTC泄露
func (p *WebRTCProtection) addFirewallRules() error {
	// 根据操作系统添加不同的防火墙规则
	switch runtime.GOOS {
	case "windows":
		return p.addWindowsFirewallRules()
	case "linux":
		return p.addLinuxFirewallRules()
	case "darwin": // macOS
		return p.addMacOSFirewallRules()
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// removeFirewallRules 移除防火墙规则
func (p *WebRTCProtection) removeFirewallRules() error {
	// 根据操作系统移除不同的防火墙规则
	switch runtime.GOOS {
	case "windows":
		return p.removeWindowsFirewallRules()
	case "linux":
		return p.removeLinuxFirewallRules()
	case "darwin": // macOS
		return p.removeMacOSFirewallRules()
	default:
		return fmt.Errorf("不支持的操作系统: %s", runtime.GOOS)
	}
}

// addWindowsFirewallRules 添加Windows防火墙规则
func (p *WebRTCProtection) addWindowsFirewallRules() error {
	// 阻止常见的STUN/TURN端口
	stunPorts := []string{"3478", "3479", "5349", "5350", "19302"}

	for _, port := range stunPorts {
		// 阻止UDP出站流量到STUN/TURN端口
		ruleName := fmt.Sprintf("BlockWebRTC_UDP_Out_%s", port)
		cmd := fmt.Sprintf("netsh advfirewall firewall add rule name=\"%s\" dir=out action=block protocol=UDP remoteport=%s", ruleName, port)
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("添加防火墙规则失败: %v", err)
			continue
		}
		p.firewallRules = append(p.firewallRules, ruleName)

		// 阻止TCP出站流量到STUN/TURN端口
		ruleName = fmt.Sprintf("BlockWebRTC_TCP_Out_%s", port)
		cmd = fmt.Sprintf("netsh advfirewall firewall add rule name=\"%s\" dir=out action=block protocol=TCP remoteport=%s", ruleName, port)
		_, err = runCommand(cmd)
		if err != nil {
			log.Printf("添加防火墙规则失败: %v", err)
			continue
		}
		p.firewallRules = append(p.firewallRules, ruleName)
	}

	log.Printf("已添加Windows防火墙规则阻止WebRTC泄露")
	return nil
}

// removeWindowsFirewallRules 移除Windows防火墙规则
func (p *WebRTCProtection) removeWindowsFirewallRules() error {
	for _, ruleName := range p.firewallRules {
		cmd := fmt.Sprintf("netsh advfirewall firewall delete rule name=\"%s\"", ruleName)
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("移除防火墙规则失败: %v", err)
			// 继续尝试移除其他规则
		}
	}

	// 清空规则列表
	p.firewallRules = []string{}

	log.Printf("已移除Windows防火墙规则")
	return nil
}

// addLinuxFirewallRules 添加Linux防火墙规则
func (p *WebRTCProtection) addLinuxFirewallRules() error {
	// 检查iptables是否可用
	_, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("iptables未安装: %v", err)
	}

	// 阻止常见的STUN/TURN端口
	stunPorts := []string{"3478", "3479", "5349", "5350", "19302"}

	for _, port := range stunPorts {
		// 阻止UDP出站流量到STUN/TURN端口
		cmd := fmt.Sprintf("iptables -A OUTPUT -p udp --dport %s -j DROP", port)
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("添加iptables规则失败: %v", err)
			continue
		}

		// 阻止TCP出站流量到STUN/TURN端口
		cmd = fmt.Sprintf("iptables -A OUTPUT -p tcp --dport %s -j DROP", port)
		_, err = runCommand(cmd)
		if err != nil {
			log.Printf("添加iptables规则失败: %v", err)
			continue
		}
	}

	log.Printf("已添加Linux防火墙规则阻止WebRTC泄露")
	return nil
}

// removeLinuxFirewallRules 移除Linux防火墙规则
func (p *WebRTCProtection) removeLinuxFirewallRules() error {
	// 检查iptables是否可用
	_, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("iptables未安装: %v", err)
	}

	// 阻止常见的STUN/TURN端口
	stunPorts := []string{"3478", "3479", "5349", "5350", "19302"}

	for _, port := range stunPorts {
		// 移除UDP规则
		cmd := fmt.Sprintf("iptables -D OUTPUT -p udp --dport %s -j DROP", port)
		_, err := runCommand(cmd)
		if err != nil {
			log.Printf("移除iptables规则失败: %v", err)
			// 继续尝试移除其他规则
		}

		// 移除TCP规则
		cmd = fmt.Sprintf("iptables -D OUTPUT -p tcp --dport %s -j DROP", port)
		_, err = runCommand(cmd)
		if err != nil {
			log.Printf("移除iptables规则失败: %v", err)
			// 继续尝试移除其他规则
		}
	}

	log.Printf("已移除Linux防火墙规则")
	return nil
}

// addMacOSFirewallRules 添加macOS防火墙规则
func (p *WebRTCProtection) addMacOSFirewallRules() error {
	// 检查pfctl是否可用
	_, err := exec.LookPath("pfctl")
	if err != nil {
		return fmt.Errorf("pfctl未安装: %v", err)
	}

	// 创建临时pf规则文件
	ruleFile := "/tmp/webrtc_block.pf"

	// 编写pf规则
	rules := `
# Block WebRTC STUN/TURN ports
block out proto udp to any port {3478, 3479, 5349, 5350, 19302}
block out proto tcp to any port {3478, 3479, 5349, 5350, 19302}
`

	// 写入规则文件
	err = os.WriteFile(ruleFile, []byte(rules), 0644)
	if err != nil {
		return fmt.Errorf("创建pf规则文件失败: %v", err)
	}

	// 加载规则
	cmd := fmt.Sprintf("pfctl -f %s", ruleFile)
	_, err = runCommand(cmd)
	if err != nil {
		return fmt.Errorf("加载pf规则失败: %v", err)
	}

	// 启用pf
	cmd = "pfctl -e"
	_, err = runCommand(cmd)
	if err != nil {
		log.Printf("启用pf失败: %v", err)
		// 这不是致命错误，继续执行
	}

	log.Printf("已添加macOS防火墙规则阻止WebRTC泄露")
	return nil
}

// removeMacOSFirewallRules 移除macOS防火墙规则
func (p *WebRTCProtection) removeMacOSFirewallRules() error {
	// 检查pfctl是否可用
	_, err := exec.LookPath("pfctl")
	if err != nil {
		return fmt.Errorf("pfctl未安装: %v", err)
	}

	// 创建空的规则文件
	ruleFile := "/tmp/webrtc_block.pf"
	err = os.WriteFile(ruleFile, []byte(""), 0644)
	if err != nil {
		return fmt.Errorf("创建空pf规则文件失败: %v", err)
	}

	// 加载空规则，实际上是移除之前的规则
	cmd := fmt.Sprintf("pfctl -f %s", ruleFile)
	_, err = runCommand(cmd)
	if err != nil {
		return fmt.Errorf("移除pf规则失败: %v", err)
	}

	log.Printf("已移除macOS防火墙规则")
	return nil
}

// createBrowserConfig 创建浏览器配置文件
func (p *WebRTCProtection) createBrowserConfig() error {
	// 创建浏览器配置指南
	log.Printf("WebRTC泄露防护建议：")
	log.Printf("1. Chrome浏览器: 安装WebRTC Control扩展或在chrome://flags中禁用WebRTC")
	log.Printf("2. Firefox浏览器: 在about:config中设置media.peerconnection.enabled为false")
	log.Printf("3. Edge浏览器: 安装WebRTC Control扩展")

	return nil
}

// blockSTUNServers 阻止常见的STUN服务器
func (p *WebRTCProtection) blockSTUNServers() error {
	// 常见的STUN服务器
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

	// 在hosts文件中阻止这些服务器
	return p.addHostsEntries(stunServers)
}

// addHostsEntries 在hosts文件中添加条目
func (p *WebRTCProtection) addHostsEntries(domains []string) error {
	// 获取hosts文件路径
	hostsFile := ""
	switch runtime.GOOS {
	case "windows":
		hostsFile = os.Getenv("SystemRoot") + "\\System32\\drivers\\etc\\hosts"
	default:
		hostsFile = "/etc/hosts"
	}

	// 读取当前hosts文件内容
	content, err := os.ReadFile(hostsFile)
	if err != nil {
		return fmt.Errorf("读取hosts文件失败: %v", err)
	}

	// 检查是否已经有WebRTC防护标记
	if strings.Contains(string(content), "# WebRTC Protection") {
		log.Printf("hosts文件已包含WebRTC防护条目")
		return nil
	}

	// 添加新条目
	f, err := os.OpenFile(hostsFile, os.O_APPEND|os.O_WRONLY, 0644)
	if err != nil {
		return fmt.Errorf("打开hosts文件失败: %v", err)
	}
	defer f.Close()

	// 添加标记和条目
	_, err = f.WriteString("\n# WebRTC Protection\n")
	if err != nil {
		return fmt.Errorf("写入hosts文件失败: %v", err)
	}

	for _, domain := range domains {
		_, err = f.WriteString(fmt.Sprintf("127.0.0.1 %s\n", domain))
		if err != nil {
			return fmt.Errorf("写入hosts文件失败: %v", err)
		}
	}

	log.Printf("已在hosts文件中阻止%d个STUN服务器", len(domains))
	return nil
}

// IsEnabled 检查WebRTC泄露防护是否已启用
func (p *WebRTCProtection) IsEnabled() bool {
	return p.enabled
}

// CheckWebRTCLeak 检查WebRTC泄露
func (p *WebRTCProtection) CheckWebRTCLeak() (bool, error) {
	// 这个函数尝试检测是否存在WebRTC泄露
	// 由于这需要浏览器环境，我们只能提供一个简单的检查

	// 检查是否可以连接到常见的STUN服务器
	stunServer := "stun.l.google.com:19302"
	conn, err := net.DialTimeout("udp", stunServer, 5*time.Second)
	if err != nil {
		// 无法连接，可能是已经被阻止
		return false, nil
	}
	defer conn.Close()

	// 可以连接，可能存在泄露
	return true, nil
}
