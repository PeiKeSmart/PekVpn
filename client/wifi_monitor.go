package main

import (
	"fmt"
	"log"
	"runtime"
	"strings"
	"sync"
	"time"
)

// WiFiMonitor 结构体用于监控WiFi连接状态
type WiFiMonitor struct {
	isRunning      bool
	stopChan       chan struct{}
	mutex          sync.Mutex
	lastKnownSSID  string
	reconnectCount int
	maxReconnects  int
	onDisconnect   func()
	onReconnect    func(oldSSID, newSSID string)
}

// NewWiFiMonitor 创建一个新的WiFi监控器
func NewWiFiMonitor() *WiFiMonitor {
	return &WiFiMonitor{
		isRunning:     false,
		stopChan:      make(chan struct{}),
		reconnectCount: 0,
		maxReconnects: 5,
	}
}

// Start 开始监控WiFi连接
func (w *WiFiMonitor) Start() {
	w.mutex.Lock()
	if w.isRunning {
		w.mutex.Unlock()
		return
	}
	w.isRunning = true
	w.stopChan = make(chan struct{})
	w.mutex.Unlock()

	go w.monitorLoop()
	log.Printf("WiFi连接监控已启动")
}

// Stop 停止监控WiFi连接
func (w *WiFiMonitor) Stop() {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	
	if !w.isRunning {
		return
	}
	
	close(w.stopChan)
	w.isRunning = false
	log.Printf("WiFi连接监控已停止")
}

// SetDisconnectHandler 设置WiFi断开连接时的回调函数
func (w *WiFiMonitor) SetDisconnectHandler(handler func()) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.onDisconnect = handler
}

// SetReconnectHandler 设置WiFi重新连接时的回调函数
func (w *WiFiMonitor) SetReconnectHandler(handler func(oldSSID, newSSID string)) {
	w.mutex.Lock()
	defer w.mutex.Unlock()
	w.onReconnect = handler
}

// monitorLoop 监控WiFi连接状态的主循环
func (w *WiFiMonitor) monitorLoop() {
	// 初始化，获取当前WiFi连接信息
	currentSSID, err := w.getCurrentWiFiSSID()
	if err == nil && currentSSID != "" {
		w.mutex.Lock()
		w.lastKnownSSID = currentSSID
		w.mutex.Unlock()
		log.Printf("当前WiFi连接: %s", currentSSID)
	}

	checkInterval := 10 * time.Second
	for {
		select {
		case <-w.stopChan:
			return
		case <-time.After(checkInterval):
			w.checkWiFiStatus()
		}
	}
}

// checkWiFiStatus 检查WiFi状态并处理变化
func (w *WiFiMonitor) checkWiFiStatus() {
	// 获取当前WiFi连接信息
	currentSSID, err := w.getCurrentWiFiSSID()
	
	w.mutex.Lock()
	lastSSID := w.lastKnownSSID
	w.mutex.Unlock()
	
	// 检查WiFi是否断开
	if err != nil || currentSSID == "" {
		log.Printf("WiFi连接可能已断开: %v", err)
		
		// 检查是否真的断开了
		isConnected := w.isNetworkConnected()
		if !isConnected {
			log.Printf("确认WiFi已断开连接")
			
			// 调用断开连接回调
			w.mutex.Lock()
			if w.onDisconnect != nil {
				handler := w.onDisconnect
				w.mutex.Unlock()
				handler()
			} else {
				w.mutex.Unlock()
			}
			
			// 尝试修复WiFi连接
			w.tryFixWiFiConnection()
		}
		
		// 增加检查频率
		return
	}
	
	// 检查WiFi是否发生了变化（重连到不同的网络）
	if lastSSID != "" && currentSSID != lastSSID {
		log.Printf("WiFi连接已变化: %s -> %s", lastSSID, currentSSID)
		
		// 调用重连回调
		w.mutex.Lock()
		w.lastKnownSSID = currentSSID
		if w.onReconnect != nil {
			handler := w.onReconnect
			w.mutex.Unlock()
			handler(lastSSID, currentSSID)
		} else {
			w.mutex.Unlock()
		}
	} else if lastSSID == "" && currentSSID != "" {
		// 首次连接或从断开状态恢复
		log.Printf("WiFi已连接: %s", currentSSID)
		w.mutex.Lock()
		w.lastKnownSSID = currentSSID
		w.reconnectCount = 0 // 重置重连计数
		w.mutex.Unlock()
	}
}

// getCurrentWiFiSSID 获取当前连接的WiFi SSID
func (w *WiFiMonitor) getCurrentWiFiSSID() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("当前仅支持Windows系统")
	}
	
	// 使用netsh命令获取当前WiFi连接信息
	cmd := "netsh wlan show interfaces | findstr SSID"
	output, err := runCommand(cmd)
	if err != nil {
		return "", fmt.Errorf("获取WiFi信息失败: %v", err)
	}
	
	// 解析SSID
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "SSID") && !strings.Contains(line, "BSSID") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ssid := strings.TrimSpace(parts[1])
				return ssid, nil
			}
		}
	}
	
	return "", fmt.Errorf("未找到WiFi连接")
}

// isNetworkConnected 检查网络是否连接
func (w *WiFiMonitor) isNetworkConnected() bool {
	// 检查方法1: 尝试ping默认网关
	defaultGateway, err := getDefaultGateway()
	if err == nil {
		cmd := fmt.Sprintf("ping -n 1 -w 1000 %s", defaultGateway)
		_, err = runCommand(cmd)
		if err == nil {
			return true
		}
	}
	
	// 检查方法2: 尝试ping公共DNS
	cmd := "ping -n 1 -w 1000 8.8.8.8"
	_, err = runCommand(cmd)
	if err == nil {
		return true
	}
	
	// 检查方法3: 检查网络适配器状态
	cmd = "Get-NetAdapter | Where-Object {$_.MediaType -eq 'WiFi' -and $_.Status -eq 'Up'} | Select-Object -ExpandProperty Name"
	output, _ := runCommand(cmd)
	if strings.TrimSpace(output) != "" {
		// 有活跃的WiFi适配器，但可能没有互联网连接
		return true
	}
	
	return false
}

// tryFixWiFiConnection 尝试修复WiFi连接
func (w *WiFiMonitor) tryFixWiFiConnection() {
	w.mutex.Lock()
	reconnectCount := w.reconnectCount
	w.reconnectCount++
	w.mutex.Unlock()
	
	if reconnectCount >= w.maxReconnects {
		log.Printf("已达到最大重连尝试次数(%d)，不再尝试自动修复", w.maxReconnects)
		return
	}
	
	log.Printf("尝试修复WiFi连接 (尝试 %d/%d)", reconnectCount+1, w.maxReconnects)
	
	// 获取WiFi适配器
	cmd := "Get-NetAdapter | Where-Object {$_.MediaType -eq 'WiFi'} | Select-Object -ExpandProperty Name"
	output, err := runCommand(cmd)
	if err != nil || strings.TrimSpace(output) == "" {
		log.Printf("未找到WiFi适配器")
		return
	}
	
	wifiAdapters := strings.Split(strings.TrimSpace(output), "\n")
	for _, adapter := range wifiAdapters {
		adapter = strings.TrimSpace(adapter)
		if adapter == "" {
			continue
		}
		
		log.Printf("尝试重启WiFi适配器: %s", adapter)
		
		// 使用更温和的方式重启WiFi适配器
		w.restartWiFiAdapterGently(adapter)
	}
}

// restartWiFiAdapterGently 温和地重启WiFi适配器
func (w *WiFiMonitor) restartWiFiAdapterGently(adapter string) {
	// 1. 先尝试刷新WiFi连接而不是直接禁用/启用适配器
	cmd := "netsh wlan disconnect"
	_, _ = runCommand(cmd)
	time.Sleep(2 * time.Second)
	
	cmd = "netsh wlan connect name=\"" + w.lastKnownSSID + "\""
	_, _ = runCommand(cmd)
	
	// 等待连接建立
	time.Sleep(5 * time.Second)
	
	// 检查是否已连接
	if w.isNetworkConnected() {
		log.Printf("WiFi连接已恢复")
		return
	}
	
	// 2. 如果刷新连接失败，尝试禁用/启用适配器
	log.Printf("刷新WiFi连接失败，尝试禁用/启用适配器: %s", adapter)
	
	// 禁用适配器
	cmd = fmt.Sprintf("Disable-NetAdapter -Name \"%s\" -Confirm:$false", adapter)
	_, _ = runCommand(cmd)
	time.Sleep(3 * time.Second)
	
	// 启用适配器
	cmd = fmt.Sprintf("Enable-NetAdapter -Name \"%s\" -Confirm:$false", adapter)
	_, _ = runCommand(cmd)
	
	// 等待适配器启动
	time.Sleep(5 * time.Second)
	
	// 3. 尝试重新连接到已知网络
	if w.lastKnownSSID != "" {
		cmd = "netsh wlan connect name=\"" + w.lastKnownSSID + "\""
		_, _ = runCommand(cmd)
		time.Sleep(3 * time.Second)
	}
}

// GetWiFiNetworks 获取可用的WiFi网络列表
func (w *WiFiMonitor) GetWiFiNetworks() []string {
	if runtime.GOOS != "windows" {
		log.Printf("当前仅支持Windows系统")
		return nil
	}
	
	cmd := "netsh wlan show networks | findstr SSID"
	output, err := runCommand(cmd)
	if err != nil {
		log.Printf("获取WiFi网络列表失败: %v", err)
		return nil
	}
	
	var networks []string
	lines := strings.Split(output, "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if strings.Contains(line, "SSID") && !strings.Contains(line, "BSSID") {
			parts := strings.Split(line, ":")
			if len(parts) >= 2 {
				ssid := strings.TrimSpace(parts[1])
				if ssid != "" {
					networks = append(networks, ssid)
				}
			}
		}
	}
	
	return networks
}

// GetWiFiSignalStrength 获取当前WiFi信号强度
func (w *WiFiMonitor) GetWiFiSignalStrength() (int, error) {
	if runtime.GOOS != "windows" {
		return 0, fmt.Errorf("当前仅支持Windows系统")
	}
	
	cmd := "netsh wlan show interfaces | findstr Signal"
	output, err := runCommand(cmd)
	if err != nil {
		return 0, fmt.Errorf("获取WiFi信号强度失败: %v", err)
	}
	
	// 解析信号强度
	if strings.Contains(output, "%") {
		parts := strings.Split(output, ":")
		if len(parts) >= 2 {
			signalStr := strings.TrimSpace(parts[1])
			signalStr = strings.Replace(signalStr, "%", "", -1)
			var signal int
			_, err := fmt.Sscanf(signalStr, "%d", &signal)
			if err == nil {
				return signal, nil
			}
		}
	}
	
	return 0, fmt.Errorf("无法解析WiFi信号强度")
}
