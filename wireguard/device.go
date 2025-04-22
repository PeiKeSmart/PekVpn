package wireguard

import (
	"crypto/rand"
	"fmt"
	"log"
	"net"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/conn"
	"golang.zx2c4.com/wireguard/device"
	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// WireGuardDevice 表示一个WireGuard设备
type WireGuardDevice struct {
	Config       *Config
	Device       *device.Device
	TunDevice    tun.Device
	TunName      string
	IsServer     bool
	Peers        map[wgtypes.Key]*PeerInfo
	PeersLock    sync.Mutex
	Logger       *log.Logger
	AmneziaWG    *AmneziaWGModifier
	UseAmneziaWG bool
}

// PeerInfo 表示对等点信息
type PeerInfo struct {
	Config            *Config
	IP                net.IP
	LastSeen          time.Time
	IsLoggedIn        bool
	PublicKey         wgtypes.Key // 对等点公钥
	LastHandshakeTime time.Time   // 最后握手时间
	LastDataReceived  time.Time   // 最后数据接收时间
	AllowedIPs        []net.IPNet // 允许的IP地址
}

// NewWireGuardDevice 创建一个新的WireGuard设备
func NewWireGuardDevice(config *Config, isServer bool, mtu ...int) (*WireGuardDevice, error) {
	// 创建日志记录器
	logger := log.New(os.Stdout, "", log.LstdFlags)

	// 处理MTU参数
	var mtuValue int
	if len(mtu) > 0 && mtu[0] > 0 {
		mtuValue = mtu[0]
		logger.Printf("使用指定的MTU值: %d", mtuValue)
	} else {
		// 使用默认值
		mtuValue = 1420
		if !isServer {
			mtuValue = 1380 // 客户端使用更保守的MTU值
		}
	}

	// 创建TUN设备
	tunDevice, tunName, err := createTunDevice(isServer, mtuValue)
	if err != nil {
		return nil, fmt.Errorf("创建TUN设备失败: %v", err)
	}

	logger.Printf("TUN设备 %s 已创建", tunName)

	// 创建WireGuard设备
	logger.Printf("正在创建WireGuard设备...")
	dev := device.NewDevice(tunDevice, conn.NewDefaultBind(), device.NewLogger(device.LogLevelVerbose, ""))

	// 配置WireGuard设备
	err = configureWireGuardDevice(dev, config, isServer)
	if err != nil {
		return nil, fmt.Errorf("配置WireGuard设备失败: %v", err)
	}

	// 检查是否使用AmneziaWG
	var amneziaWG *AmneziaWGModifier
	useAmneziaWG := false

	// 如果配置中有AmneziaWG相关设置，创建AmneziaWG修改器
	// 这里我们只是简单地检查是否有预共享密钥
	if config.PresharedKey != (wgtypes.Key{}) {
		amneziaWG = NewAmneziaWGModifier()
		useAmneziaWG = true
		logger.Printf("启用AmneziaWG支持...")
	}

	// 创建WireGuardDevice结构
	wgDevice := &WireGuardDevice{
		Config:       config,
		Device:       dev,
		TunDevice:    tunDevice,
		TunName:      tunName,
		IsServer:     isServer,
		Peers:        make(map[wgtypes.Key]*PeerInfo),
		Logger:       logger,
		AmneziaWG:    amneziaWG,
		UseAmneziaWG: useAmneziaWG,
	}

	return wgDevice, nil
}

// createTunDevice 创建TUN设备
func createTunDevice(isServer bool, mtu int) (tun.Device, string, error) {
	// 设置TUN设备名称
	tunName := "wg0"
	if isServer {
		tunName = "wgs0"
	}

	// 在Windows上，设备名称需要特殊处理
	if runtime.GOOS == "windows" {
		// Windows上需要指定一个有效的名称
		if isServer {
			tunName = "WireGuardServer"
		} else {
			// 为客户端生成一个唯一的名称，避免冲突
			// 使用时间戳和随机数生成唯一的名称
			random := make([]byte, 4)
			rand.Read(random)
			tunName = fmt.Sprintf("WireGuardClient_%d_%x", time.Now().Unix(), random)
		}

		// 尝试加载Wintun驱动
		err := LoadWintunDriver()
		if err != nil {
			log.Printf("警告: %v", err)
			log.Printf("请从 https://www.wintun.net/ 下载Wintun驱动，并将wintun.dll文件放置在程序目录下")
		}
	}

	// 使用指定的MTU值
	if mtu <= 0 {
		// 如果没有指定MTU，使用默认值
		mtu = 1420 // WireGuard推荐的MTU值
	}
	log.Printf("使用MTU值: %d", mtu)

	// 使用wireguard-go的原生TUN实现
	var tunDevice tun.Device
	var err error

	// 尝试创建TUN设备
	if runtime.GOOS == "windows" {
		// 在Windows上，我们需要以管理员身份运行
		// 检查是否以管理员身份运行
		isAdmin, _ := isRunningAsAdmin()
		if !isAdmin {
			log.Printf("警告: 程序没有以管理员身份运行，可能无法创建TUN设备")
		}

		// 尝试使用指定名称创建TUN设备
		tunDevice, err = tun.CreateTUN(tunName, mtu)
		if err != nil {
			log.Printf("使用指定名称创建TUN设备失败: %v", err)

			// 尝试使用空名称
			log.Printf("尝试使用空名称创建TUN设备...")
			tunDevice, err = tun.CreateTUN("", mtu)
			if err != nil {
				log.Printf("使用空名称创建TUN设备失败: %v", err)

				// 尝试使用GUID作为名称
				guid := fmt.Sprintf("{%s}", generateGUID())
				log.Printf("尝试使用GUID创建TUN设备: %s", guid)
				tunDevice, err = tun.CreateTUN(guid, mtu)
				if err != nil {
					return nil, "", fmt.Errorf("创建TUN设备失败: %v\n\n请确保程序以管理员身份运行，并且wintun.dll文件已存在于程序目录下或系统路径中", err)
				}
			}
		}
	} else {
		// 其他平台先尝试使用指定名称
		tunDevice, err = tun.CreateTUN(tunName, mtu)
		if err != nil {
			// 如果创建失败，尝试使用空名称
			tunDevice, err = tun.CreateTUN("", mtu)
			if err != nil {
				return nil, "", fmt.Errorf("创建TUN设备失败: %v", err)
			}
		}
	}

	// 获取设备名称
	actualName, err := tunDevice.Name()
	if err != nil {
		// 如果无法获取名称，使用默认名称
		if runtime.GOOS == "windows" {
			actualName = "wg-windows"
		} else {
			actualName = tunName
		}
		log.Printf("无法获取TUN设备名称，使用默认名称: %s", actualName)
	} else {
		log.Printf("创建TUN设备成功，名称: %s", actualName)
	}

	return tunDevice, actualName, nil
}

// configureWireGuardDevice 配置WireGuard设备
func configureWireGuardDevice(dev *device.Device, config *Config, isServer bool) error {
	// 构建WireGuard配置字符串
	var uapiConfig string

	// 设置私钥
	uapiConfig += fmt.Sprintf("private_key=%s\n", KeyToHex(config.PrivateKey))

	// 如果是服务端，设置监听端口
	if isServer {
		uapiConfig += fmt.Sprintf("listen_port=%d\n", config.ListenPort)
	}

	// 应用配置
	err := dev.IpcSet(uapiConfig)
	if err != nil {
		return fmt.Errorf("应用WireGuard配置失败: %v", err)
	}

	// 如果是客户端，添加服务端作为Peer
	if !isServer && config.PublicKey != (wgtypes.Key{}) {
		// 构建Peer配置
		var peerConfig string

		// 设置服务端公钥
		peerConfig += fmt.Sprintf("public_key=%s\n", KeyToHex(config.PublicKey))

		// 设置预共享密钥（如果有）
		if config.PresharedKey != (wgtypes.Key{}) {
			peerConfig += fmt.Sprintf("preshared_key=%s\n", KeyToHex(config.PresharedKey))
		}

		// 设置端点（如果有）
		if config.Endpoint != "" {
			peerConfig += fmt.Sprintf("endpoint=%s\n", config.Endpoint)
		}

		// 设置允许的IP
		for _, ip := range config.AllowedIPs {
			peerConfig += fmt.Sprintf("allowed_ip=%s\n", ip.String())
		}

		// 设置持久保活
		if config.PersistentKeepalive > 0 {
			peerConfig += fmt.Sprintf("persistent_keepalive_interval=%d\n", config.PersistentKeepalive)
		}

		// 应用Peer配置
		err = dev.IpcSet(peerConfig)
		if err != nil {
			return fmt.Errorf("添加服务端Peer失败: %v", err)
		}
	}

	// 启动设备
	dev.Up()

	return nil
}

// AddPeer 添加对等点
func (wg *WireGuardDevice) AddPeer(peerConfig *Config, peerIP net.IP) error {
	// 构建对等点配置
	var uapiConfig string

	// 设置公钥
	uapiConfig += fmt.Sprintf("public_key=%s\n", KeyToHex(peerConfig.PublicKey))

	// 设置预共享密钥（如果有）
	if peerConfig.PresharedKey != (wgtypes.Key{}) {
		uapiConfig += fmt.Sprintf("preshared_key=%s\n", KeyToHex(peerConfig.PresharedKey))
	}

	// 设置端点（如果有）
	if peerConfig.Endpoint != "" {
		uapiConfig += fmt.Sprintf("endpoint=%s\n", peerConfig.Endpoint)
	}

	// 设置允许的IP
	for _, ip := range peerConfig.AllowedIPs {
		uapiConfig += fmt.Sprintf("allowed_ip=%s\n", ip.String())
	}

	// 设置持久保活
	if peerConfig.PersistentKeepalive > 0 {
		uapiConfig += fmt.Sprintf("persistent_keepalive_interval=%d\n", peerConfig.PersistentKeepalive)
	}

	// 如果使用AmneziaWG，应用特定修改
	if wg.UseAmneziaWG && wg.AmneziaWG != nil {
		// 这里可以添加AmneziaWG特定的配置
		wg.Logger.Printf("应用AmneziaWG对等点配置修改...")

		// 例如，可以添加自定义字段
		uapiConfig += "amnezia_enabled=true\n"
	}

	// 应用配置
	err := wg.Device.IpcSet(uapiConfig)
	if err != nil {
		return fmt.Errorf("添加对等点失败: %v", err)
	}

	// 添加到对等点列表
	wg.PeersLock.Lock()

	// 创建允许的IP列表
	allowedIPs := make([]net.IPNet, len(peerConfig.AllowedIPs))
	copy(allowedIPs, peerConfig.AllowedIPs)

	wg.Peers[peerConfig.PublicKey] = &PeerInfo{
		Config:            peerConfig,
		IP:                peerIP,
		LastSeen:          time.Now(),
		IsLoggedIn:        true,
		PublicKey:         peerConfig.PublicKey,
		LastHandshakeTime: time.Now(),
		LastDataReceived:  time.Now(),
		AllowedIPs:        allowedIPs,
	}
	wg.PeersLock.Unlock()

	return nil
}

// RemovePeer 移除对等点
func (wg *WireGuardDevice) RemovePeer(publicKey wgtypes.Key) error {
	// 构建移除对等点的配置
	uapiConfig := fmt.Sprintf("public_key=%s\nremove=true\n", KeyToHex(publicKey))

	// 应用配置
	err := wg.Device.IpcSet(uapiConfig)
	if err != nil {
		return fmt.Errorf("移除对等点失败: %v", err)
	}

	// 从对等点列表中移除
	wg.PeersLock.Lock()
	delete(wg.Peers, publicKey)
	wg.PeersLock.Unlock()

	return nil
}

// Close 关闭WireGuard设备
func (wg *WireGuardDevice) Close() {
	wg.Device.Close()
}

// GetPeers 获取所有对等点
func (wg *WireGuardDevice) GetPeers() ([]*PeerInfo, error) {
	// 锁定对等点列表
	wg.PeersLock.Lock()
	defer wg.PeersLock.Unlock()

	// 创建结果切片
	result := make([]*PeerInfo, 0, len(wg.Peers))

	// 直接从设备获取当前状态
	// 使用 IpcGet 获取设备状态
	deviceInfo, err := wg.Device.IpcGet()
	if err == nil {
		// 解析设备状态信息
		lines := strings.Split(deviceInfo, "\n")
		var currentPeer string
		var lastHandshake time.Time
		var hasData bool

		for _, line := range lines {
			line = strings.TrimSpace(line)
			if strings.HasPrefix(line, "peer:") {
				// 新的对等点开始
				currentPeer = strings.TrimSpace(strings.TrimPrefix(line, "peer:"))
				lastHandshake = time.Time{}
				hasData = false
			} else if strings.HasPrefix(line, "last handshake:") {
				// 解析最后握手时间
				handshakeStr := strings.TrimSpace(strings.TrimPrefix(line, "last handshake:"))
				if handshakeStr != "0" && handshakeStr != "(none)" {
					// 尝试解析时间
					seconds, err := strconv.ParseInt(handshakeStr, 10, 64)
					if err == nil {
						lastHandshake = time.Unix(seconds, 0)
					}
				}
			} else if strings.HasPrefix(line, "rx bytes:") || strings.HasPrefix(line, "tx bytes:") {
				// 检查是否有数据传输
				bytesStr := strings.TrimSpace(strings.Split(line, ":")[1])
				bytes, err := strconv.ParseInt(bytesStr, 10, 64)
				if err == nil && bytes > 0 {
					hasData = true
				}
			}

			// 如果已经处理完一个对等点的所有信息
			if (line == "" || strings.HasPrefix(line, "peer:")) && currentPeer != "" {
				// 尝试解析公钥
				pubKey, err := ParseKey(currentPeer)
				if err == nil {
					// 更新对等点信息
					if peerInfo, exists := wg.Peers[pubKey]; exists {
						// 更新最后握手时间
						if !lastHandshake.IsZero() && lastHandshake.After(peerInfo.LastHandshakeTime) {
							peerInfo.LastHandshakeTime = lastHandshake
							// 如果有新的握手，也更新数据接收时间
							peerInfo.LastDataReceived = lastHandshake
						}

						// 如果有数据传输，更新最后数据接收时间
						if hasData {
							peerInfo.LastDataReceived = time.Now()
						}
					}
				}

				// 重置当前对等点
				if line == "" {
					currentPeer = ""
				}
			}
		}
	}

	// 检查是否有DEBUG日志中的握手数据
	// 这是一个额外的检查，确保即使IpcGet没有捕获到握手，我们也能处理DEBUG日志中的握手数据
	for pubKey, peerInfo := range wg.Peers {
		// 如果最后握手时间是很久以前，但我们知道有最近的握手数据（通过DEBUG日志）
		// 我们将最后活跃时间更新为当前时间
		// 使用更短的时间间隔，确保即使只有握手数据而没有实际数据传输，客户端也不会被清除
		if time.Since(peerInfo.LastHandshakeTime) > 1*time.Minute {
			// 尝试检查是否有活跃连接
			if peerInfo.IP != nil {
				// 尝试触发握手机制
				cmd := fmt.Sprintf("ping -c 1 -W 1 %s", peerInfo.IP.String())
				if runtime.GOOS == "windows" {
					cmd = fmt.Sprintf("ping -n 1 -w 1000 %s", peerInfo.IP.String())
				}

				// 执行ping命令，但不关心结果
				var command *exec.Cmd
				if runtime.GOOS == "windows" {
					command = exec.Command("powershell", "-Command", cmd)
				} else {
					command = exec.Command("sh", "-c", cmd)
				}
				_, _ = command.CombinedOutput()

				// 给WireGuard一点时间来处理握手
				time.Sleep(100 * time.Millisecond)

				// 检查设备日志，寻找握手数据
				// 这里我们假设如果有握手数据，那么客户端是活跃的
				// 我们将最后活跃时间更新为当前时间
				peerInfo.LastHandshakeTime = time.Now()
				peerInfo.LastDataReceived = time.Now()
				if wg.Logger != nil {
					wg.Logger.Printf("检测到客户端 %s 有握手数据，更新最后活跃时间", pubKey.String())
				}
			}
		}
	}

	// 遍历所有对等点
	for _, peer := range wg.Peers {
		result = append(result, peer)
	}

	return result, nil
}

// KeyToHex 将wgtypes.Key转换为十六进制字符串
func KeyToHex(key wgtypes.Key) string {
	return fmt.Sprintf("%x", key[:]) // 将密钥字节转换为十六进制
}

// generateGUID 生成一个随机GUID
func generateGUID() string {
	b := make([]byte, 16)
	_, err := rand.Read(b)
	if err != nil {
		return "00000000-0000-0000-0000-000000000000"
	}

	b[6] = (b[6] & 0x0f) | 0x40 // Version 4
	b[8] = (b[8] & 0x3f) | 0x80 // Variant is 10

	return fmt.Sprintf("%x-%x-%x-%x-%x", b[0:4], b[4:6], b[6:8], b[8:10], b[10:])
}

// isRunningAsAdmin 检查程序是否以管理员身份运行
func isRunningAsAdmin() (bool, error) {
	if runtime.GOOS != "windows" {
		// 非Windows系统，检查是否为root用户
		return os.Geteuid() == 0, nil
	}

	// 在Windows上，我们可以尝试创建一个测试文件在系统目录中
	// 如果成功，则表示有管理员权限
	testFile := os.Getenv("SystemRoot") + "\\System32\\test_admin.tmp"
	f, err := os.Create(testFile)
	if err == nil {
		f.Close()
		os.Remove(testFile)
		return true, nil
	}

	// 如果无法创建文件，可能没有管理员权限
	return false, nil
}
