package wireguard

import (
	"fmt"
	"net"

	"golang.zx2c4.com/wireguard/wgctrl/wgtypes"
)

// Config 表示WireGuard配置
type Config struct {
	PrivateKey          wgtypes.Key
	PublicKey           wgtypes.Key
	ListenPort          int
	Endpoint            string
	AllowedIPs          []net.IPNet
	PresharedKey        wgtypes.Key
	PersistentKeepalive int
}

// GeneratePrivateKey 生成WireGuard私钥
func GeneratePrivateKey() (wgtypes.Key, error) {
	return wgtypes.GeneratePrivateKey()
}

// GeneratePublicKey 从私钥生成公钥
func GeneratePublicKey(privateKey wgtypes.Key) wgtypes.Key {
	return privateKey.PublicKey()
}

// GeneratePresharedKey 生成预共享密钥
func GeneratePresharedKey() (wgtypes.Key, error) {
	return wgtypes.GenerateKey()
}

// ParseKey 从Base64字符串解析密钥
func ParseKey(b64 string) (wgtypes.Key, error) {
	return wgtypes.ParseKey(b64)
}

// NewServerConfig 创建服务端配置
func NewServerConfig(listenPort int) (*Config, error) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	publicKey := GeneratePublicKey(privateKey)

	return &Config{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ListenPort: listenPort,
	}, nil
}

// NewServerConfigWithKey 使用现有私钥创建服务端配置
func NewServerConfigWithKey(listenPort int, privateKey wgtypes.Key) (*Config, error) {
	publicKey := GeneratePublicKey(privateKey)

	return &Config{
		PrivateKey: privateKey,
		PublicKey:  publicKey,
		ListenPort: listenPort,
	}, nil
}

// NewClientConfig 创建客户端配置
func NewClientConfig(serverPublicKey wgtypes.Key, serverEndpoint string, allowedIPs []net.IPNet) (*Config, error) {
	privateKey, err := GeneratePrivateKey()
	if err != nil {
		return nil, fmt.Errorf("生成私钥失败: %v", err)
	}

	publicKey := GeneratePublicKey(privateKey)

	presharedKey, err := GeneratePresharedKey()
	if err != nil {
		return nil, fmt.Errorf("生成预共享密钥失败: %v", err)
	}

	return &Config{
		PrivateKey:          privateKey,
		PublicKey:           publicKey,
		Endpoint:            serverEndpoint,
		AllowedIPs:          allowedIPs,
		PresharedKey:        presharedKey,
		PersistentKeepalive: 25, // 25秒
	}, nil
}

// GetWireGuardConfigString 获取WireGuard配置文件内容
func (c *Config) GetWireGuardConfigString(isServer bool, clientConfigs []*Config) string {
	config := "[Interface]\n"
	config += fmt.Sprintf("PrivateKey = %s\n", c.PrivateKey.String())

	if isServer {
		config += fmt.Sprintf("ListenPort = %d\n", c.ListenPort)

		// 添加客户端配置
		for i, client := range clientConfigs {
			config += fmt.Sprintf("\n# Client %d\n", i+1)
			config += "[Peer]\n"
			config += fmt.Sprintf("PublicKey = %s\n", client.PublicKey.String())

			if client.PresharedKey != (wgtypes.Key{}) {
				config += fmt.Sprintf("PresharedKey = %s\n", client.PresharedKey.String())
			}

			for _, ip := range client.AllowedIPs {
				config += fmt.Sprintf("AllowedIPs = %s\n", ip.String())
			}
		}
	} else {
		// 客户端配置
		config += "[Peer]\n"
		config += fmt.Sprintf("PublicKey = %s\n", c.PublicKey.String())

		if c.PresharedKey != (wgtypes.Key{}) {
			config += fmt.Sprintf("PresharedKey = %s\n", c.PresharedKey.String())
		}

		if c.Endpoint != "" {
			config += fmt.Sprintf("Endpoint = %s\n", c.Endpoint)
		}

		for _, ip := range c.AllowedIPs {
			config += fmt.Sprintf("AllowedIPs = %s\n", ip.String())
		}

		if c.PersistentKeepalive > 0 {
			config += fmt.Sprintf("PersistentKeepalive = %d\n", c.PersistentKeepalive)
		}
	}

	return config
}

// AmneziaWGModify 应用AmneziaWG特定的修改
// AmneziaWG是WireGuard的一个修改版本，具有一些特定的变化
func AmneziaWGModify(config *Config) {
	// 创建AmneziaWG修改器
	modifier := NewAmneziaWGModifier()

	// 应用AmneziaWG修改
	modifier.ModifyConfig(config)
}
