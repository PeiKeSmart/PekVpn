package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"sync"
)

// AuthStore 存储VPN客户端公钥与SOCKS5认证信息的关联
type AuthStore struct {
	// 公钥 -> 认证信息的映射
	authMap map[string]AuthInfo
	// 互斥锁，保护map的并发访问
	mutex sync.RWMutex
}

// AuthInfo 存储SOCKS5认证信息
type AuthInfo struct {
	Username string
	Password string
}

// NewAuthStore 创建一个新的认证信息存储
func NewAuthStore() *AuthStore {
	return &AuthStore{
		authMap: make(map[string]AuthInfo),
	}
}

// AddOrUpdate 添加或更新认证信息
func (a *AuthStore) AddOrUpdate(publicKey string, username, password string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	a.authMap[publicKey] = AuthInfo{
		Username: username,
		Password: password,
	}
}

// Get 获取认证信息
func (a *AuthStore) Get(publicKey string) (AuthInfo, bool) {
	a.mutex.RLock()
	defer a.mutex.RUnlock()

	info, exists := a.authMap[publicKey]
	return info, exists
}

// Remove 移除认证信息
func (a *AuthStore) Remove(publicKey string) {
	a.mutex.Lock()
	defer a.mutex.Unlock()

	delete(a.authMap, publicKey)
}

// GenerateAuthInfo 根据公钥生成唯一的认证信息
func GenerateAuthInfo(publicKey string, regSecret string) AuthInfo {
	// 使用公钥和注册密钥生成唯一的用户名和密码
	hash := sha256.Sum256([]byte(publicKey + regSecret))
	username := "vpn_" + base64.RawURLEncoding.EncodeToString(hash[:8])
	password := base64.RawURLEncoding.EncodeToString(hash[8:24])

	return AuthInfo{
		Username: username,
		Password: password,
	}
}

// GetAuthInfoForClient 获取客户端的认证信息，如果不存在则生成
func (a *AuthStore) GetAuthInfoForClient(publicKey string, regSecret string) AuthInfo {
	a.mutex.RLock()
	info, exists := a.authMap[publicKey]
	a.mutex.RUnlock()

	if !exists {
		// 生成新的认证信息
		info = GenerateAuthInfo(publicKey, regSecret)
		a.AddOrUpdate(publicKey, info.Username, info.Password)
	}

	return info
}

// String 返回认证信息的字符串表示
func (a AuthInfo) String() string {
	return fmt.Sprintf("Username: %s, Password: %s", a.Username, a.Password)
}
