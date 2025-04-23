package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"

	"github.com/pekhightvpn/wireguard"
)

// HeartbeatRequest 客户端心跳请求结构
type HeartbeatRequest struct {
	Command   string `json:"command"`
	PublicKey string `json:"public_key"`
	Secret    string `json:"secret"`
}

// HeartbeatResponse 客户端心跳响应结构
type HeartbeatResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// startHeartbeatService 启动心跳服务
func startHeartbeatService(serverEndpoint string, clientPublicKey string, config *wireguard.Config, stopCh <-chan struct{}) {
	// 解析服务器地址和端口
	host, portStr, err := net.SplitHostPort(serverEndpoint)
	if err != nil {
		log.Printf("解析服务器地址失败: %v", err)
		return
	}

	// 心跳服务使用注册服务端口
	regPort, _ := strconv.Atoi(portStr)
	regPort += 1
	heartbeatEndpoint := fmt.Sprintf("%s:%d", host, regPort)

	log.Printf("心跳服务已启动，服务器地址: %s", heartbeatEndpoint)

	// 每30秒发送一次心跳
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	// 立即发送第一次心跳
	sendHeartbeat(heartbeatEndpoint, clientPublicKey)

	for {
		select {
		case <-ticker.C:
			// 发送心跳
			sendHeartbeat(heartbeatEndpoint, clientPublicKey)
		case <-stopCh:
			// 停止心跳服务
			log.Printf("心跳服务已停止")
			return
		}
	}
}

// sendHeartbeat 发送心跳
func sendHeartbeat(heartbeatEndpoint string, clientPublicKey string) {
	// 解析服务器地址
	heartbeatAddr, err := net.ResolveUDPAddr("udp", heartbeatEndpoint)
	if err != nil {
		log.Printf("解析心跳服务地址失败: %v", err)
		return
	}

	// 创建心跳请求
	request := HeartbeatRequest{
		Command:   "HEARTBEAT",
		PublicKey: clientPublicKey,
		Secret:    *regSecret,
	}

	// 序列化请求
	requestJSON, err := json.Marshal(request)
	if err != nil {
		log.Printf("序列化心跳请求失败: %v", err)
		return
	}

	// 创建UDP连接
	heartbeatConn, err := net.DialUDP("udp", nil, heartbeatAddr)
	if err != nil {
		log.Printf("连接心跳服务失败: %v", err)
		return
	}
	defer heartbeatConn.Close()

	// 设置超时时间
	heartbeatConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发送心跳请求
	_, err = heartbeatConn.Write(requestJSON)
	if err != nil {
		log.Printf("发送心跳请求失败: %v", err)
		return
	}

	// 接收响应
	buf := make([]byte, 1024)
	n, _, err := heartbeatConn.ReadFromUDP(buf)
	if err != nil {
		log.Printf("接收心跳响应失败: %v", err)
		return
	}

	// 解析响应
	var response HeartbeatResponse
	if err := json.Unmarshal(buf[:n], &response); err != nil {
		log.Printf("解析心跳响应失败: %v", err)
		return
	}

	// 检查响应
	if !response.Success {
		log.Printf("心跳失败: %s", response.Message)
		return
	}

	// 心跳成功
	log.Printf("心跳成功: %s", response.Message)
}
