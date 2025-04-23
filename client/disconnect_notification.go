package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"strconv"
	"time"
)

// DisconnectRequest 客户端断开连接请求结构
type DisconnectRequest struct {
	Command   string `json:"command"`
	PublicKey string `json:"public_key"`
	Secret    string `json:"secret"`
}

// DisconnectResponse 客户端断开连接响应结构
type DisconnectResponse struct {
	Success bool   `json:"success"`
	Message string `json:"message"`
}

// sendDisconnectNotification 向服务器发送断开连接通知
func sendDisconnectNotification(serverEndpoint string, clientPublicKey string) {
	// 解析服务器地址和端口
	host, portStr, err := net.SplitHostPort(serverEndpoint)
	if err != nil {
		log.Printf("解析服务器地址失败: %v", err)
		return
	}

	// 断开连接通知使用注册服务端口
	regPort, _ := strconv.Atoi(portStr)
	regPort += 1
	disconnectEndpoint := fmt.Sprintf("%s:%d", host, regPort)

	log.Printf("发送断开连接通知到: %s", disconnectEndpoint)

	// 解析服务器地址
	disconnectAddr, err := net.ResolveUDPAddr("udp", disconnectEndpoint)
	if err != nil {
		log.Printf("解析断开连接服务地址失败: %v", err)
		return
	}

	// 创建断开连接请求
	request := DisconnectRequest{
		Command:   "DISCONNECT",
		PublicKey: clientPublicKey,
		Secret:    *regSecret,
	}

	// 序列化请求
	requestJSON, err := json.Marshal(request)
	if err != nil {
		log.Printf("序列化断开连接请求失败: %v", err)
		return
	}

	// 创建UDP连接
	disconnectConn, err := net.DialUDP("udp", nil, disconnectAddr)
	if err != nil {
		log.Printf("连接断开连接服务失败: %v", err)
		return
	}
	defer disconnectConn.Close()

	// 设置超时时间
	disconnectConn.SetDeadline(time.Now().Add(5 * time.Second))

	// 发送断开连接请求
	_, err = disconnectConn.Write(requestJSON)
	if err != nil {
		log.Printf("发送断开连接请求失败: %v", err)
		return
	}

	// 接收响应
	buf := make([]byte, 1024)
	n, _, err := disconnectConn.ReadFromUDP(buf)
	if err != nil {
		log.Printf("接收断开连接响应失败: %v", err)
		return
	}

	// 解析响应
	var response DisconnectResponse
	if err := json.Unmarshal(buf[:n], &response); err != nil {
		log.Printf("解析断开连接响应失败: %v", err)
		return
	}

	// 检查响应
	if !response.Success {
		log.Printf("断开连接失败: %s", response.Message)
		return
	}

	// 断开连接成功
	log.Printf("断开连接成功: %s", response.Message)
}
