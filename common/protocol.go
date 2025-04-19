package common

import (
	"encoding/binary"
	"errors"
	"net"
)

const (
	// 数据包类型
	PacketTypeData    = 0x01 // 数据包
	PacketTypeControl = 0x02 // 控制包

	// 控制包子类型
	ControlTypeAuth      = 0x01 // 认证
	ControlTypeAuthReply = 0x02 // 认证回复
	ControlTypePing      = 0x03 // 心跳
	ControlTypePong      = 0x04 // 心跳回复

	// 认证结果
	AuthResultSuccess = 0x00 // 认证成功
	AuthResultFailed  = 0x01 // 认证失败

	// 包头长度
	HeaderSize = 4
)

// Packet 表示VPN协议的数据包
type Packet struct {
	Type    byte   // 包类型
	SubType byte   // 子类型
	Length  uint16 // 数据长度
	Data    []byte // 数据
}

// EncodePacket 将数据包编码为字节流
func EncodePacket(p *Packet) []byte {
	buf := make([]byte, HeaderSize+len(p.Data))
	buf[0] = p.Type
	buf[1] = p.SubType
	binary.BigEndian.PutUint16(buf[2:4], uint16(len(p.Data)))
	copy(buf[HeaderSize:], p.Data)
	return buf
}

// DecodePacket 从字节流解码数据包
func DecodePacket(data []byte) (*Packet, error) {
	if len(data) < HeaderSize {
		return nil, errors.New("数据包太短")
	}

	p := &Packet{
		Type:    data[0],
		SubType: data[1],
		Length:  binary.BigEndian.Uint16(data[2:4]),
	}

	if len(data) >= HeaderSize+int(p.Length) {
		p.Data = make([]byte, p.Length)
		copy(p.Data, data[HeaderSize:HeaderSize+int(p.Length)])
		return p, nil
	}

	return nil, errors.New("数据包不完整")
}

// CreateAuthPacket 创建认证包
func CreateAuthPacket(username, password string) *Packet {
	authData := append([]byte(username), 0)
	authData = append(authData, []byte(password)...)
	
	return &Packet{
		Type:    PacketTypeControl,
		SubType: ControlTypeAuth,
		Length:  uint16(len(authData)),
		Data:    authData,
	}
}

// CreateAuthReplyPacket 创建认证回复包
func CreateAuthReplyPacket(result byte) *Packet {
	return &Packet{
		Type:    PacketTypeControl,
		SubType: ControlTypeAuthReply,
		Length:  1,
		Data:    []byte{result},
	}
}

// CreateDataPacket 创建数据包
func CreateDataPacket(data []byte) *Packet {
	return &Packet{
		Type:    PacketTypeData,
		SubType: 0,
		Length:  uint16(len(data)),
		Data:    data,
	}
}

// CreatePingPacket 创建心跳包
func CreatePingPacket() *Packet {
	return &Packet{
		Type:    PacketTypeControl,
		SubType: ControlTypePing,
		Length:  0,
		Data:    []byte{},
	}
}

// CreatePongPacket 创建心跳回复包
func CreatePongPacket() *Packet {
	return &Packet{
		Type:    PacketTypeControl,
		SubType: ControlTypePong,
		Length:  0,
		Data:    []byte{},
	}
}

// Client 表示一个VPN客户端连接
type Client struct {
	Conn       net.Conn
	IP         net.IP
	Username   string
	IsLoggedIn bool
}
