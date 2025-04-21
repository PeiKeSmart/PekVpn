module github.com/pekhightvpn

go 1.24

require (
	github.com/armon/go-socks5 v0.0.0-20160902184237-e75332964ef5
	github.com/songgao/water v0.0.0-20200317203138-2b4b6d7c09d8
	github.com/xjasonlyu/tun2socks/v2 v2.5.2
	golang.org/x/crypto v0.37.0
	golang.org/x/net v0.39.0
	golang.zx2c4.com/wireguard v0.0.0-20231211153847-12269c276173
	golang.zx2c4.com/wireguard/wgctrl v0.0.0-20241231184526-a9ab2273dd10
)

require (
	github.com/Dreamacro/go-shadowsocks2 v0.1.8 // indirect
	github.com/ajg/form v1.5.1 // indirect
	github.com/docker/go-units v0.5.0 // indirect
	github.com/go-chi/chi/v5 v5.0.8 // indirect
	github.com/go-chi/cors v1.2.1 // indirect
	github.com/go-chi/render v1.0.2 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/google/uuid v1.3.0 // indirect
	github.com/gorilla/websocket v1.5.0 // indirect
	github.com/sirupsen/logrus v1.9.3 // indirect
	go.uber.org/atomic v1.11.0 // indirect
	go.uber.org/automaxprocs v1.5.2 // indirect
	golang.org/x/sys v0.32.0 // indirect
	golang.org/x/time v0.3.0 // indirect
	golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	gvisor.dev/gvisor v0.0.0-20230927004350-cbd86285d259 // indirect
)

// 本地模块替换
replace github.com/pekhightvpn/wireguard => ./wireguard
