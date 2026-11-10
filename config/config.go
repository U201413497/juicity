package config

import (
	"encoding/json"
	"os"
)

var (
	Version = "unknown"
)

type Config struct {
	// Client
	Server                string            `json:"server"`
	// PortRange 可选。例如 "50000-50050"。
	// 若为空，也会尝试从 server 解析 "host:50000-50050" 这种写法。
	PortRange             string            `json:"port_range,omitempty"`
	// PortHopInterval 秒。0 表示不主动周期跳，只在每次新建 QUIC 连接时随机端口。
	PortHopInterval       int               `json:"port_hop_interval,omitempty"`
	Uuid                  string            `json:"uuid"`
	Password              string            `json:"password"`
	Sni                   string            `json:"sni"`
	AllowInsecure         bool              `json:"allow_insecure"`
	PinnedCertChainSha256 string            `json:"pinned_certchain_sha256"`
	ProtectPath           string            `json:"protect_path"`
	Forward               map[string]string `json:"forward"`

	// Server
	Users                 map[string]string `json:"users"`
	Certificate           string            `json:"certificate"`
	PrivateKey            string            `json:"private_key"`
	Fwmark                string            `json:"fwmark"`
	SendThrough           string            `json:"send_through"`
	DialerLink            string            `json:"dialer_link"`
	DisableOutboundUdp443 bool              `json:"disable_outbound_udp443"`

	// Common
	Listen            string `json:"listen"`
	CongestionControl string `json:"congestion_control"`
	LogLevel          string `json:"log_level"`
}

func ReadConfig(p string) (*Config, error) {
	f, err := os.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var c Config
	if err = json.NewDecoder(f).Decode(&c); err != nil {
		return nil, err
	}
	return &c, nil
}
