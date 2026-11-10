package common

import (
	"fmt"
	"math/rand"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	portHopRng   = rand.New(rand.NewSource(time.Now().UnixNano()))
	portHopRngMu sync.Mutex
)

// PortRange 表示闭区间端口范围。
type PortRange struct {
	Min uint16
	Max uint16
}

func (r PortRange) Valid() bool {
	return r.Min > 0 && r.Max >= r.Min
}

func (r PortRange) Single() bool {
	return r.Valid() && r.Min == r.Max
}

func (r PortRange) Pick() uint16 {
	if !r.Valid() {
		return 0
	}
	if r.Min == r.Max {
		return r.Min
	}
	portHopRngMu.Lock()
	defer portHopRngMu.Unlock()
	return r.Min + uint16(portHopRng.Intn(int(r.Max-r.Min)+1))
}

// ParsePortRange 解析 "50000-50050" 或 "443"。
func ParsePortRange(s string) (PortRange, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return PortRange{}, fmt.Errorf("empty port range")
	}
	if strings.Contains(s, "-") {
		parts := strings.SplitN(s, "-", 2)
		min64, err1 := strconv.ParseUint(strings.TrimSpace(parts[0]), 10, 16)
		max64, err2 := strconv.ParseUint(strings.TrimSpace(parts[1]), 10, 16)
		if err1 != nil || err2 != nil {
			return PortRange{}, fmt.Errorf("invalid port range: %q", s)
		}
		if min64 == 0 || max64 == 0 || max64 < min64 {
			return PortRange{}, fmt.Errorf("invalid port range bounds: %q", s)
		}
		return PortRange{Min: uint16(min64), Max: uint16(max64)}, nil
	}
	p, err := strconv.ParseUint(s, 10, 16)
	if err != nil || p == 0 {
		return PortRange{}, fmt.Errorf("invalid port: %q", s)
	}
	return PortRange{Min: uint16(p), Max: uint16(p)}, nil
}

// SplitServerHostPort 支持:
//   - host:443
//   - host:50000-50050
//   - [ipv6]:443
//   - [ipv6]:50000-50050
// 若 server 无范围，可用 fallbackRange（来自 port_range 字段）。
func SplitServerHostPort(server, fallbackRange string) (host string, pr PortRange, err error) {
	server = strings.TrimSpace(server)
	if server == "" {
		return "", PortRange{}, fmt.Errorf("empty server")
	}

	// 先按标准 SplitHostPort；失败则尝试把最后一段当范围。
	h, p, e := net.SplitHostPort(server)
	if e == nil {
		host = h
		pr, err = ParsePortRange(p)
		if err != nil {
			return "", PortRange{}, err
		}
	} else {
		// 可能是 host:50000-50050（标准库会报错）
		// 找最后一个 ':'
		i := strings.LastIndex(server, ":")
		if i <= 0 {
			return "", PortRange{}, fmt.Errorf("invalid server address: %q", server)
		}
		host = server[:i]
		// 去掉 IPv6 方括号
		host = strings.TrimPrefix(host, "[")
		host = strings.TrimSuffix(host, "]")
		pr, err = ParsePortRange(server[i+1:])
		if err != nil {
			return "", PortRange{}, fmt.Errorf("invalid server address: %q: %w", server, err)
		}
	}

	if fallbackRange != "" {
		fr, err2 := ParsePortRange(fallbackRange)
		if err2 != nil {
			return "", PortRange{}, err2
		}
		// 显式 port_range 优先覆盖
		pr = fr
	}
	if !pr.Valid() {
		return "", PortRange{}, fmt.Errorf("no valid port for server %q", server)
	}
	return host, pr, nil
}

// JoinHostPort 安全拼接 host + port。
func JoinHostPort(host string, port uint16) string {
	return net.JoinHostPort(host, strconv.Itoa(int(port)))
}
