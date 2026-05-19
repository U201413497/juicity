package consts

import (
	"time"
)

// default value for relay (internal/relay)
const (
	EthernetMtu       = 1280
	DefaultNatTimeout = 3 * time.Minute
	DnsQueryTimeout   = 17 * time.Second // RFC 5452
)
