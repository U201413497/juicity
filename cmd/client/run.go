package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/daeuniverse/outbound/netproxy"
	"github.com/daeuniverse/outbound/protocol"
	"github.com/daeuniverse/outbound/protocol/juicity"
	gliderLog "github.com/nadoo/glider/pkg/log"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"

	"github.com/juicity/juicity/cmd/internal/shared"
	"github.com/juicity/juicity/common"
	"github.com/juicity/juicity/config"
	"github.com/juicity/juicity/pkg/client/dialer"
	"github.com/juicity/juicity/pkg/log"
	"github.com/juicity/juicity/server"
)

var (
	logger = log.NewLogger(&log.Options{
		TimeFormat: time.DateTime,
	})

	runCmd = &cobra.Command{
		Use:   "run",
		Short: "To run juicity-client in the foreground.",
		Run: func(cmd *cobra.Command, args []string) {
			if _, ok := os.LookupEnv("QUIC_GO_DISABLE_GSO"); !ok {
				os.Setenv("QUIC_GO_DISABLE_GSO", "1")
			}
			arguments := shared.GetArguments()
			conf, err := arguments.GetConfig()
			if err != nil {
				logger.Fatal().Err(err).Msg("Failed to read config")
			}
			if logger, err = arguments.GetLogger(conf.LogLevel); err != nil {
				logger.Fatal().Err(err).Msg("Failed to init logger")
			}
			gliderLog.SetLogger(logger)

			go func() {
				if err := Serve(conf); err != nil {
					logger.Fatal().Err(err).Send()
				}
			}()
			sigs := make(chan os.Signal, 1)
			signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP, syscall.SIGQUIT, syscall.SIGILL)
			for sig := range sigs {
				logger.Warn().Str("signal", sig.String()).Msg("Exiting")
				return
			}
		},
	}
)

// hoppingDialer 在每次拨号时把目标换成 host:范围内随机端口。
// 这样即使 daeuniverse/outbound 的 juicity.Dialer 持有固定 ProxyAddress，
// 只要底层 UDP dial 的 addr 被改写，就能实现端口跳跃。
type hoppingDialer struct {
	base   netproxy.Dialer
	host   string
	ports  common.PortRange
	mu     sync.Mutex
	cur    string // 当前选用的 host:port，便于日志
}

func newHoppingDialer(base netproxy.Dialer, host string, ports common.PortRange) *hoppingDialer {
	h := &hoppingDialer{base: base, host: host, ports: ports}
	h.cur = common.JoinHostPort(host, ports.Pick())
	return h
}

func (h *hoppingDialer) Current() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.cur
}

func (h *hoppingDialer) PickNew() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.cur = common.JoinHostPort(h.host, h.ports.Pick())
	return h.cur
}

func (h *hoppingDialer) DialContext(ctx context.Context, network string, addr string) (netproxy.Conn, error) {
	// juicity 拨号时会 DialContext(..., proxyAddress)
	// 无论传入的是哪个固定地址，都改写到当前/新随机端口。
	target := h.Current()
	// 每次 UDP 拨号都换端口（真正的连接级跳跃）
	if !h.ports.Single() {
		target = h.PickNew()
		logger.Info().Str("proxy", target).Msg("port hop: dial")
	}
	return h.base.DialContext(ctx, network, target)
}

func buildTLS(conf *config.Config, sni string) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		NextProtos:         []string{"h3"},
		MinVersion:         tls.VersionTLS13,
		ServerName:         sni,
		InsecureSkipVerify: conf.AllowInsecure,
	}
	if conf.PinnedCertChainSha256 != "" {
		pinnedHash, err := base64.URLEncoding.DecodeString(conf.PinnedCertChainSha256)
		if err != nil {
			pinnedHash, err = base64.StdEncoding.DecodeString(conf.PinnedCertChainSha256)
			if err != nil {
				pinnedHash, err = hex.DecodeString(conf.PinnedCertChainSha256)
				if err != nil {
					return nil, fmt.Errorf("failed to decode PinnedCertChainSha256")
				}
			}
		}
		tlsConfig.InsecureSkipVerify = true
		tlsConfig.VerifyPeerCertificate = func(rawCerts [][]byte, verifiedChains [][]*x509.Certificate) error {
			if !bytes.Equal(common.GenerateCertChainHash(rawCerts), pinnedHash) {
				return fmt.Errorf("pinned hash of cert chain does not match")
			}
			return nil
		}
	}
	return tlsConfig, nil
}

func newJuicityDialer(conf *config.Config, host string, ports common.PortRange, tlsConfig *tls.Config) (netproxy.Dialer, error) {
	// ProxyAddress 给一个合法初始值；实际拨号由 hoppingDialer 改写端口。
	proxyAddr := common.JoinHostPort(host, ports.Pick())
	base := dialer.NewClientDialer(conf)
	hop := newHoppingDialer(base, host, ports)

	d, err := juicity.NewDialer(hop, protocol.Header{
		ProxyAddress: proxyAddr,
		Feature1:     conf.CongestionControl,
		TlsConfig:    tlsConfig,
		User:         conf.Uuid,
		Password:     conf.Password,
		IsClient:     true,
		Flags:        0,
	})
	if err != nil {
		return nil, err
	}
	return d, nil
}

func Serve(conf *config.Config) error {
	host, ports, err := common.SplitServerHostPort(conf.Server, conf.PortRange)
	if err != nil {
		return fmt.Errorf("parse server/port: %w", err)
	}

	if conf.Sni == "" {
		conf.Sni = host
	}
	tlsConfig, err := buildTLS(conf, conf.Sni)
	if err != nil {
		return err
	}

	d, err := newJuicityDialer(conf, host, ports, tlsConfig)
	if err != nil {
		return err
	}

	logger.Info().
		Str("host", host).
		Uint16("port_min", ports.Min).
		Uint16("port_max", ports.Max).
		Int("hop_interval_sec", conf.PortHopInterval).
		Msg("juicity client port hop config")

	if conf.Listen == "" && len(conf.Forward) == 0 {
		logger.Fatal().Msg("Please fill in at least one of `listen` and `forward` in the config file.")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	wg := pool.New().WithErrors().WithContext(ctx).WithCancelOnError()

	if conf.Listen != "" {
		s, err := server.NewMixed("mixed://"+conf.Listen, d)
		if err != nil {
			return err
		}
		wg.Go(func(ctx context.Context) error {
			ch := make(chan struct{}, 1)
			go func() {
				s.ListenAndServe()
				ch <- struct{}{}
			}()
			select {
			case <-ch:
				return fmt.Errorf("ListenAndServe: unexpected error")
			case <-ctx.Done():
				return nil
			}
		})
	}

	if len(conf.Forward) != 0 {
		for local, remote := range conf.Forward {
			local, remote := local, remote
			forwarder, err := server.NewForwarder(server.ForwarderOptions{
				Logger:     logger,
				Dialer:     d,
				LocalAddr:  local,
				RemoteAddr: remote,
			})
			if err != nil {
				return err
			}
			wg.Go(func(ctx context.Context) (err error) {
				ch := make(chan error, 1)
				go func() {
					ch <- forwarder.Serve()
				}()
				select {
				case err := <-ch:
					return err
				case <-ctx.Done():
					return nil
				}
			})
		}
	}

	// 可选：周期强制换端口（通过再包一层无法关掉已有 QUIC；
	// 真正断旧连需要 outbound 支持。这里保留字段以便 Husi 写入，
	// 实际「每次 dial 换端口」已由 hoppingDialer 完成。）
	if conf.PortHopInterval > 0 && !ports.Single() {
		wg.Go(func(ctx context.Context) error {
			t := time.NewTicker(time.Duration(conf.PortHopInterval) * time.Second)
			defer t.Stop()
			for {
				select {
				case <-ctx.Done():
					return nil
				case <-t.C:
					logger.Info().Msg("port hop interval tick (next dial will use a new port)")
				}
			}
		})
	}

	return wg.Wait()
}

func init() {
	rootCmd.Version = shared.GetVersion(cgoEnabled)
	rootCmd.AddCommand(runCmd)
	shared.InitArgumentsFlags(runCmd)
}
