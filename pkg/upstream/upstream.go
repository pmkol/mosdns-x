/*
 * Copyright (C) 2020-2022, IrineSistiana
 *
 * This file is part of mosdns.
 *
 * mosdns is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * mosdns is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

package upstream

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"gitlab.com/go-extension/http"
	eTLS "gitlab.com/go-extension/tls"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/upstream/bootstrap"
	"github.com/pmkol/mosdns-x/pkg/upstream/doh"
	"github.com/pmkol/mosdns-x/pkg/upstream/doh3"
	mQUIC "github.com/pmkol/mosdns-x/pkg/upstream/quic"
	"github.com/pmkol/mosdns-x/pkg/upstream/transport"
	"github.com/pmkol/mosdns-x/pkg/upstream/udp"
)

// Upstream represents a DNS upstream.
type Upstream interface {
	// ExchangeContext exchanges query message m to the upstream, and returns
	// response. It MUST NOT keep or modify m.
	ExchangeContext(ctx context.Context, m *dns.Msg) (*dns.Msg, error)

	io.Closer
}

type Opt struct {
	// DialAddr specifies the address the upstream will
	// actually dial to.
	DialAddr string

	// Socks5 specifies the socks5 proxy server that the upstream
	// will connect though.
	// Not implemented for udp upstreams and doh upstreams with http/3.
	Socks5 string

	// SoMark sets the socket SO_MARK option in unix system.
	SoMark int

	// BindToDevice sets the socket SO_BINDTODEVICE option in unix system.
	BindToDevice string

	// IdleTimeout specifies the idle timeout for long-connections.
	// Available for TCP, DoT, DoH.
	// If negative, TCP, DoT will not reuse connections.
	// Default: TCP, DoT: 10s , DoH: 30s.
	IdleTimeout time.Duration

	// EnablePipeline enables query pipelining support as RFC 7766 6.2.1.1 suggested.
	// Available for TCP, DoT upstream with IdleTimeout >= 0.
	EnablePipeline bool

	// MaxConns limits the total number of connections, including connections
	// in the dialing states.
	// Implemented for TCP/DoT pipeline enabled upstreams and DoH upstreams.
	// Default is 2.
	MaxConns int

	// Bootstrap specifies a plain dns server for the go runtime to solve the
	// domain of the upstream server. It SHOULD be an IP address. Custom port
	// is supported.
	// Note: Use a domain address may cause dead resolve loop and additional
	// latency to dial upstream server.
	// HTTP3 is not supported.
	Bootstrap string

	// TLS skip certificate veriry
	Insecure bool

	// The set of root certificate authorities that clients use when verifying server certificates.
	RootCAs *x509.CertPool

	// Logger specifies the logger that the upstream will use.
	Logger *zap.Logger

	// KernelTX and KernelRX control whether kernel TLS offloading is enabled
	// If the kernel is not supported, it is automatically downgraded to the application implementation
	//
	// If this option is enabled, please mount the TLS module before you run application.
	// On Linux, it will try to automatically mount the tls kernel module.
	KernelRX, KernelTX bool
}

func NewUpstream(addr string, opt *Opt) (Upstream, error) {
	if opt == nil {
		opt = new(Opt)
	}

	// parse protocol and server addr
	if !strings.Contains(addr, "://") {
		addr = "udp://" + addr
	}
	addrURL, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("invalid server address, %w", err)
	}

	dialer := &net.Dialer{
		Resolver: bootstrap.NewPlainBootstrap(opt.Bootstrap),
		Control: getSocketControlFunc(socketOpts{
			so_mark:        opt.SoMark,
			bind_to_device: opt.BindToDevice,
		}),
	}
	lc := net.ListenConfig{Control: getSocketControlFunc(socketOpts{
		so_mark:        opt.SoMark,
		bind_to_device: opt.BindToDevice,
	})}

	switch addrURL.Scheme {
	case "", "udp":
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 53)
		tto := transport.Opts{
			Logger: opt.Logger,
			DialFunc: func(ctx context.Context) (net.Conn, error) {
				return dialer.DialContext(ctx, "tcp", dialAddr)
			},
			WriteFunc: dnsutils.WriteMsgToTCP,
			ReadFunc:  dnsutils.ReadMsgFromTCP,
		}
		tt, err := transport.NewTransport(tto)
		if err != nil {
			return nil, fmt.Errorf("cannot init tcp transport, %w", err)
		}
		return udp.NewUDPUpstream(dialAddr, func(ctx context.Context) (*net.UDPConn, error) {
			conn, err := dialer.DialContext(ctx, "udp", dialAddr)
			if err != nil {
				return nil, err
			}
			udpConn, isUDPConn := conn.(*net.UDPConn)
			if !isUDPConn {
				return nil, fmt.Errorf("this in not a udp conn")
			}
			return udpConn, nil
		}, tt)
	case "tcp":
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 53)
		to := transport.Opts{
			Logger: opt.Logger,
			DialFunc: func(ctx context.Context) (net.Conn, error) {
				return dialTCP(ctx, dialAddr, opt.Socks5, dialer)
			},
			WriteFunc:      dnsutils.WriteMsgToTCP,
			ReadFunc:       dnsutils.ReadMsgFromTCP,
			IdleTimeout:    opt.IdleTimeout,
			EnablePipeline: opt.EnablePipeline,
			MaxConns:       opt.MaxConns,
		}
		return transport.NewTransport(to)
	case "dot", "tls":
		tlsConfig := createETLSConfig(opt, "dot", addrURL.Host)
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 853)
		to := transport.Opts{
			Logger: opt.Logger,
			DialFunc: func(ctx context.Context) (net.Conn, error) {
				conn, err := dialTCP(ctx, dialAddr, opt.Socks5, dialer)
				if err != nil {
					return nil, err
				}
				tlsConn := eTLS.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					tlsConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			WriteFunc:      dnsutils.WriteMsgToTCP,
			ReadFunc:       dnsutils.ReadMsgFromTCP,
			IdleTimeout:    opt.IdleTimeout,
			EnablePipeline: opt.EnablePipeline,
			MaxConns:       opt.MaxConns,
		}
		return transport.NewTransport(to)
	case "doq", "quic":
		tlsConfig := createTLSConfig(opt, "doq", addrURL.Host)
		idleConnTimeout := time.Second * 30
		if opt.IdleTimeout > 0 {
			idleConnTimeout = opt.IdleTimeout
		}
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 853)
		quicConfig := &quic.Config{
			TokenStore:                     quic.NewLRUTokenStore(1, 10),
			InitialStreamReceiveWindow:     4 * 1024,
			MaxStreamReceiveWindow:         4 * 1024,
			InitialConnectionReceiveWindow: 8 * 1024,
			MaxConnectionReceiveWindow:     64 * 1024,
			KeepAlivePeriod:                idleConnTimeout / 2,
		}
		return mQUIC.NewQUICUpstream(dialAddr, func(ctx context.Context) (*mQUIC.Conn, error) {
			c, err := dialer.DialContext(ctx, "udp", dialAddr)
			if err != nil {
				return nil, err
			}
			c.Close()
			uc, isUC := c.(*net.UDPConn)
			if !isUC {
				return nil, fmt.Errorf("this is not an udp conn")
			}
			pc, err := lc.ListenPacket(ctx, "udp", "")
			if err != nil {
				return nil, err
			}
			return mQUIC.Dial(ctx, pc, uc.RemoteAddr(), tlsConfig, quicConfig)
		}), nil
	case "http":
		idleConnTimeout := time.Second * 30
		if opt.IdleTimeout > 0 {
			idleConnTimeout = opt.IdleTimeout
		}
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 80)
		return doh.NewUpstream(addrURL, &http.Transport{
			DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				return dialer.DialContext(ctx, network, dialAddr)
			},
			IdleConnTimeout: idleConnTimeout,
		}), nil
	case "https", "h2", "doh":
		idleConnTimeout := time.Second * 30
		if opt.IdleTimeout > 0 {
			idleConnTimeout = opt.IdleTimeout
		}
		addrURL.Scheme = "https"
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 443)
		tlsConfig := createETLSConfig(opt, "h2", addrURL.Hostname())
		return doh.NewUpstream(addrURL, &http.Transport{
			DialTLSContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
				conn, err := dialer.DialContext(ctx, network, dialAddr)
				if err != nil {
					return nil, err
				}
				tlsConn := eTLS.Client(conn, tlsConfig)
				if err := tlsConn.HandshakeContext(ctx); err != nil {
					tlsConn.Close()
					return nil, err
				}
				return tlsConn, nil
			},
			IdleConnTimeout:   idleConnTimeout,
			ForceAttemptHTTP2: true,
		}), nil
	case "h3", "doh3":
		idleConnTimeout := time.Second * 30
		if opt.IdleTimeout > 0 {
			idleConnTimeout = opt.IdleTimeout
		}
		addrURL.Scheme = "https"
		dialAddr := getDialAddrWithPort(addrURL.Host, opt.DialAddr, 443)
		tlsConfig := createTLSConfig(opt, "h3", addrURL.Hostname())
		return doh3.NewUpstream(addrURL, &http3.Transport{
			TLSClientConfig: tlsConfig,
			QUICConfig: &quic.Config{
				TokenStore:                     quic.NewLRUTokenStore(1, 10),
				InitialStreamReceiveWindow:     4 * 1024,
				MaxStreamReceiveWindow:         4 * 1024,
				InitialConnectionReceiveWindow: 8 * 1024,
				MaxConnectionReceiveWindow:     64 * 1024,
				KeepAlivePeriod:                idleConnTimeout / 2,
			},
			Dial: func(ctx context.Context, _ string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				c, err := dialer.DialContext(ctx, "udp", dialAddr)
				if err != nil {
					return nil, err
				}
				c.Close()
				uc, isUC := c.(*net.UDPConn)
				if !isUC {
					return nil, fmt.Errorf("this is not an udp conn")
				}
				pc, err := lc.ListenPacket(ctx, "udp", "")
				if err != nil {
					return nil, err
				}
				return quic.DialEarly(ctx, pc, uc.RemoteAddr(), tlsCfg, cfg)
			},
		}), nil
	default:
		return nil, fmt.Errorf("unsupported protocol [%s]", addrURL.Scheme)
	}
}

func createTLSConfig(opt *Opt, alpn string, serverName string) *tls.Config {
	config := &tls.Config{
		InsecureSkipVerify: opt.Insecure,
		RootCAs:            opt.RootCAs,
		NextProtos:         []string{alpn},
		ServerName:         serverName,
		ClientSessionCache: tls.NewLRUClientSessionCache(64),
	}
	return config
}

func createETLSConfig(opt *Opt, alpn string, serverName string) *eTLS.Config {
	config := &eTLS.Config{
		KernelTX:           opt.KernelTX,
		KernelRX:           opt.KernelRX,
		InsecureSkipVerify: opt.Insecure,
		RootCAs:            opt.RootCAs,
		NextProtos:         []string{alpn},
		ServerName:         serverName,
		ClientSessionCache: eTLS.NewLRUClientSessionCache(64),
	}
	return config
}

func getDialAddrWithPort(host, dialAddr string, defaultPort int) string {
	addr := host
	if len(dialAddr) > 0 {
		addr = dialAddr
	}
	_, _, err := net.SplitHostPort(addr)
	if err != nil { // no port, add it.
		return net.JoinHostPort(strings.Trim(addr, "[]"), strconv.Itoa(defaultPort))
	}
	return addr
}

func tryRemovePort(s string) string {
	host, _, err := net.SplitHostPort(s)
	if err != nil {
		return s
	}
	return host
}

type udpWithFallback struct {
	u *transport.Transport
	t *transport.Transport
}

func (u *udpWithFallback) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	m, err := u.u.ExchangeContext(ctx, q)
	if err != nil {
		return nil, err
	}
	if m.Truncated {
		return u.t.ExchangeContext(ctx, q)
	}
	return m, nil
}

func (u *udpWithFallback) Close() error {
	u.u.Close()
	u.t.Close()
	return nil
}
