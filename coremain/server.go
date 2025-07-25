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

package coremain

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/pires/go-proxyproto"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/coremain/listen"
	"github.com/pmkol/mosdns-x/pkg/server"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
	"github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

const defaultQueryTimeout = time.Second * 5
const (
	defaultIdleTimeout = time.Second * 10
)

func (m *Mosdns) startServers(cfg *ServerConfig) error {
	if len(cfg.Listeners) == 0 {
		return errors.New("no server listener is configured")
	}
	if len(cfg.Exec) == 0 {
		return errors.New("empty entry")
	}

	entry := m.execs[cfg.Exec]
	if entry == nil {
		return fmt.Errorf("cannot find entry %s", cfg.Exec)
	}

	queryTimeout := defaultQueryTimeout
	if cfg.Timeout > 0 {
		queryTimeout = time.Duration(cfg.Timeout) * time.Second
	}

	dnsHandlerOpts := dns_handler.EntryHandlerOpts{
		Logger:             m.logger,
		Entry:              entry,
		QueryTimeout:       queryTimeout,
		RecursionAvailable: true,
	}
	dnsHandler, err := dns_handler.NewEntryHandler(dnsHandlerOpts)
	if err != nil {
		return fmt.Errorf("failed to init entry handler, %w", err)
	}

	for _, lc := range cfg.Listeners {
		if err := m.startServerListener(lc, dnsHandler); err != nil {
			return err
		}
	}
	return nil
}

func (m *Mosdns) startServerListener(cfg *ServerListenerConfig, dnsHandler dns_handler.Handler) error {
	if len(cfg.Addr) == 0 {
		return errors.New("no address to bind")
	}

	m.logger.Info("starting server", zap.String("proto", cfg.Protocol), zap.String("addr", cfg.Addr))

	idleTimeout := defaultIdleTimeout
	if cfg.IdleTimeout > 0 {
		idleTimeout = time.Duration(cfg.IdleTimeout) * time.Second
	}

	httpOpts := http_handler.HandlerOpts{
		DNSHandler:  dnsHandler,
		Path:        cfg.URLPath,
		SrcIPHeader: cfg.GetUserIPFromHeader,
		Logger:      m.logger,
	}

	httpHandler, err := http_handler.NewHandler(httpOpts)
	if err != nil {
		return fmt.Errorf("failed to init http handler, %w", err)
	}

	opts := server.ServerOpts{
		DNSHandler:  dnsHandler,
		HttpHandler: httpHandler,
		Cert:        cfg.Cert,
		Key:         cfg.Key,
		KernelTX:    cfg.KernelTX,
		KernelRX:    cfg.KernelRX,
		IdleTimeout: idleTimeout,
		Logger:      m.logger,
	}
	s := server.NewServer(opts)

	// helper func for proxy protocol listener
	requirePP := func(_ net.Addr) (proxyproto.Policy, error) {
		return proxyproto.REQUIRE, nil
	}

	config := listen.CreateListenConfig()
	abstract := strings.HasPrefix(cfg.Addr, "@")

	var run func() error
	switch cfg.Protocol {
	case "", "udp", "quic", "doq", "h3", "doh3":
		var conn net.PacketConn
		var err error
		if cfg.UnixDomainSocket {
			if !abstract {
				os.Remove(cfg.Addr)
			}
			conn, err = config.ListenPacket(context.Background(), "unixgram", cfg.Addr)
			if !abstract {
				os.Chmod(cfg.Addr, 0x777)
			}
		} else {
			conn, err = config.ListenPacket(context.Background(), "udp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		switch cfg.Protocol {
		case "", "udp":
			run = func() error { return s.ServeUDP(conn) }
		case "quic", "doq":
			l, err := s.CreateQUICListner(conn, []string{"doq", "quic", "doq-i00", "doq-i02", "doq-i03", "doq-i11"})
			if err != nil {
				return err
			}
			run = func() error { return s.ServeQUIC(l) }
		case "h3", "doh3":
			l, err := s.CreateQUICListner(conn, []string{"h3"})
			if err != nil {
				return err
			}
			run = func() error { return s.ServeH3(l) }
		}
	case "tcp", "tls", "dot", "http", "https", "doh":
		var l net.Listener
		var err error
		if cfg.UnixDomainSocket {
			if !abstract {
				os.Remove(cfg.Addr)
			}
			l, err = config.Listen(context.Background(), "unix", cfg.Addr)
			if !abstract {
				os.Chmod(cfg.Addr, 0x777)
			}
		} else {
			l, err = config.Listen(context.Background(), "tcp", cfg.Addr)
		}
		if err != nil {
			return err
		}
		if cfg.ProxyProtocol {
			l = &proxyproto.Listener{Listener: l, Policy: requirePP}
		}
		switch cfg.Protocol {
		case "tcp":
			run = func() error { return s.ServeTCP(l) }
		case "tls", "dot":
			l, err = s.CreateTLSListner(l, []string{"dot", "tls"})
			if err != nil {
				return err
			}
			run = func() error { return s.ServeTCP(l) }
		case "http":
			run = func() error { return s.ServeHTTP(l) }
		case "https", "doh":
			l, err = s.CreateTLSListner(l, []string{"h2"})
			if err != nil {
				return err
			}
			run = func() error { return s.ServeHTTP(l) }
		}
	default:
		return fmt.Errorf("unknown protocol: [%s]", cfg.Protocol)
	}

	m.sc.Attach(func(done func(), closeSignal <-chan struct{}) {
		defer done()
		errChan := make(chan error, 1)
		go func() {
			errChan <- run()
		}()
		select {
		case err := <-errChan:
			m.sc.SendCloseSignal(fmt.Errorf("server exited, %w", err))
		case <-closeSignal:
		}
	})

	return nil
}
