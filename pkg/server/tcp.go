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

package server

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"gitlab.com/go-extension/tls"
	"go.uber.org/zap"

	"github.com/miekg/dns"
	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

type TCPConn struct {
	sync.Mutex
	net.Conn
	handler dns_handler.Handler
	meta    *C.RequestMeta
}

func (c *TCPConn) ServeDNS(ctx context.Context, req *dns.Msg) (*dns.Msg, error) {
	return c.handler.ServeDNS(ctx, req, c.meta)
}

func (c *TCPConn) WriteRawMsg(b []byte) (int, error) {
	c.Lock()
	defer c.Unlock()
	return dnsutils.WriteRawMsgToTCP(c, b)
}

const (
	defaultTCPIdleTimeout = time.Second * 10
	tcpFirstReadTimeout   = time.Millisecond * 500
)

func (s *Server) ServeTCP(l net.Listener) error {
	defer l.Close()

	handler := s.opts.DNSHandler
	if handler == nil {
		return errMissingDNSHandler
	}

	if ok := s.trackCloser(l, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(l, false)

	// handle listener
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		c, err := l.Accept()
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			if err, ok := err.(net.Error); ok && err.Temporary() {
				continue
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		go s.handleConnectionTcp(ctx, &TCPConn{Conn: c, handler: handler})
	}
}

func (s *Server) handleConnectionTcp(ctx context.Context, c *TCPConn) {
	defer c.Close()

	if !s.trackCloser(c, true) {
		return
	}
	defer s.trackCloser(c, false)

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	clientAddr := utils.GetAddrFromAddr(c.RemoteAddr())
	meta := C.NewRequestMeta(clientAddr)

	protocol := C.ProtocolTCP
	if tlsConn, ok := c.Conn.(*tls.Conn); ok {
		handshakeTimeout := s.opts.IdleTimeout
		if handshakeTimeout <= 0 {
			handshakeTimeout = defaultTCPIdleTimeout
		}

		handshakeCtx, cancel := context.WithTimeout(ctx, handshakeTimeout)
		defer cancel()

		if err := tlsConn.HandshakeContext(handshakeCtx); err != nil {
			s.opts.Logger.Warn("handshake failed", zap.Stringer("from", c.RemoteAddr()), zap.Error(err))
			return
		}

		meta.SetServerName(tlsConn.ConnectionState().ServerName)
		protocol = C.ProtocolTLS
	}
	meta.SetProtocol(protocol)
	c.meta = meta

	idleTimeout := s.opts.IdleTimeout
	if idleTimeout <= 0 {
		idleTimeout = defaultTCPIdleTimeout
	}

	c.SetReadDeadline(time.Now().Add(min(idleTimeout, tcpFirstReadTimeout)))

	for {
		req, _, err := dnsutils.ReadMsgFromTCP(c)
		if err != nil {
			return // read err, close the connection
		}

		go s.handleQueryTcp(ctx, c, req)

		c.SetReadDeadline(time.Now().Add(idleTimeout))
	}
}

func (s *Server) handleQueryTcp(ctx context.Context, c *TCPConn, req *dns.Msg) {
	r, err := c.ServeDNS(ctx, req)
	if err != nil {
		s.opts.Logger.Warn("handler err", zap.Error(err))
		c.Close()
		return
	}

	b, buf, err := pool.PackBuffer(r)
	if err != nil {
		s.opts.Logger.Error("failed to unpack handler's response", zap.Error(err), zap.Stringer("msg", r))
		return
	}
	defer buf.Release()

	_, err = c.WriteRawMsg(b)
	if err != nil {
		s.opts.Logger.Warn("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
		return
	}
}
