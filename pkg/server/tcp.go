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

	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

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

	firstReadTimeout := tcpFirstReadTimeout
	idleTimeout := s.opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultTCPIdleTimeout
	}
	if idleTimeout < firstReadTimeout {
		firstReadTimeout = idleTimeout
	}

	// handle listener
	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		c, err := l.Accept()
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		// handle connection
		tcpConnCtx, cancelConn := context.WithCancel(listenerCtx)
		go func() {
			defer c.Close()
			defer cancelConn()

			if !s.trackCloser(c, true) {
				return
			}
			defer s.trackCloser(c, false)

			clientAddr := utils.GetAddrFromAddr(c.RemoteAddr())
			meta := C.NewRequestMeta(clientAddr)

			firstRead := true

			var access sync.Mutex
			for {
				if firstRead {
					firstRead = false
					c.SetReadDeadline(time.Now().Add(firstReadTimeout))
				} else {
					c.SetReadDeadline(time.Now().Add(idleTimeout))
				}
				req, _, err := dnsutils.ReadMsgFromTCP(c)
				if err != nil {
					return // read err, close the connection
				}

				// handle query
				go func() {
					r, err := handler.ServeDNS(tcpConnCtx, req, meta)
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

					access.Lock()
					_, err = dnsutils.WriteRawMsgToTCP(c, b)
					access.Unlock()
					if err != nil {
						s.opts.Logger.Warn("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
						return
					}
				}()
			}
		}()
	}
}
