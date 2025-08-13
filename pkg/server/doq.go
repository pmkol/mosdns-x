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
	"time"

	"github.com/quic-go/quic-go"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	C "github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

type quicCloser struct {
	closed bool
	conn   *quic.Conn
}

func (c *quicCloser) Close() error {
	if c.closed {
		return nil
	}
	return c.conn.CloseWithError(1, "")
}

func (c *quicCloser) close(code quic.ApplicationErrorCode) error {
	if c.closed {
		return nil
	}
	return c.conn.CloseWithError(code, "")
}

func (s *Server) ServeQUIC(l *quic.EarlyListener) error {
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
		idleTimeout = defaultQUICIdleTimeout
	}
	if idleTimeout < firstReadTimeout {
		firstReadTimeout = idleTimeout
	}

	// handle listener
	listenerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	for {
		c, err := l.Accept(listenerCtx)
		if err != nil {
			if s.Closed() {
				return ErrServerClosed
			}
			return fmt.Errorf("unexpected listener err: %w", err)
		}

		// handle connection
		quicConnCtx, cancelConn := context.WithCancel(listenerCtx)
		closer := &quicCloser{conn: c}
		go func() {
			defer closer.close(0)
			defer cancelConn()
			if !s.trackCloser(closer, true) {
				closer.close(1)
				return
			}

			clientAddr := utils.GetAddrFromAddr(c.RemoteAddr())
			meta := C.NewRequestMeta(clientAddr)
			defer s.trackCloser(closer, false)

			timeout := time.AfterFunc(firstReadTimeout, cancelConn)
			for {
				stream, err := c.AcceptStream(quicConnCtx)
				if err != nil {
					closer.close(1)
					return
				}
				// handle stream
				go func() {
					req, _, err := dnsutils.ReadMsgFromTCP(stream)
					timeout.Reset(idleTimeout)
					if err != nil {
						stream.CancelRead(1)
						stream.CancelWrite(1)
						return
					}

					defer stream.Close()
					stream.CancelRead(0)

					if req.Id != 0 {
						stream.CancelWrite(1)
						closer.close(1)
						return
					}

					// handle query
					r, err := handler.ServeDNS(quicConnCtx, req, meta)
					if err != nil {
						stream.CancelWrite(1)
						s.opts.Logger.Warn("handler err", zap.Error(err))
						return
					}

					b, buf, err := pool.PackBuffer(r)
					if err != nil {
						stream.CancelWrite(1)
						s.opts.Logger.Error("failed to unpack handler's response", zap.Error(err), zap.Stringer("msg", r))
						return
					}
					defer buf.Release()

					if _, err := dnsutils.WriteRawMsgToTCP(stream, b); err != nil {
						stream.CancelWrite(1)
						s.opts.Logger.Warn("failed to write response", zap.Stringer("client", c.RemoteAddr()), zap.Error(err))
					}
				}()
			}
		}()
	}
}
