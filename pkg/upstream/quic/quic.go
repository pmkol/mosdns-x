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

package quic

import (
	"context"
	"errors"
	"sync"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
)

var _ error = (*closedConnError)(nil)

type closedConnError struct{}

func (e *closedConnError) Error() string {
	return "connection is closed"
}

type Conn struct {
	conn       *quic.Conn
	closed     chan struct{}
	handshaked chan struct{}
	sync.RWMutex
}

func NewConn(conn *quic.Conn) *Conn {
	c := &Conn{
		conn:       conn,
		closed:     make(chan struct{}),
		handshaked: make(chan struct{}),
	}
	go func() {
		select {
		case <-c.closed:
		case <-conn.Context().Done():
		case <-conn.HandshakeComplete():
			conn, err := conn.NextConnection(context.Background())
			if err != nil {
				select {
				case <-c.closed:
				default:
					close(c.closed)
				}
				return
			}
			c.Lock()
			defer c.Unlock()
			close(c.handshaked)
			c.conn = conn
		}
	}()
	return c
}

func (c *Conn) isActive() bool {
	c.RLock()
	conn := c.conn
	c.RUnlock()
	select {
	case <-c.closed:
		return false
	case <-conn.Context().Done():
		return false
	default:
		return true
	}
}

func (c *Conn) closeWithError(code quic.ApplicationErrorCode, desc string) error {
	select {
	case <-c.closed:
	default:
		close(c.closed)
	}
	c.Lock()
	defer c.Unlock()
	return c.conn.CloseWithError(code, desc)
}

func (c *Conn) openStreamSync(ctx context.Context) (*quic.Stream, error) {
	c.RLock()
	conn := c.conn
	c.RUnlock()
	return conn.OpenStreamSync(ctx)
}

type Upstream struct {
	conn     *Conn
	dialFunc func(ctx context.Context) (*Conn, error)
	sync.RWMutex
}

func NewQUICUpstream(addr string, dialFunc func(ctx context.Context) (*Conn, error)) *Upstream {
	return &Upstream{
		dialFunc: dialFunc,
	}
}

func (h *Upstream) offer(ctx context.Context) (*Conn, error) {
	h.RLock()
	outer := h.conn
	h.RUnlock()
	if outer != nil && outer.isActive() {
		return outer, nil
	}
	h.Lock()
	defer h.Unlock()
	outer = h.conn
	if outer != nil && outer.isActive() {
		return outer, nil
	}
	conn, err := h.dialFunc(ctx)
	if err != nil {
		return nil, err
	}
	h.conn = conn
	return conn, nil
}

func (h *Upstream) Close() error {
	h.Lock()
	defer h.Unlock()
	conn := h.conn
	if conn != nil {
		go conn.closeWithError(0, "")
	}
	return nil
}

func (h *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	q.Id = 0
	var err error
	for range 3 {
		var conn *Conn
		conn, err = h.offer(ctx)
		if err != nil {
			return nil, err
		}
		var resp *dns.Msg
		resp, err = exchangeMsg(ctx, conn, q)
		if err == nil {
			return resp, err
		}
	}
	return nil, err
}

func exchangeMsg(ctx context.Context, conn *Conn, q *dns.Msg) (*dns.Msg, error) {
	resp, err := exchange(ctx, conn, q)
	if errors.Is(err, quic.Err0RTTRejected) {
		select {
		case <-conn.closed:
			return nil, &closedConnError{}
		case <-conn.handshaked:
			return exchange(ctx, conn, q)
		}
	}
	return resp, err
}

func exchange(ctx context.Context, conn *Conn, q *dns.Msg) (*dns.Msg, error) {
	stream, err := conn.openStreamSync(ctx)
	if err != nil {
		return nil, err
	}
	_, err = dnsutils.WriteMsgToTCP(stream, q)
	if err != nil {
		stream.CancelRead(1)
		stream.CancelWrite(1)
		return nil, err
	}
	stream.Close()
	r, _, err := dnsutils.ReadMsgFromTCP(stream)
	if err != nil {
		stream.CancelRead(1)
		return nil, err
	}
	return r, nil
}
