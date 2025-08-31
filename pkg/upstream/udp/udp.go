/*
 * Copyright (C) 2020-2025, pmkol
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

package udp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/upstream/transport"
)

const (
	defaultBufSize = 4096
	pendingTTL     = 10 * time.Second
)

var bufPool = sync.Pool{
	New: func() interface{} {
		return make([]byte, defaultBufSize)
	},
}

type pendingEntry struct {
	ch       chan *dns.Msg
	deadline time.Time
}

type Upstream struct {
	dialFunc     func(ctx context.Context) (net.Conn, error)
	tcpTransport *transport.Transport

	mu         sync.Mutex
	conn       net.Conn
	readerOn   bool
	connecting int32
	connDone   chan struct{}

	pendingMu sync.Mutex
	pending   map[uint16]*pendingEntry
	wakeup    chan struct{}

	writeMu sync.Mutex
	rr      uint32
	closed  int32
}

func NewUDPUpstream(dialFunc func(ctx context.Context) (net.Conn, error), tcpTransport *transport.Transport) (*Upstream, error) {
	if dialFunc == nil {
		return nil, errors.New("dialFunc required")
	}
	u := &Upstream{
		dialFunc:     dialFunc,
		tcpTransport: tcpTransport,
		pending:      make(map[uint16]*pendingEntry),
		wakeup:       make(chan struct{}, 1),
	}
	go u.pendingJanitor()
	return u, nil
}

func (u *Upstream) Close() error {
	if !atomic.CompareAndSwapInt32(&u.closed, 0, 1) {
		return nil
	}

	u.mu.Lock()
	if u.conn != nil {
		_ = u.conn.Close()
		u.conn = nil
		u.readerOn = false
	}
	u.mu.Unlock()

	select {
	case u.wakeup <- struct{}{}:
	default:
	}

	u.pendingMu.Lock()
	snapshot := make([]struct {
		id    uint16
		entry *pendingEntry
	}, 0, len(u.pending))
	for id, entry := range u.pending {
		snapshot = append(snapshot, struct {
			id    uint16
			entry *pendingEntry
		}{id, entry})
	}
	u.pending = make(map[uint16]*pendingEntry)
	u.pendingMu.Unlock()

	for _, it := range snapshot {
		select {
		case it.entry.ch <- nil:
		default:
		}
	}
	return nil
}

func (u *Upstream) ensureConn(ctx context.Context) error {
	for {
		u.mu.Lock()
		if atomic.LoadInt32(&u.closed) == 1 {
			u.mu.Unlock()
			return errors.New("udp upstream closed")
		}
		if u.conn != nil && u.readerOn {
			u.mu.Unlock()
			return nil
		}
		if atomic.CompareAndSwapInt32(&u.connecting, 0, 1) {
			u.connDone = make(chan struct{})
			done := u.connDone
			u.mu.Unlock()

			defer func() {
				u.mu.Lock()
				atomic.StoreInt32(&u.connecting, 0)
				select {
				case <-done:
				default:
					close(done)
				}
				u.mu.Unlock()
			}()

			var conn net.Conn
			var err error

			defer func() {
				if r := recover(); r != nil {
					err = fmt.Errorf("dial panic: %v", r)
				}
			}()

			conn, err = u.dialFunc(ctx)
			if err != nil {
				return err
			}

			u.mu.Lock()
			if atomic.LoadInt32(&u.closed) == 1 {
				_ = conn.Close()
				u.mu.Unlock()
				return errors.New("udp upstream closed")
			}
			u.conn = conn
			u.readerOn = true
			u.mu.Unlock()

			go u.reader(conn)
			return nil
		}
		done := u.connDone
		u.mu.Unlock()

		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-done:
		}
	}
}

func (u *Upstream) reader(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("udp upstream reader panic: %v\n", r)
			u.handleConnClosed(conn, fmt.Errorf("reader panic: %v", r))
		}
	}()

	b := bufPool.Get().([]byte)
	defer bufPool.Put(b)

	for {
		if atomic.LoadInt32(&u.closed) == 1 {
			return
		}

		n, err := conn.Read(b)
		if err != nil {
			u.handleConnClosed(conn, err)
			return
		}

		if n > 0 {
			msg := new(dns.Msg)
			if err := msg.Unpack(b[:n]); err == nil {
				u.removePendingAndNotify(msg.Id, msg)
			}
		}
	}
}

func (u *Upstream) handleConnClosed(conn net.Conn, _ error) {
	u.mu.Lock()
	if u.conn == conn {
		_ = u.conn.Close()
		u.conn = nil
		u.readerOn = false
	}
	u.mu.Unlock()

	u.pendingMu.Lock()
	snapshot := make([]struct {
		id    uint16
		entry *pendingEntry
	}, 0, len(u.pending))
	for id, entry := range u.pending {
		snapshot = append(snapshot, struct {
			id    uint16
			entry *pendingEntry
		}{id, entry})
	}
	u.pending = make(map[uint16]*pendingEntry)
	u.pendingMu.Unlock()

	for _, it := range snapshot {
		select {
		case it.entry.ch <- nil:
		default:
		}
	}

	select {
	case u.wakeup <- struct{}{}:
	default:
	}
}

func (u *Upstream) removePendingAndNotify(id uint16, msg *dns.Msg) {
	u.pendingMu.Lock()
	entry, ok := u.pending[id]
	if !ok {
		u.pendingMu.Unlock()
		return
	}
	delete(u.pending, id)
	u.pendingMu.Unlock()

	select {
	case entry.ch <- msg:
	default:
	}
}

func (u *Upstream) claimID() (uint16, chan *dns.Msg, error) {
	for i := 0; i < 65536; i++ {
		id := uint16(atomic.AddUint32(&u.rr, 1) & 0xffff)
		u.pendingMu.Lock()
		if _, exists := u.pending[id]; !exists {
			ch := make(chan *dns.Msg, 2)
			u.pending[id] = &pendingEntry{
				ch:       ch,
				deadline: time.Now().Add(pendingTTL),
			}
			select {
			case u.wakeup <- struct{}{}:
			default:
			}
			u.pendingMu.Unlock()
			return id, ch, nil
		}
		u.pendingMu.Unlock()
	}
	return 0, nil, errors.New("no free dns id available")
}

func (u *Upstream) unclaimID(id uint16) {
	u.removePendingAndNotify(id, nil)
	select {
	case u.wakeup <- struct{}{}:
	default:
	}
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	if atomic.LoadInt32(&u.closed) == 1 {
		return nil, errors.New("udp upstream closed")
	}

	origID := q.Id
	if err := u.ensureConn(ctx); err != nil {
		return nil, err
	}

	id, respCh, err := u.claimID()
	if err != nil {
		return nil, err
	}
	defer u.unclaimID(id)

	u.mu.Lock()
	conn := u.conn
	u.mu.Unlock()
	if conn == nil {
		return nil, errors.New("udp connection closed")
	}

	u.writeMu.Lock()
	var dlSet bool
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetWriteDeadline(dl)
		dlSet = true
	}
	cq := q.Copy()
	cq.Id = id
	_, err = dnsutils.WriteMsgToUDP(conn, cq)
	if dlSet {
		_ = conn.SetWriteDeadline(time.Time{})
	}
	u.writeMu.Unlock()

	if err != nil {
		u.mu.Lock()
		if u.conn != nil {
			_ = u.conn.Close()
			u.conn = nil
			u.readerOn = false
		}
		u.mu.Unlock()
		return nil, err
	}

	select {
	case resp := <-respCh:
		if resp == nil {
			return nil, errors.New("connection closed or read error")
		}
		if resp.Truncated {
			if u.tcpTransport == nil {
				return nil, errors.New("truncated response but tcpTransport is nil")
			}
			resp, err := u.tcpTransport.ExchangeContext(ctx, q)
			if err != nil {
				return nil, err
			}
			resp.Id = origID
			return resp, nil
		}
		resp.Id = origID
		return resp, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func (u *Upstream) pendingJanitor() {
	var timer *time.Timer
	for {
		if atomic.LoadInt32(&u.closed) == 1 {
			if timer != nil {
				timer.Stop()
			}
			return
		}

		var nextDeadline time.Time
		u.pendingMu.Lock()
		now := time.Now()
		for id, entry := range u.pending {
			if now.After(entry.deadline) {
				delete(u.pending, id)
				select {
				case entry.ch <- nil:
				default:
				}
			} else {
				if nextDeadline.IsZero() || entry.deadline.Before(nextDeadline) {
					nextDeadline = entry.deadline
				}
			}
		}
		u.pendingMu.Unlock()

		var ch <-chan time.Time
		if !nextDeadline.IsZero() {
			wait := time.Until(nextDeadline)
			if wait < 0 {
				wait = 0
			}
			if timer == nil {
				timer = time.NewTimer(wait)
			} else {
				if !timer.Stop() {
					select {
					case <-timer.C:
					default:
					}
				}
				timer.Reset(wait)
			}
			ch = timer.C
		}

		select {
		case <-u.wakeup:
		case <-ch:
		}
	}
}

type UpstreamPool struct {
	upstreams []*Upstream
	next      uint32
}

func NewUpstreamPool(dialFunc func(ctx context.Context) (net.Conn, error), tcpTransport *transport.Transport) (*UpstreamPool, error) {
	num := runtime.NumCPU() * 2
	pool := &UpstreamPool{
		upstreams: make([]*Upstream, num),
	}
	for i := 0; i < num; i++ {
		u, err := NewUDPUpstream(dialFunc, tcpTransport)
		if err != nil {
			for j := 0; j < i; j++ {
				_ = pool.upstreams[j].Close()
			}
			return nil, err
		}
		pool.upstreams[i] = u
	}
	return pool, nil
}

func (p *UpstreamPool) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	i := atomic.AddUint32(&p.next, 1)
	u := p.upstreams[i%uint32(len(p.upstreams))]
	return u.ExchangeContext(ctx, q)
}

func (p *UpstreamPool) Close() error {
	var firstErr error
	for _, u := range p.upstreams {
		if err := u.Close(); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
