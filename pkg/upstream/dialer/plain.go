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

package dialer

import (
	"context"
	"fmt"
	"net"
	"syscall"
	"time"
)

type PlainDialer struct {
	dialer *net.Dialer
}

func newPlainDialer(dialer *net.Dialer) *PlainDialer {
	return &PlainDialer{dialer: dialer}
}

func (d *PlainDialer) DialContext(ctx context.Context, network string, addr string) (net.Conn, error) {
	if network != "tcp" && network != "udp" {
		return nil, fmt.Errorf("unsupported network type: %s", network)
	}
	conn, err := d.dialer.DialContext(ctx, network, addr)
	if err != nil {
		return nil, err
	}
	if network == "tcp" {
		return conn, nil
	}
	uc, isUDPConn := conn.(*net.UDPConn)
	if !isUDPConn {
		return nil, fmt.Errorf("not a *net.UDPConn")
	}
	return &PlainPacketConn{inner: uc}, nil
}

type PlainPacketConn struct {
	inner *net.UDPConn
}

func (p *PlainPacketConn) Close() error {
	return p.inner.Close()
}

func (p *PlainPacketConn) LocalAddr() net.Addr {
	return p.inner.LocalAddr()
}

func (p *PlainPacketConn) RemoteAddr() net.Addr {
	return p.inner.RemoteAddr()
}

func (p *PlainPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := p.inner.Read(b)
	if err != nil {
		return 0, nil, err
	}
	return n, p.RemoteAddr(), nil
}

func (p *PlainPacketConn) Read(b []byte) (int, error) {
	n, _, err := p.ReadFrom(b)
	return n, err
}

func (p *PlainPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return p.Write(b)
}

func (p *PlainPacketConn) Write(b []byte) (int, error) {
	return p.inner.Write(b)
}

func (p *PlainPacketConn) SetDeadline(t time.Time) error {
	return p.inner.SetDeadline(t)
}

func (p *PlainPacketConn) SetReadDeadline(t time.Time) error {
	return p.inner.SetReadDeadline(t)
}

func (p *PlainPacketConn) SetWriteDeadline(t time.Time) error {
	return p.inner.SetWriteDeadline(t)
}

func (p *PlainPacketConn) SyscallConn() (syscall.RawConn, error) {
	return p.inner.SyscallConn()
}

func (p *PlainPacketConn) SetReadBuffer(bytes int) error {
	return p.inner.SetReadBuffer(bytes)
}

func (p *PlainPacketConn) SetWriteBuffer(bytes int) error {
	return p.inner.SetWriteBuffer(bytes)
}

func (p *PlainPacketConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	return p.inner.ReadMsgUDP(b, oob)
}

func (p *PlainPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
	return p.inner.WriteMsgUDP(b, oob, nil)
}
