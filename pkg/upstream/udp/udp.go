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

package udp

import (
	"context"
	"net"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/upstream/transport"
)

type Upstream struct {
	dialFunc     func(ctx context.Context) (net.Conn, error)
	tcpTransport *transport.Transport
}

func NewUDPUpstream(dialFunc func(ctx context.Context) (net.Conn, error), tcpTransport *transport.Transport) (*Upstream, error) {
	return &Upstream{dialFunc, tcpTransport}, nil
}

func (u *Upstream) Close() error {
	return nil
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	conn, err := u.dialFunc(ctx)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	dnsutils.WriteMsgToUDP(conn, q)
	r, _, err := dnsutils.ReadMsgFromUDP(conn, 65535)
	if err != nil {
		return nil, err
	}
	if r.Truncated {
		return u.tcpTransport.ExchangeContext(ctx, q)
	}
	return r, nil
}
