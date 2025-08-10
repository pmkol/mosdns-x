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

package doh3

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"

	"github.com/miekg/dns"
	"github.com/quic-go/quic-go/http3"

	C "github.com/pmkol/mosdns-x/constant"
	"github.com/pmkol/mosdns-x/pkg/pool"
)

const dnsContentType = "application/dns-message"

var bufPool = pool.NewBytesBufPool(65535)

type Upstream struct {
	url       *url.URL
	transport *http3.Transport
}

func NewUpstream(url *url.URL, transport *http3.Transport) *Upstream {
	return &Upstream{url, transport}
}

func (u *Upstream) ExchangeContext(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	q.Id = 0
	wire, buf, err := pool.PackBuffer(q)
	if err != nil {
		return nil, err
	}
	defer buf.Release()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u.url.String(), bytes.NewReader(wire))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", dnsContentType)
	req.Header.Set("Accept", dnsContentType)
	req.Header.Set("User-Agent", fmt.Sprintf("mosdns-x/%s", C.Version))
	res, err := u.transport.RoundTrip(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode < 200 || res.StatusCode > 299 {
		return nil, fmt.Errorf("unexpected status %v: %s", res.StatusCode, res.Status)
	}
	if contentType := res.Header.Get("Content-Type"); contentType != dnsContentType {
		return nil, fmt.Errorf("unexpected content type: %s", contentType)
	}
	if contentLength := res.Header.Get("Content-Length"); contentLength == "" {
		return nil, fmt.Errorf("empty response")
	} else if length, _ := strconv.Atoi(contentLength); length == 0 {
		return nil, fmt.Errorf("empty response")
	}
	bb := bufPool.Get()
	defer bufPool.Release(bb)
	_, err = bb.ReadFrom(res.Body)
	if err != nil {
		return nil, err
	}
	r := new(dns.Msg)
	err = r.Unpack(bb.Bytes())
	if err != nil {
		return nil, err
	}
	return r, nil
}

func (u *Upstream) Close() error {
	u.transport.CloseIdleConnections()
	return u.transport.Close()
}
