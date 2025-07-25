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

package fastforward

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/miekg/dns"

	"github.com/pmkol/mosdns-x/coremain"
	"github.com/pmkol/mosdns-x/pkg/bundled_upstream"
	"github.com/pmkol/mosdns-x/pkg/executable_seq"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/upstream"
	"github.com/pmkol/mosdns-x/pkg/utils"
)

const PluginType = "fast_forward"

func init() {
	coremain.RegNewPluginFunc(PluginType, Init, func() interface{} { return new(Args) })
}

var _ coremain.ExecutablePlugin = (*fastForward)(nil)

type fastForward struct {
	*coremain.BP
	args *Args

	upstreamWrappers []bundled_upstream.Upstream
	upstreamsCloser  []io.Closer
}

type Args struct {
	Upstream []*UpstreamConfig `yaml:"upstream"`
	CA       []string          `yaml:"ca"`
}

type UpstreamConfig struct {
	Addr         string `yaml:"addr"` // required
	DialAddr     string `yaml:"dial_addr"`
	Trusted      bool   `yaml:"trusted"`
	Socks5       string `yaml:"socks5"`
	SoMark       int    `yaml:"so_mark"`
	BindToDevice string `yaml:"bind_to_device"`

	IdleTimeout        int    `yaml:"idle_timeout"`
	MaxConns           int    `yaml:"max_conns"`
	EnablePipeline     bool   `yaml:"enable_pipeline"`
	EnableHTTP3        bool   `yaml:"enable_http3"`
	Bootstrap          string `yaml:"bootstrap"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
}

func Init(bp *coremain.BP, args interface{}) (p coremain.Plugin, err error) {
	return newFastForward(bp, args.(*Args))
}

func newFastForward(bp *coremain.BP, args *Args) (*fastForward, error) {
	if len(args.Upstream) == 0 {
		return nil, errors.New("no upstream is configured")
	}

	f := &fastForward{
		BP:   bp,
		args: args,
	}

	// rootCAs
	var rootCAs *x509.CertPool
	if len(args.CA) != 0 {
		var err error
		rootCAs, err = utils.LoadCertPool(args.CA)
		if err != nil {
			return nil, fmt.Errorf("failed to load ca: %w", err)
		}
	}

	for i, c := range args.Upstream {
		if len(c.Addr) == 0 {
			return nil, errors.New("missing server addr")
		}

		if strings.HasPrefix(c.Addr, "udpme://") {
			u := newUDPME(c.Addr[8:], c.Trusted)
			f.upstreamWrappers = append(f.upstreamWrappers, u)
			if i == 0 {
				u.trusted = true
			}
			continue
		}

		opt := &upstream.Opt{
			DialAddr:       c.DialAddr,
			Socks5:         c.Socks5,
			SoMark:         c.SoMark,
			BindToDevice:   c.BindToDevice,
			IdleTimeout:    time.Duration(c.IdleTimeout) * time.Second,
			MaxConns:       c.MaxConns,
			EnablePipeline: c.EnablePipeline,
			EnableHTTP3:    c.EnableHTTP3,
			Bootstrap:      c.Bootstrap,
			TLSConfig: &tls.Config{
				InsecureSkipVerify: c.InsecureSkipVerify,
				RootCAs:            rootCAs,
				ClientSessionCache: tls.NewLRUClientSessionCache(64),
			},
			Logger: bp.L(),
		}

		u, err := upstream.NewUpstream(c.Addr, opt)
		if err != nil {
			return nil, fmt.Errorf("failed to init upstream: %w", err)
		}

		w := &upstreamWrapper{
			address: c.Addr,
			trusted: c.Trusted,
			u:       u,
		}

		if i == 0 { // Set first upstream as trusted upstream.
			w.trusted = true
		}

		f.upstreamWrappers = append(f.upstreamWrappers, w)
		f.upstreamsCloser = append(f.upstreamsCloser, u)
	}

	return f, nil
}

type upstreamWrapper struct {
	address string
	trusted bool
	u       upstream.Upstream
}

func (u *upstreamWrapper) Exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	return u.u.ExchangeContext(ctx, q)
}

func (u *upstreamWrapper) Address() string {
	return u.address
}

func (u *upstreamWrapper) Trusted() bool {
	return u.trusted
}

// Exec forwards qCtx.Q() to upstreams, and sets qCtx.R().
// qCtx.Status() will be set as
// - handler.ContextStatusResponded: if it received a response.
// - handler.ContextStatusServerFailed: if all upstreams failed.
func (f *fastForward) Exec(ctx context.Context, qCtx *query_context.Context, next executable_seq.ExecutableChainNode) error {
	err := f.exec(ctx, qCtx)
	if err != nil {
		return err
	}
	return executable_seq.ExecChainNode(ctx, qCtx, next)
}

func (f *fastForward) exec(ctx context.Context, qCtx *query_context.Context) (err error) {
	r, err := bundled_upstream.ExchangeParallel(ctx, qCtx, f.upstreamWrappers, f.L())
	if err != nil {
		return err
	}
	qCtx.SetResponse(r)
	return nil
}

func (f *fastForward) Shutdown() error {
	for _, u := range f.upstreamsCloser {
		u.Close()
	}
	return nil
}
