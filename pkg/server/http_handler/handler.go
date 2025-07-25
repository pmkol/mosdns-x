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

package http_handler

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"

	"github.com/miekg/dns"
	"go.uber.org/zap"

	"github.com/pmkol/mosdns-x/pkg/dnsutils"
	"github.com/pmkol/mosdns-x/pkg/pool"
	"github.com/pmkol/mosdns-x/pkg/query_context"
	"github.com/pmkol/mosdns-x/pkg/server/dns_handler"
)

var nopLogger = zap.NewNop()

type HandlerOpts struct {
	// DNSHandler is required.
	DNSHandler dns_handler.Handler

	// Path specifies the query endpoint. If it is empty, Handler
	// will ignore the request path.
	Path string

	// SrcIPHeader specifies the header that contain client source address.
	// e.g. "X-Forwarded-For".
	SrcIPHeader string

	// Logger specifies the logger which Handler writes its log to.
	// Default is a nop logger.
	Logger *zap.Logger
}

func (opts *HandlerOpts) Init() error {
	if opts.DNSHandler == nil {
		return errors.New("nil dns handler")
	}
	if opts.Logger == nil {
		opts.Logger = nopLogger
	}
	return nil
}

type Handler struct {
	opts HandlerOpts
}

func NewHandler(opts HandlerOpts) (*Handler, error) {
	if err := opts.Init(); err != nil {
		return nil, err
	}
	return &Handler{opts: opts}, nil
}

func (h *Handler) warnErr(req *http.Request, msg string, err error) {
	h.opts.Logger.Warn(msg, zap.String("from", req.RemoteAddr), zap.String("method", req.Method), zap.String("url", req.RequestURI), zap.Error(err))
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, req *http.Request) {
	addrPort, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		w.Write([]byte(fmt.Errorf("failed to parse request remote addr: %s", err).Error()))
		w.WriteHeader(http.StatusInternalServerError)
		h.opts.Logger.Error("failed to parse request remote addr", zap.String("addr", req.RemoteAddr), zap.Error(err))
		return
	}
	clientAddr := addrPort.Addr()

	// read remote addr from header
	if header := h.opts.SrcIPHeader; len(header) != 0 {
		if xff := req.Header.Get(header); len(xff) != 0 {
			addr, err := readClientAddrFromXFF(xff)
			if err != nil {
				w.Write([]byte("invalid client address"))
				w.WriteHeader(http.StatusBadRequest)
				h.warnErr(req, "failed to get client ip from header", err)
				return
			}
			clientAddr = addr
		}
	}

	// check url path
	if len(h.opts.Path) != 0 && req.URL.Path != h.opts.Path {
		w.Write([]byte("invalid request path"))
		w.WriteHeader(http.StatusNotFound)
		h.warnErr(req, "invalid request", fmt.Errorf("invalid request path %s", req.URL.Path))
		return
	}

	// check accept header
	if accept := req.Header.Get("Accept"); accept != "application/dns-message" {
		w.Write([]byte("invalid Accept header"))
		w.WriteHeader(http.StatusPreconditionFailed)
		h.warnErr(req, "invalid Accept header", fmt.Errorf("invalid Accept header %s", accept))
		return
	}

	var b []byte

	switch req.Method {
	case http.MethodGet:
		s := req.URL.Query().Get("dns")
		if len(s) == 0 {
			w.Write([]byte("no dns param"))
			w.WriteHeader(http.StatusBadRequest)
			h.warnErr(req, "no dns param", errors.New("no dns param"))
			return
		}

		b, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			w.Write([]byte("invalid dns param"))
			w.WriteHeader(http.StatusBadRequest)
			h.warnErr(req, "decode base64 query failed", fmt.Errorf(" base64 query failed: %s", err))
			return
		}
	case http.MethodPost:
		if contentType := req.Header.Get("Content-Type"); contentType != "application/dns-message" {
			w.Write([]byte("invalid Content-Type"))
			w.WriteHeader(http.StatusUnsupportedMediaType)
			h.warnErr(req, "invalid Content-Type", fmt.Errorf("invalid Content-Type %s", contentType))
			return
		}

		b, err = io.ReadAll(req.Body)
		if err != nil {
			w.Write([]byte("invalid request body"))
			w.WriteHeader(http.StatusBadRequest)
			h.warnErr(req, "read request body failed", err)
			return
		}
	default:
		w.Write([]byte("invalid request method"))
		w.WriteHeader(http.StatusMethodNotAllowed)
		h.warnErr(req, "invalid method", fmt.Errorf("invalid method %s", req.Method))
		return
	}

	// read msg
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		w.Write([]byte("invalid request message"))
		w.WriteHeader(http.StatusBadRequest)
		h.warnErr(req, "unpack request failed", err)
		return
	}

	r, err := h.opts.DNSHandler.ServeDNS(req.Context(), m, &query_context.RequestMeta{ClientAddr: clientAddr})
	if err != nil {
		w.Write([]byte("unpack response failed"))
		w.WriteHeader(http.StatusInternalServerError)
		h.warnErr(req, "unpack response failed", err)
		return
	}

	b, buf, err := pool.PackBuffer(r)
	if err != nil {
		w.Write([]byte("pack response failed"))
		w.WriteHeader(http.StatusInternalServerError)
		h.warnErr(req, "pack response failed", err)
		return
	}
	defer buf.Release()

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", dnsutils.GetMinimalTTL(r)))
	if _, err := w.Write(b); err != nil {
		h.warnErr(req, "write response failed", err)
		return
	}
}

func readClientAddrFromXFF(s string) (netip.Addr, error) {
	if i := strings.IndexRune(s, ','); i > 0 {
		return netip.ParseAddr(s[:i])
	}
	return netip.ParseAddr(s)
}
