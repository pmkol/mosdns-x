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
	"reflect"
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
	// "True-Client-IP" "X-Real-IP" "X-Forwarded-For" will parse automatically.
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
	// get remote addr from header and request
	var meta query_context.RequestMeta
	if addr, err := getRemoteAddr(req, h.opts.SrcIPHeader); err == nil {
		meta.ClientAddr = addr
	}

	// check url path
	if len(h.opts.Path) != 0 && req.URL.Path != h.opts.Path {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("invalid request path"))
		h.warnErr(req, "invalid request", fmt.Errorf("invalid request path %s", req.URL.Path))
		return
	}

	// check accept header
	if accept := req.Header.Get("Accept"); accept != "application/dns-message" {
		w.WriteHeader(http.StatusPreconditionFailed)
		w.Write([]byte("invalid Accept header"))
		h.warnErr(req, "invalid Accept header", fmt.Errorf("invalid Accept header %s", accept))
		return
	}

	var b []byte
	var err error

	switch req.Method {
	case http.MethodGet:
		s := req.URL.Query().Get("dns")
		if len(s) == 0 {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("no dns param"))
			h.warnErr(req, "no dns param", errors.New("no dns param"))
			return
		}

		b, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid dns param"))
			h.warnErr(req, "decode base64 query failed", fmt.Errorf(" base64 query failed: %s", err))
			return
		}
	case http.MethodPost:
		if contentType := req.Header.Get("Content-Type"); contentType != "application/dns-message" {
			w.WriteHeader(http.StatusUnsupportedMediaType)
			w.Write([]byte("invalid Content-Type"))
			h.warnErr(req, "invalid Content-Type", fmt.Errorf("invalid Content-Type %s", contentType))
			return
		}

		b, err = io.ReadAll(req.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			w.Write([]byte("invalid request body"))
			h.warnErr(req, "read request body failed", err)
			return
		}
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		w.Write([]byte("invalid request method"))
		h.warnErr(req, "invalid method", fmt.Errorf("invalid method %s", req.Method))
		return
	}

	// read msg
	m := new(dns.Msg)
	if err := m.Unpack(b); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		w.Write([]byte("invalid request message"))
		h.warnErr(req, "unpack request failed", err)
		return
	}

	r, err := h.opts.DNSHandler.ServeDNS(req.Context(), m, &meta)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("unpack response failed"))
		h.warnErr(req, "unpack response failed", err)
		return
	}

	b, buf, err := pool.PackBuffer(r)
	if err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		w.Write([]byte("pack response failed"))
		h.warnErr(req, "pack response failed", err)
		return
	}
	defer buf.Release()

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", fmt.Sprintf("max-age=%d", dnsutils.GetMinimalTTL(r)))
	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(b); err != nil {
		h.warnErr(req, "write response failed", err)
	}
}

func getRemoteAddr(req *http.Request, customHeader string) (netip.Addr, error) {
	if tcip := req.Header.Get("True-Client-IP"); tcip != "" {
		if addr, err := netip.ParseAddr(tcip); err == nil {
			req.RemoteAddr = addr.String()
			return addr, nil
		}
	}
	if xrip := req.Header.Get("X-Real-IP"); xrip != "" {
		if addr, err := netip.ParseAddr(xrip); err == nil {
			req.RemoteAddr = addr.String()
			return addr, nil
		}
	}
	if xff := req.Header.Get("X-Forwarded-For"); xff != "" {
		ip, _, _ := strings.Cut(xff, ",")
		if addr, err := netip.ParseAddr(ip); err == nil {
			req.RemoteAddr = addr.String()
			return addr, nil
		}
	}
	if customHeader != "" && !contain([]string{"True-Client-IP", "X-Real-IP", "X-Forwarded-For"}, customHeader) {
		if ip := req.Header.Get(customHeader); ip != "" {
			if addr, err := netip.ParseAddr(ip); err == nil {
				req.RemoteAddr = addr.String()
				return addr, nil
			}
		}
	}
	addrport, err := netip.ParseAddrPort(req.RemoteAddr)
	if err != nil {
		return netip.Addr{}, err
	}
	return addrport.Addr(), nil
}

func contain[T any](arr []T, it T) bool {
	for _, item := range arr {
		if reflect.DeepEqual(it, item) {
			return true
		}
	}
	return false
}
