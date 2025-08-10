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
	"io"
	"net"
	"net/url"
	"time"

	"gitlab.com/go-extension/http"

	H "github.com/pmkol/mosdns-x/pkg/server/http_handler"
)

func (s *Server) ServeHTTP(l net.Listener) error {
	defer l.Close()

	if s.opts.HttpHandler == nil {
		return errMissingHTTPHandler
	}

	idleTimeout := s.opts.IdleTimeout
	if idleTimeout == 0 {
		idleTimeout = defaultTCPIdleTimeout
	}

	hs := &http.Server{
		Handler:           &eHandler{s.opts.HttpHandler},
		ReadHeaderTimeout: time.Millisecond * 500,
		ReadTimeout:       time.Second * 5,
		WriteTimeout:      time.Second * 5,
		IdleTimeout:       idleTimeout,
		MaxHeaderBytes:    2048,
	}
	if ok := s.trackCloser(hs, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(hs, false)

	err := hs.Serve(l)
	if err == http.ErrServerClosed { // Replace http.ErrServerClosed with our ErrServerClosed
		return ErrServerClosed
	} else if err != nil {
		return err
	}
	return nil
}

type eHandler struct {
	h *H.Handler
}

func (h *eHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	h.h.ServeHTTP(&eWriter{w}, &eRequest{r})
}

type eRequest struct {
	r *http.Request
}

func (r *eRequest) URL() *url.URL {
	return r.r.URL
}

func (r *eRequest) Body() io.ReadCloser {
	return r.r.Body
}

func (r *eRequest) Header() H.Header {
	return r.r.Header
}

func (r *eRequest) Method() string {
	return r.r.Method
}

func (r *eRequest) Context() context.Context {
	return r.r.Context()
}

func (r *eRequest) RequestURI() string {
	return r.r.RequestURI
}

func (r *eRequest) GetRemoteAddr() string {
	return r.r.RemoteAddr
}

func (r *eRequest) SetRemoteAddr(addr string) {
	r.r.RemoteAddr = addr
}

type eWriter struct {
	w http.ResponseWriter
}

func (w *eWriter) Header() H.Header {
	return w.w.Header()
}

func (w *eWriter) Write(b []byte) (int, error) {
	return w.w.Write(b)
}

func (w *eWriter) WriteHeader(statusCode int) {
	w.w.WriteHeader(statusCode)
}
