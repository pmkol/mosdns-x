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
	"net"
	"net/http"
	"time"

	"go.uber.org/zap"
	"golang.org/x/net/http2"
)

func (s *Server) ServeHTTP(l net.Listener) error {
	defer l.Close()

	if s.opts.HttpHandler == nil {
		return errMissingHTTPHandler
	}

	hs := &http.Server{
		Handler:           s.opts.HttpHandler,
		ReadHeaderTimeout: time.Millisecond * 500,
		ReadTimeout:       time.Second * 5,
		WriteTimeout:      time.Second * 5,
		IdleTimeout:       s.opts.IdleTimeout,
		MaxHeaderBytes:    2048,
	}
	if ok := s.trackCloser(hs, true); !ok {
		return ErrServerClosed
	}
	defer s.trackCloser(hs, false)

	err := http2.ConfigureServer(hs, &http2.Server{IdleTimeout: s.opts.IdleTimeout})
	if err != nil {
		s.opts.Logger.Error("failed to set up http2 support", zap.Error(err))
	}

	err = hs.Serve(l)
	if err == http.ErrServerClosed { // Replace http.ErrServerClosed with our ErrServerClosed
		return ErrServerClosed
	} else if err != nil {
		return err
	}
	return nil
}
