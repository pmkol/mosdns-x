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
	"crypto/tls"
	"errors"
	"net"
	"time"

	"github.com/fsnotify/fsnotify"
	eTLS "gitlab.com/go-extension/tls"
)

type cert[T tls.Certificate | eTLS.Certificate] struct {
	c *T
}

func tryCreateWatchCert[T tls.Certificate | eTLS.Certificate](certFile string, keyFile string, createFunc func(string, string) (T, error)) (*cert[T], error) {
	c, err := createFunc(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cc := &cert[T]{&c}
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		watcher.Add(certFile)
		watcher.Add(keyFile)
		var timer *time.Timer
		for {
			select {
			case e, ok := <-watcher.Events:
				if !ok {
					if timer != nil {
						timer.Stop()
						timer = nil
					}
					return
				}
				if e.Has(fsnotify.Chmod) || e.Has(fsnotify.Remove) {
					continue
				}
				if timer == nil {
					timer = time.AfterFunc(time.Second, func() {
						timer = nil
						if c, err := createFunc(certFile, keyFile); err == nil {
							cc.c = &c
						}
					})
				} else {
					timer.Reset(time.Second)
				}
			case err := <-watcher.Errors:
				if err != nil {
					if timer != nil {
						timer.Stop()
						timer = nil
					}
					return
				}
			}
		}
	}()
	return cc, nil
}

func (s *Server) createTLSListner(l net.Listener, nextProtos []string) (net.Listener, error) {
	tlsConf := &tls.Config{
		NextProtos: nextProtos,
	}
	if len(s.opts.Key)+len(s.opts.Cert) != 0 {
		c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair)
		if err != nil {
			return nil, err
		}
		tlsConf.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.c, nil
		}
	} else {
		return nil, errors.New("missing certificate for tls listener")
	}
	return tls.NewListener(l, tlsConf), nil
}

func (s *Server) createETLSListner(l net.Listener, nextProtos []string) (net.Listener, error) {
	tlsConf := &eTLS.Config{
		KernelTX:   true,
		KernelRX:   false,
		NextProtos: nextProtos,
	}
	if len(s.opts.Key)+len(s.opts.Cert) != 0 {
		c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, eTLS.LoadX509KeyPair)
		if err != nil {
			return nil, err
		}
		tlsConf.GetCertificate = func(chi *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			return c.c, nil
		}
	} else {
		return nil, errors.New("missing certificate for tls listener")
	}
	return eTLS.NewListener(l, tlsConf), nil
}
