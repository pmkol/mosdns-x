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

func watchCert[T tls.Certificate | eTLS.Certificate](c *T, cert string, key string, createFunc func(string, string) (T, error)) {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return
	}
	watcher.Add(cert)
	watcher.Add(key)

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
					if cert, err := createFunc(cert, key); err == nil {
						c = &cert
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
}

func (s *Server) createTLSConfig(nextProtos []string) (*tls.Config, error) {
	var tlsConf *tls.Config
	if s.opts.TLSConfig != nil {
		tlsConf = s.opts.TLSConfig.Clone()
	} else {
		tlsConf = new(tls.Config)
	}

	tlsConf.NextProtos = nextProtos

	if len(s.opts.Key)+len(s.opts.Cert) != 0 {
		var c *tls.Certificate
		cert, err := tls.LoadX509KeyPair(s.opts.Cert, s.opts.Key)
		if err != nil {
			return nil, err
		}
		c = &cert
		tlsConf.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c, nil
		}
		go watchCert(c, s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair)
	} else if len(tlsConf.Certificates) == 0 {
		return nil, errors.New("missing certificate for tls listener")
	}

	return tlsConf, nil
}

func (s *Server) createTLSListner(l net.Listener, nextProtos []string) (net.Listener, error) {
	tlsConf := &tls.Config{
		NextProtos: nextProtos,
	}
	if len(s.opts.Key)+len(s.opts.Cert) != 0 {
		var c *tls.Certificate
		cert, err := tls.LoadX509KeyPair(s.opts.Cert, s.opts.Key)
		if err != nil {
			return nil, err
		}
		c = &cert
		tlsConf.GetCertificate = func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c, nil
		}
		go watchCert(c, s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair)
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
		var c *eTLS.Certificate
		cert, err := eTLS.LoadX509KeyPair(s.opts.Cert, s.opts.Key)
		if err != nil {
			return nil, err
		}
		c = &cert
		tlsConf.GetCertificate = func(chi *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			return c, nil
		}
		go watchCert(c, s.opts.Cert, s.opts.Key, eTLS.LoadX509KeyPair)
	} else {
		return nil, errors.New("missing certificate for tls listener")
	}
	return eTLS.NewListener(l, tlsConf), nil
}
