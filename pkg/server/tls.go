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
	"crypto/x509"
	"errors"
	"net"
	"time"

	"github.com/fsnotify/fsnotify"
	"github.com/quic-go/quic-go"
	eTLS "gitlab.com/go-extension/tls"
)

type cert[T tls.Certificate | eTLS.Certificate] struct {
	c *T
}

func calculateTimeUntilMidnight() time.Duration {
	now := time.Now()
	nextMidnight := time.Date(now.Year(), now.Month(), now.Day()+1, 0, 0, 0, 0, now.Location())
	return nextMidnight.Sub(now)
}

func tryCreateWatchCert[T tls.Certificate | eTLS.Certificate](certFile string, keyFile string, createFunc func(string, string) (T, error)) (*cert[T], error) {
	c, err := createFunc(certFile, keyFile)
	if err != nil {
		return nil, err
	}
	cc := &cert[T]{&c}
	checkAndReloadCert := func() {
		var certBytes [][]byte
		switch c := any(cc.c).(type) {
		case *tls.Certificate:
			certBytes = c.Certificate
		case *eTLS.Certificate:
			certBytes = c.Certificate
		}
		if len(certBytes) > 0 {
			if x509Cert, err := x509.ParseCertificate(certBytes[0]); err == nil {
				now := time.Now()
				expiryThreshold := now.Add(72 * time.Hour)
				if x509Cert.NotAfter.Before(expiryThreshold) {
					if newCert, err := createFunc(certFile, keyFile); err == nil {
						cc.c = &newCert
					}
				}
			}
		}
	}
	go func() {
		watcher, err := fsnotify.NewWatcher()
		if err != nil {
			return
		}
		defer watcher.Close()
		_ = watcher.Add(certFile)
		_ = watcher.Add(keyFile)
		var timer *time.Timer
		dailyCheckTimer := time.NewTimer(calculateTimeUntilMidnight())
		defer dailyCheckTimer.Stop()
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
				if err != nil && timer != nil {
					timer.Stop()
					timer = nil
				}
			case <-dailyCheckTimer.C:
				checkAndReloadCert()
				dailyCheckTimer.Reset(calculateTimeUntilMidnight())
			}
		}
	}()
	return cc, nil
}

func (s *Server) CreateQUICListner(conn net.PacketConn, nextProtos []string) (*quic.EarlyListener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}
	c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, tls.LoadX509KeyPair)
	if err != nil {
		return nil, err
	}
	return quic.ListenEarly(conn, &tls.Config{
		NextProtos: nextProtos,
		GetCertificate: func(chi *tls.ClientHelloInfo) (*tls.Certificate, error) {
			return c.c, nil
		},
	}, &quic.Config{
		Allow0RTT:                      true,
		InitialStreamReceiveWindow:     1252,
		MaxStreamReceiveWindow:         4 * 1024,
		InitialConnectionReceiveWindow: 8 * 1024,
		MaxConnectionReceiveWindow:     16 * 1024,
	})
}

func (s *Server) CreateETLSListner(l net.Listener, nextProtos []string) (net.Listener, error) {
	if s.opts.Cert == "" || s.opts.Key == "" {
		return nil, errors.New("missing certificate for tls listener")
	}
	c, err := tryCreateWatchCert(s.opts.Cert, s.opts.Key, eTLS.LoadX509KeyPair)
	if err != nil {
		return nil, err
	}
	return eTLS.NewListener(l, &eTLS.Config{
		KernelTX:       s.opts.KernelTX,
		KernelRX:       s.opts.KernelRX,
		AllowEarlyData: true,
		MaxEarlyData:   4096,
		NextProtos:     nextProtos,
		Defaults: eTLS.Defaults{
			AllSecureCipherSuites: true,
			AllSecureCurves:       true,
		},
		GetCertificate: func(_ *eTLS.ClientHelloInfo) (*eTLS.Certificate, error) {
			return c.c, nil
		},
	}), nil
}
