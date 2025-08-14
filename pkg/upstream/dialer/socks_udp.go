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

package dialer

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"syscall"
	"time"
)

type SocksPacketConn struct {
	conn  net.Conn
	inner *net.UDPConn
	dest  *SocksAddr
	cache []byte
}

func (s *SocksPacketConn) Close() error {
	s.conn.Close()
	return s.inner.Close()
}

func (s *SocksPacketConn) LocalAddr() net.Addr {
	return s.inner.LocalAddr()
}

func (s *SocksPacketConn) RemoteAddr() net.Addr {
	if s.dest != nil {
		return s.dest.NetAddr()
	}
	return s.inner.RemoteAddr()
}

func (s *SocksPacketConn) pack(b []byte, addr net.Addr) ([]byte, error) {
	sAddr, err := ParseSocksAddr(addr.String())
	if err != nil {
		return nil, err
	}
	return slices.Concat([]byte{Reversed, Reversed, NoFragment}, sAddr.Slice(), b), nil
}

func (s *SocksPacketConn) unpack(b []byte) ([]byte, net.Addr, error) {
	if len(b) < 4 {
		return nil, nil, fmt.Errorf("header incomplete")
	}
	if reserved := b[:2]; reserved[0] != Reversed || reserved[1] != Reversed {
		return nil, nil, fmt.Errorf("invalid reserved byte: %v", reserved)
	}
	if b[2] != NoFragment {
		return nil, nil, fmt.Errorf("packet fragment is not supported")
	}
	switch b[3] {
	case TypeIPv4:
		if len(b) < 10 {
			return nil, nil, fmt.Errorf("ipv4 address incomplete")
		}
		addr, ok := netip.AddrFromSlice(b[4:8])
		if !ok {
			return nil, nil, fmt.Errorf("invalid ipv4 address")
		}
		port := binary.BigEndian.Uint16(b[8:10])
		return b[10:], net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port)), nil
	case TypeFqdn:
		addrLen := uint8(s.cache[4])
		if len(b) < int(addrLen+7) {
			return nil, nil, fmt.Errorf("fqdn address incomplete")
		}
		fqdn := string(s.cache[5 : 5+addrLen])
		port := binary.BigEndian.Uint16(s.cache[5+addrLen : 7+addrLen])
		fqdnAddr := UDPFqdnAddr(fmt.Sprintf("%s:%d", fqdn, port))
		return b[7+addrLen:], &fqdnAddr, nil
	case TypeIPv6:
		if len(b) < 22 {
			return nil, nil, fmt.Errorf("ipv6 address incomplete")
		}
		addr, ok := netip.AddrFromSlice(s.cache[4:20])
		if !ok {
			return nil, nil, fmt.Errorf("invalid ipv6 address")
		}
		port := binary.BigEndian.Uint16(s.cache[20:22])
		return b[22:], net.UDPAddrFromAddrPort(netip.AddrPortFrom(addr, port)), nil
	default:
		return nil, nil, fmt.Errorf("invalid address type: %v", s.cache[3])
	}
}

func (s *SocksPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	n, err := s.inner.Read(s.cache)
	if err != nil {
		return 0, nil, fmt.Errorf("read socks udp packet failed: %v", err)
	}
	payload, addr, err := s.unpack(s.cache[:n])
	if err != nil {
		return 0, nil, fmt.Errorf("read socks udp packet failed: unpack packet failed: %v", err)
	}
	if len(b) < len(payload) {
		return 0, nil, fmt.Errorf("read socks udp packet failed: aim slice too short")
	}
	copy(b, payload)
	return len(payload), addr, nil
}

func (s *SocksPacketConn) Read(b []byte) (int, error) {
	n, _, err := s.ReadFrom(b)
	return n, err
}

func (s *SocksPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	payload, err := s.pack(b, addr)
	if err != nil {
		return 0, fmt.Errorf("send socks udp packet failed: pack packet failed: %v", err)
	}
	n, err := s.inner.Write(payload)
	if err != nil {
		return 0, err
	}
	if n < len(payload) {
		return 0, fmt.Errorf("send socks udp packet failed: send packet incomplete")
	}
	return len(b), nil
}

func (s *SocksPacketConn) Write(b []byte) (int, error) {
	if s.dest == nil {
		return 0, fmt.Errorf("cannot use Write with unlimited destination")
	}
	return s.WriteTo(b, s.dest.NetAddr())
}

func (s *SocksPacketConn) SetDeadline(t time.Time) error {
	return s.inner.SetDeadline(t)
}

func (s *SocksPacketConn) SetReadDeadline(t time.Time) error {
	return s.inner.SetReadDeadline(t)
}

func (s *SocksPacketConn) SetWriteDeadline(t time.Time) error {
	return s.inner.SetWriteDeadline(t)
}

func (s *SocksPacketConn) SyscallConn() (syscall.RawConn, error) {
	return s.inner.SyscallConn()
}

func (s *SocksPacketConn) getHeaderLen() int {
	if s.dest == nil {
		return 262
	}
	return len(s.dest.Slice())
}

func (s *SocksPacketConn) SetReadBuffer(bytes int) error {
	return s.inner.SetReadBuffer(bytes + s.getHeaderLen())
}

func (s *SocksPacketConn) SetWriteBuffer(bytes int) error {
	return s.inner.SetWriteBuffer(bytes + s.getHeaderLen())
}

// todo
// func (s *SocksPacketConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
// 	n, oobn, flag, _, err := s.inner.ReadMsgUDP(s.cache, oob)
// 	if err != nil {
// 		return 0, 0, 0, nil, fmt.Errorf("read socks udp packet failed: %v", err)
// 	}
// 	payload, addr, err := s.unpack(s.cache[:n])
// 	if err != nil {
// 		return 0, 0, 0, nil, fmt.Errorf("read socks udp packet failed: unpack packet failed: %v", err)
// 	}
// 	uAddr, isUDPAddr := addr.(*net.UDPAddr)
// 	if !isUDPAddr {
// 		return 0, 0, 0, nil, fmt.Errorf("read socks udp packet failed: address is not an *net.UDPAddr")
// 	}
// 	if len(b) < len(payload) {
// 		return 0, 0, 0, nil, fmt.Errorf("read socks udp packet failed: aim slice too short")
// 	}
// 	copy(b, payload)
// 	return len(payload), oobn, flag, uAddr, nil
// }

// func (s *SocksPacketConn) WriteMsgUDP(b, oob []byte, addr *net.UDPAddr) (int, int, error) {
// 	payload, err := s.pack(b, addr)
// 	if err != nil {
// 		return 0, 0, fmt.Errorf("send socks udp packet failed: pack packet failed: %v", err)
// 	}
// 	n, oobn, err := s.inner.WriteMsgUDP(payload, oob, nil)
// 	if err != nil {
// 		return 0, 0, fmt.Errorf("send socks udp packet failed: %v", err)
// 	}
// 	if n < len(payload) {
// 		return 0, 0, fmt.Errorf("send socks udp packet failed: send packet incomplete")
// 	}
// 	return len(b), oobn, nil
// }
