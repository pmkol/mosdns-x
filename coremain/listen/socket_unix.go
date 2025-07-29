//go:build darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

package listen

import (
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func CreateListenConfig() net.ListenConfig {
	return net.ListenConfig{
		Control: func(network, address string, c syscall.RawConn) error {
			var e error
			err := c.Control(func(fd uintptr) {
				e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEADDR, 1)
				if e != nil {
					return
				}
				e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_REUSEPORT, 1)
				if e != nil {
					return
				}
				e = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_RCVBUF, 64*1024)
				if e != nil {
					return
				}
			})
			if err != nil {
				return err
			}
			if e != nil {
				return e
			}
			return nil
		},
	}
}
