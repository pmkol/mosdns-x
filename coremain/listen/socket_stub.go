//go:build !darwin && !dragonfly && !freebsd && !linux && !netbsd && !openbsd && !solaris && !windows

package listen

import (
	"net"
)

func CreateListenConfig() net.ListenConfig {
	return net.ListenConfig{}
}
