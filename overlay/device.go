package overlay

import (
	"github.com/slackhq/nebula/iputil"
	"io"
	"net/netip"
)

type Device interface {
	io.ReadWriteCloser
	Activate() error
	Cidr() netip.Prefix
	Name() string
	RouteFor(addr iputil.VpnIp) iputil.VpnIp
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}
