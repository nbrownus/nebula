//go:build !e2e_testing
// +build !e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"
	"os"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	"golang.org/x/sys/unix"
)

type tun struct {
	io.ReadWriteCloser
	fd         int
	Device     string
	Cidr       *net.IPNet
	MaxMTU     int
	DefaultMTU int
	TXQueueLen int
	Routes     []Route
	cidrTree   *cidr.Tree4
	l          *logrus.Logger
}

func newTunFromFd(l *logrus.Logger, deviceFd int, certCidr *net.IPNet, defaultMTU int, routes []Route, txQueueLen int) (*tun, error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	cidrTree := cidr.NewTree4()
	for _, r := range routes {
		if r.Via != nil {
			cidrTree.AddCIDR(r.Cidr, r.Via)
		}
	}

	return &tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          "android",
		Cidr:            certCidr,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		cidrTree:        cidrTree,
		l:               l,
	}, nil
}

func newTun(_ *logrus.Logger, _ string, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in Android")
}

func (t *tun) WriteRaw(b []byte) error {
	var nn int
	for {
		max := len(b)
		n, err := unix.Write(t.fd, b[nn:max])
		if n > 0 {
			nn += n
		}
		if nn == len(b) {
			return err
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
}

func (t *tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.cidrTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func (t tun) Activate() error {
	return nil
}

func (t *tun) CidrNet() *net.IPNet {
	return t.Cidr
}

func (t *tun) DeviceName() string {
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for android")
}
