//go:build ios && !e2e_testing
// +build ios,!e2e_testing

package overlay

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/iputil"
)

type tun struct {
	io.ReadWriteCloser
	Device string
	Cidr   *net.IPNet
}

func newTun(_ *logrus.Logger, _ string, _ *net.IPNet, _ int, _ []Route, _ int, _ bool) (*tun, error) {
	return nil, fmt.Errorf("newTun not supported in iOS")
}

func newTunFromFd(_ *logrus.Logger, deviceFd int, certCidr *net.IPNet, _ int, routes []Route, _ int) (*tun, error) {
	if len(routes) > 0 {
		return nil, fmt.Errorf("routes are not supported in iOS")
	}

	file := os.NewFile(uintptr(deviceFd), "/dev/tun")
	return &tun{
		Cidr:            certCidr,
		Device:          "iOS",
		ReadWriteCloser: &tunReadCloser{f: file},
	}, nil
}

func (t *tun) RouteFor(iputil.VpnIp) iputil.VpnIp {
	return 0
}

func (t *tun) Activate() error {
	return nil
}

func (t *tun) WriteRaw(b []byte) error {
	_, err := t.Write(b)
	return err
}

// The following is hoisted up from water, we do this so we can inject our own fd on iOS
type tunReadCloser struct {
	f io.ReadWriteCloser

	rMu  sync.Mutex
	rBuf []byte

	wMu  sync.Mutex
	wBuf []byte
}

func (t *tunReadCloser) Read(to []byte) (int, error) {
	t.rMu.Lock()
	defer t.rMu.Unlock()

	if cap(t.rBuf) < len(to)+4 {
		t.rBuf = make([]byte, len(to)+4)
	}
	t.rBuf = t.rBuf[:len(to)+4]

	n, err := t.f.Read(t.rBuf)
	copy(to, t.rBuf[4:])
	return n - 4, err
}

func (t *tunReadCloser) Write(from []byte) (int, error) {

	if len(from) == 0 {
		return 0, syscall.EIO
	}

	t.wMu.Lock()
	defer t.wMu.Unlock()

	if cap(t.wBuf) < len(from)+4 {
		t.wBuf = make([]byte, len(from)+4)
	}
	t.wBuf = t.wBuf[:len(from)+4]

	// Determine the IP Family for the NULL L2 Header
	ipVer := from[0] >> 4
	if ipVer == 4 {
		t.wBuf[3] = syscall.AF_INET
	} else if ipVer == 6 {
		t.wBuf[3] = syscall.AF_INET6
	} else {
		return 0, errors.New("unable to determine IP version from packet")
	}

	copy(t.wBuf[4:], from)

	n, err := t.f.Write(t.wBuf)
	return n - 4, err
}

func (t *tunReadCloser) Close() error {
	return t.f.Close()
}

func (t *tun) CidrNet() *net.IPNet {
	return t.Cidr
}

func (t *tun) DeviceName() string {
	return t.Device
}

func (t *tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented for ios")
}
