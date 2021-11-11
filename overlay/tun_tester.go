//go:build e2e_testing
// +build e2e_testing

package overlay

import (
	"fmt"
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
)

type TestTun struct {
	Device   string
	Cidr     *net.IPNet
	MTU      int
	Routes   []Route
	cidrTree *cidr.Tree4
	l        *logrus.Logger

	RxPackets chan []byte // Packets to receive into nebula
	TxPackets chan []byte // Packets transmitted outside by nebula
}

func newTun(l *logrus.Logger, deviceName string, certCidr *net.IPNet, defaultMTU int, routes []Route, _ int, _ bool) (*TestTun, error) {
	cidrTree := cidr.NewTree4()
	for _, r := range routes {
		if r.Via != nil {
			cidrTree.AddCIDR(r.Cidr, r.Via)
		}
	}

	return &TestTun{
		Device:    deviceName,
		Cidr:      certCidr,
		MTU:       defaultMTU,
		Routes:    routes,
		cidrTree:  cidrTree,
		l:         l,
		RxPackets: make(chan []byte, 1),
		TxPackets: make(chan []byte, 1),
	}, nil
}

func (t *TestTun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := t.cidrTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func newTunFromFd(_ *logrus.Logger, _ int, _ *net.IPNet, _ int, _ []Route, _ int) (*TestTun, error) {
	return nil, fmt.Errorf("newTunFromFd not supported")
}

// Send will place a byte array onto the receive queue for nebula to consume
// These are unencrypted ip layer frames destined for another nebula node.
// packets should exit the udp side, capture them with udpConn.Get
func (t *TestTun) Send(packet []byte) {
	t.l.WithField("dataLen", len(packet)).Info("tun receiving injected packet")
	t.RxPackets <- packet
}

// Get will pull an unencrypted ip layer frame from the transmit queue
// nebula meant to send this message to some application on the local system
// packets were ingested from the udp side, you can send them with udpConn.Send
func (t *TestTun) Get(block bool) []byte {
	if block {
		return <-t.TxPackets
	}

	select {
	case p := <-t.TxPackets:
		return p
	default:
		return nil
	}
}

//********************************************************************************************************************//
// Below this is boilerplate implementation to make nebula actually work
//********************************************************************************************************************//

func (t *TestTun) Activate() error {
	return nil
}

func (t *TestTun) CidrNet() *net.IPNet {
	return t.Cidr
}

func (t *TestTun) DeviceName() string {
	return t.Device
}

func (t *TestTun) Write(b []byte) (n int, err error) {
	return len(b), t.WriteRaw(b)
}

func (t *TestTun) Close() error {
	close(t.RxPackets)
	return nil
}

func (t *TestTun) WriteRaw(b []byte) error {
	packet := make([]byte, len(b), len(b))
	copy(packet, b)
	t.TxPackets <- packet
	return nil
}

func (t *TestTun) Read(b []byte) (int, error) {
	p := <-t.RxPackets
	copy(b, p)
	return len(p), nil
}

func (t *TestTun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	return nil, fmt.Errorf("TODO: multiqueue not implemented")
}
