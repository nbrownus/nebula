//go:build (!linux || android) && !e2e_testing
// +build !linux android
// +build !e2e_testing

// udp_generic implements the nebula UDP interface in pure Go stdlib. This
// means it can be used on platforms like Darwin and Windows.

package udp

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/firewall"
	"github.com/slackhq/nebula/header"
)

type GenericConn struct {
	*net.UDPConn
	l *logrus.Logger
}

var _ Conn = &GenericConn{}

func NewGenericListener(l *logrus.Logger, ip netip.Addr, port int, multi bool, batch int) (Conn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", net.JoinHostPort(ip.String(), fmt.Sprintf("%v", port)))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &GenericConn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (u *GenericConn) WriteTo(b []byte, addr netip.AddrPort) error {
	_, err := u.UDPConn.WriteToUDPAddrPort(b, addr)
	return err
}

func (u *GenericConn) LocalAddr() (netip.AddrPort, error) {
	a := u.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr, _ := netip.AddrFromSlice(v.IP)
		return netip.AddrPortFrom(addr, uint16(v.Port)), nil

	default:
		return netip.AddrPort{}, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *GenericConn) ReloadConfig(c *config.C) {
	// TODO
}

func NewUDPStatsEmitter(udpConns []Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

type rawMessage struct {
	Len uint32
}

func (u *GenericConn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, rua, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			u.l.WithError(err).Debug("udp socket is closed, exiting read loop")
			return
		}

		r(
			netip.AddrPortFrom(rua.Addr().Unmap(), rua.Port()),
			plaintext[:0],
			buffer[:n],
			h,
			fwPacket,
			lhf,
			nb,
			q,
			cache.Get(u.l),
		)
	}
}
