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

type Conn struct {
	*net.UDPConn
	l *logrus.Logger
}

func NewListener(l *logrus.Logger, ip string, port int, multi bool, batch int) (*Conn, error) {
	lc := NewListenConfig(multi)
	pc, err := lc.ListenPacket(context.TODO(), "udp", fmt.Sprintf("%s:%d", ip, port))
	if err != nil {
		return nil, err
	}
	if uc, ok := pc.(*net.UDPConn); ok {
		return &Conn{UDPConn: uc, l: l}, nil
	}
	return nil, fmt.Errorf("Unexpected PacketConn: %T %#v", pc, pc)
}

func (uc *Conn) WriteTo(b []byte, addr netip.AddrPort) error {
	_, err := uc.UDPConn.WriteToUDPAddrPort(b, addr)
	return err
}

func (uc *Conn) LocalAddr() (*Addr, error) {
	a := uc.UDPConn.LocalAddr()

	switch v := a.(type) {
	case *net.UDPAddr:
		addr := &Addr{IP: make([]byte, len(v.IP))}
		copy(addr.IP, v.IP)
		addr.Port = uint16(v.Port)
		return addr, nil

	default:
		return nil, fmt.Errorf("LocalAddr returned: %#v", a)
	}
}

func (u *Conn) ReloadConfig(c *config.C) {
	// TODO
}

func NewUDPStatsEmitter(udpConns []*Conn) func() {
	// No UDP stats for non-linux
	return func() {}
}

type rawMessage struct {
	Len uint32
}

func (u *Conn) ListenOut(r EncReader, lhf LightHouseHandlerFunc, cache *firewall.ConntrackCacheTicker, q int) {
	plaintext := make([]byte, MTU)
	buffer := make([]byte, MTU)
	h := &header.H{}
	fwPacket := &firewall.Packet{}
	nb := make([]byte, 12, 12)

	for {
		// Just read one packet at a time
		n, addr, err := u.ReadFromUDPAddrPort(buffer)
		if err != nil {
			u.l.WithError(err).Error("Failed to read packets")
			continue
		}

		r(addr, nil, plaintext[:0], buffer[:n], h, fwPacket, lhf, nb, q, cache.Get(u.l))
	}
}
