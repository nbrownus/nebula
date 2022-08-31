package udp

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
)

type m map[string]interface{}

type Addr struct {
	IP   net.IP
	Port uint16
}

func NewAddr(ip net.IP, port uint16) *Addr {
	addr := Addr{IP: make([]byte, net.IPv6len), Port: port}
	copy(addr.IP, ip.To16())
	return &addr
}

func NewAddrFromString(s string) netip.AddrPort {
	addr, err := ParseIPAndPort(s)
	//TODO: handle err
	_ = err
	return addr
}

func (ua *Addr) Equals(t *Addr) bool {
	if t == nil || ua == nil {
		return t == nil && ua == nil
	}
	return ua.IP.Equal(t.IP) && ua.Port == t.Port
}

func (ua *Addr) String() string {
	if ua == nil {
		return "<nil>"
	}

	return net.JoinHostPort(ua.IP.String(), fmt.Sprintf("%v", ua.Port))
}

func (ua *Addr) MarshalJSON() ([]byte, error) {
	if ua == nil {
		return nil, nil
	}

	return json.Marshal(m{"ip": ua.IP, "port": ua.Port})
}

func (ua *Addr) Copy() *Addr {
	if ua == nil {
		return nil
	}

	nu := Addr{
		Port: ua.Port,
		IP:   make(net.IP, len(ua.IP)),
	}

	copy(nu.IP, ua.IP)
	return &nu
}

func ParseIPAndPort(s string) (netip.AddrPort, error) {
	rIp, sPort, err := net.SplitHostPort(s)
	if err != nil {
		return netip.AddrPort{}, err
	}

	rAddr, err := net.ResolveIPAddr("ip", rIp)
	if err != nil {
		return netip.AddrPort{}, err
	}

	iPort, err := strconv.Atoi(sPort)
	if err != nil {
		return netip.AddrPort{}, err
	}

	addr, ok := netip.AddrFromSlice(rAddr.IP)
	if !ok {
		return netip.AddrPort{}, errors.New("could not create netip addr from ip addr")
	}

	return netip.AddrPortFrom(addr, uint16(iPort)), nil
}
