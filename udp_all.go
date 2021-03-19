package nebula

import (
	"encoding/json"
	"fmt"
	"net"
	"strconv"
)

type udpAddr struct {
	IP   IP
	Port uint16
}

type IP [16]byte

func NewUDPAddr(ip IP, port uint16) *udpAddr {
	return &udpAddr{IP: ip, Port: port}
}

func NewUDPAddrFromUint32(ip uint32, port uint16) *udpAddr {
	return &udpAddr{
		IP: IP{
			0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
			byte(ip & 0xff000000 >> 24), byte(ip & 0x00ff0000 >> 16), byte(ip & 0x0000ff00 >> 8), byte(ip & 0x000000ff),
		},
		Port: port,
	}
}

func NewUDPAddrFromSlice(ip []byte, port uint16) *udpAddr {
	u := udpAddr{Port: port}
	copy(u.IP[:], ip)
	return &u
}

func NewUDPAddrFromString(s string) *udpAddr {
	ip, port, err := parseIPAndPort(s)
	//TODO: handle err
	_ = err
	return &udpAddr{IP: ip, Port: port}
}

func NewIPFromNetIP(ip net.IP) IP {
	i := IP{}
	if ipV4 := ip.To4(); ipV4 != nil {
		copy(i[12:], ipV4)
	} else {
		copy(i[:], ip)
	}

	return i
}

func (ua *udpAddr) Equals(t *udpAddr) bool {
	if t == nil || ua == nil {
		return t == nil && ua == nil
	}
	return ua.IP == t.IP && ua.Port == t.Port
}

func (ua *udpAddr) String() string {
	return net.JoinHostPort(net.IP(ua.IP[:]).String(), fmt.Sprintf("%v", ua.Port))
}

func (ua *udpAddr) MarshalJSON() ([]byte, error) {
	return json.Marshal(m{"ip": ua.IP, "port": ua.Port})
}

func (ua *udpAddr) Copy() *udpAddr {
	return &udpAddr{Port: ua.Port, IP: ua.IP}
}

func (ip IP) IsV4() bool {
	// We can be a v4 in v6 or just a v4 occupying the final 4 bytes
	return isZeros(ip[0:10]) && (isZeros(ip[10:12]) || ip[10] == 0xff && ip[11] == 0xff)
}

func (ip IP) ToV4() ([]byte, bool) {
	if ip.IsV4() {
		return ip[12:16], true
	}

	return ip[:], false
}

func (ip IP) ToNetIP() net.IP {
	if ip.IsV4() {
		return ip[12:16]
	}

	return ip[:]
}

func parseIPAndPort(s string) (IP, uint16, error) {
	b := IP{}
	rIp, sPort, err := net.SplitHostPort(s)
	if err != nil {
		return b, 0, err
	}

	iPort, err := strconv.Atoi(sPort)
	ip := net.ParseIP(rIp).To16()
	copy(b[:], ip)
	return b, uint16(iPort), nil
}

func isZeros(p []byte) bool {
	for i := 0; i < len(p); i++ {
		if p[i] != 0 {
			return false
		}
	}
	return true
}
