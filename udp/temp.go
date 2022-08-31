package udp

import (
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"net/netip"
)

type EncWriter interface {
	SendVia(via interface{},
		relay interface{},
		ad,
		nb,
		out []byte,
		nocopy bool,
	)
	SendMessageToVpnIp(t header.MessageType, st header.MessageSubType, vpnIp iputil.VpnIp, p, nb, out []byte)
	Handshake(vpnIp iputil.VpnIp)
}

//TODO: The items in this file belong in their own packages but doing that in a single PR is a nightmare

type LightHouseHandlerFunc func(rAddr netip.AddrPort, vpnIp iputil.VpnIp, p []byte, w EncWriter)
