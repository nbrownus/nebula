package nebula

import (
	"github.com/slackhq/nebula/header"
	"net/netip"
)

func HandleIncomingHandshake(f *Interface, addr netip.AddrPort, via interface{}, packet []byte, h *header.H, hostinfo *HostInfo) {
	// First remote allow list check before we know the vpnIp
	if addr.IsValid() {
		if !f.lightHouse.GetRemoteAllowList().AllowUnknownVpnIp(addr) {
			f.l.WithField("udpAddr", addr).Debug("lighthouse.remote_allow_list denied incoming handshake")
			return
		}
	}

	switch h.Subtype {
	case header.HandshakeIXPSK0:
		switch h.MessageCounter {
		case 1:
			ixHandshakeStage1(f, addr, via, packet, h)
		case 2:
			newHostinfo, _ := f.handshakeManager.QueryIndex(h.RemoteIndex)
			tearDown := ixHandshakeStage2(f, addr, via, newHostinfo, packet, h)
			if tearDown && newHostinfo != nil {
				f.handshakeManager.DeleteHostInfo(newHostinfo)
			}
		}
	}

}
