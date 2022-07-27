//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula"
	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/header"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/udp"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

func TestGoodHandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me", net.IP{10, 0, 0, 1}, nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2}, nil)

	// Put their info in our lighthouse
	myControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Send a udp packet through to begin standing up the tunnel, this should come out the other side")
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))

	t.Log("Have them consume my stage 0 packet. They have a tunnel now")
	theirControl.InjectUDPPacket(myControl.GetFromUDP(true))

	t.Log("Get their stage 1 packet so that we can play with it")
	stage1Packet := theirControl.GetFromUDP(true)

	t.Log("I consume a garbage packet with a proper nebula header for our tunnel")
	// this should log a statement and get ignored, allowing the real handshake packet to complete the tunnel
	badPacket := stage1Packet.Copy()
	badPacket.Data = badPacket.Data[:len(badPacket.Data)-header.Len]
	myControl.InjectUDPPacket(badPacket)

	t.Log("Have me consume their real stage 1 packet. I have a tunnel now")
	myControl.InjectUDPPacket(stage1Packet)

	t.Log("Wait until we see my cached packet come through")
	myControl.WaitForType(1, 0, theirControl)

	t.Log("Make sure our host infos are correct")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl)

	t.Log("Get that cached packet and make sure it looks right")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)

	t.Log("Do a bidirectional tunnel test")
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()
	assertTunnel(t, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
	//TODO: assert hostmaps
}

func TestWrongResponderHandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})

	// The IPs here are chosen on purpose:
	// The current remote handling will sort by preference, public, and then lexically.
	// So we need them to have a higher address than evil (we could apply a preference though)
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me", net.IP{10, 0, 0, 100}, nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 99}, nil)
	evilControl, evilVpnIp, evilUdpAddr, _ := newSimpleServer(ca, caKey, "evil", net.IP{10, 0, 0, 2}, nil)

	// Add their real udp addr, which should be tried after evil.
	myControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)

	// Put the evil udp addr in for their vpn Ip, this is a case of being lied to by the lighthouse.
	myControl.InjectLightHouseAddr(theirVpnIpNet.IP, evilUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl, evilControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()
	evilControl.Start()

	t.Log("Start the handshake process, we will route until we see our cached packet get sent to them")
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))
	r.RouteForAllExitFunc(func(p *udp.Packet, c *nebula.Control) router.ExitType {
		h := &header.H{}
		err := h.Parse(p.Data)
		if err != nil {
			panic(err)
		}

		if p.ToIp.Equal(theirUdpAddr.IP) && p.ToPort == uint16(theirUdpAddr.Port) && h.Type == 1 {
			return router.RouteAndExit
		}

		return router.KeepRouting
	})

	//TODO: Assert pending hostmap - I should have a correct hostinfo for them now

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)

	t.Log("Test the tunnel with them")
	assertHostInfoPair(t, myUdpAddr, theirUdpAddr, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl)
	assertTunnel(t, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl, r)

	t.Log("Flush all packets from all controllers")
	r.FlushAll()

	t.Log("Ensure ensure I don't have any hostinfo artifacts from evil")
	assert.Nil(t, myControl.GetHostInfoByVpnIp(iputil.Ip2VpnIp(evilVpnIp.IP), true), "My pending hostmap should not contain evil")
	assert.Nil(t, myControl.GetHostInfoByVpnIp(iputil.Ip2VpnIp(evilVpnIp.IP), false), "My main hostmap should not contain evil")
	//NOTE: if evil lost the handshake race it may still have a tunnel since me would reject the handshake since the tunnel is complete

	//TODO: assert hostmaps for everyone
	t.Log("Success!")
	myControl.Stop()
	theirControl.Stop()
}

func Test_Case1_Stage1Race(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIpNet, myUdpAddr, _ := newSimpleServer(ca, caKey, "me  ", net.IP{10, 0, 0, 1}, nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2}, nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.IP, myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake to start on both me and them")
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))
	theirControl.InjectTunUDPPacket(myVpnIpNet.IP, 80, 80, []byte("Hi from them"))

	t.Log("Get both stage 1 handshake packets")
	myHsForThem := myControl.GetFromUDP(true)
	theirHsForMe := theirControl.GetFromUDP(true)

	r.Log("Now inject both stage 1 handshake packets")
	r.InjectUDPPacket(theirControl, myControl, theirHsForMe)
	r.InjectUDPPacket(myControl, theirControl, myHsForThem)
	//TODO: they should win, grab their index for me and make sure I use it in the end.

	r.Log("They should not have a stage 2 (won the race) but I should send one")
	r.InjectUDPPacket(myControl, theirControl, myControl.GetFromUDP(true))

	r.Log("Route for me until I send a message packet to them")
	r.RouteForAllUntilAfterMsgTypeTo(theirControl, header.Message, header.MessageNone)

	t.Log("My cached packet should be received by them")
	myCachedPacket := theirControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from me"), myCachedPacket, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)

	t.Log("Route for them until I send a message packet to me")
	theirControl.WaitForType(1, 0, myControl)

	t.Log("Their cached packet should be received by me")
	theirCachedPacket := myControl.GetFromTun(true)
	assertUdpPacket(t, []byte("Hi from them"), theirCachedPacket, theirVpnIpNet.IP, myVpnIpNet.IP, 80, 80)

	t.Log("Do a bidirectional tunnel test")
	assertTunnel(t, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl, r)

	myControl.Stop()
	theirControl.Stop()
	//TODO: assert hostmaps
}

func TestRelays(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIpNet, _, _ := newSimpleServer(ca, caKey, "me     ", net.IP{10, 0, 0, 1}, m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(ca, caKey, "relay  ", net.IP{10, 0, 0, 128}, m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", net.IP{10, 0, 0, 2}, m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.IP, relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet.IP, []net.IP{relayVpnIpNet.IP})
	relayControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Trigger a handshake from me to them via the relay")
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))

	p := r.RouteForAllUntilTxTun(theirControl)
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)
	//TODO: assert we actually used the relay even though it should be impossible for a tunnel to have occurred without it
}

func TestRehanshaking(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServer(ca, caKey, "me  ", net.IP{10, 0, 0, 1}, nil)
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them", net.IP{10, 0, 0, 2}, nil)

	// Put their info in our lighthouse and vice versa
	myControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)
	theirControl.InjectLightHouseAddr(myVpnIpNet.IP, myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	theirControl.Start()

	t.Log("Make sure a packet can flow")
	myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))
	p := r.RouteForAllUntilTxTun(theirControl)
	_ = p //TODO: assert packet

	t.Log("Renew certificate and spin until their sees my new certificate")
	_, _, myNextPrivKey, myNextPEM := newTestCert(ca, caKey, "me", time.Now(), time.Now().Add(5*time.Minute), myVpnIpNet, nil, []string{"new group"})

	caB, err := ca.MarshalToPEM()
	if err != nil {
		panic(err)
	}

	myConfig.Settings["pki"] = m{
		"ca":   string(caB),
		"cert": string(myNextPEM),
		"key":  string(myNextPrivKey),
	}
	rc, err := yaml.Marshal(myConfig.Settings)
	assert.NoError(t, err)
	myConfig.ReloadConfigString(string(rc))

	//TODO: assert new cert is in memory

	for {
		myControl.InjectTunUDPPacket(theirVpnIpNet.IP, 80, 80, []byte("Hi from me"))
		p := r.RouteForAllUntilTxTun(theirControl)
		_ = p //TODO: assert packet
		c := theirControl.GetHostInfoByVpnIp(iputil.Ip2VpnIp(myVpnIpNet.IP), false)
		if len(c.Cert.Details.Groups) != 0 {
			t.Log(c.Cert.Details.Groups)
			break
		}
	}
}

//TODO: add a test with many lies
