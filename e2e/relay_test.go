//go:build e2e_testing
// +build e2e_testing

package e2e

import (
	"net"
	"testing"
	"time"

	"github.com/slackhq/nebula/e2e/router"
	"github.com/slackhq/nebula/iputil"
	"github.com/stretchr/testify/assert"
	"gopkg.in/yaml.v2"
)

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
	r.Log("Assert the tunnel works")
	assertUdpPacket(t, []byte("Hi from me"), p, myVpnIpNet.IP, theirVpnIpNet.IP, 80, 80)
	r.RenderHostmaps("Final hostmaps", myControl, relayControl, theirControl)
	//TODO: assert we actually used the relay even though it should be impossible for a tunnel to have occurred without it
}

func TestRelaysRehandshake(t *testing.T) {
	ca, _, caKey, _ := newTestCaCert(time.Now(), time.Now().Add(10*time.Minute), []*net.IPNet{}, []*net.IPNet{}, []string{})
	myControl, myVpnIpNet, myUdpAddr, myConfig := newSimpleServer(ca, caKey, "me     ", net.IP{10, 0, 0, 1}, m{"relay": m{"use_relays": true}})
	relayControl, relayVpnIpNet, relayUdpAddr, _ := newSimpleServer(ca, caKey, "relay  ", net.IP{10, 0, 0, 128}, m{"relay": m{"am_relay": true}})
	theirControl, theirVpnIpNet, theirUdpAddr, _ := newSimpleServer(ca, caKey, "them   ", net.IP{10, 0, 0, 2}, m{"relay": m{"use_relays": true}})

	// Teach my how to get to the relay and that their can be reached via the relay
	myControl.InjectLightHouseAddr(relayVpnIpNet.IP, relayUdpAddr)
	myControl.InjectRelays(theirVpnIpNet.IP, []net.IP{relayVpnIpNet.IP})
	theirControl.InjectLightHouseAddr(relayVpnIpNet.IP, relayUdpAddr)
	theirControl.InjectRelays(myVpnIpNet.IP, []net.IP{relayVpnIpNet.IP})
	relayControl.InjectLightHouseAddr(theirVpnIpNet.IP, theirUdpAddr)
	relayControl.InjectLightHouseAddr(myVpnIpNet.IP, myUdpAddr)

	// Build a router so we don't have to reason who gets which packet
	r := router.NewR(t, myControl, relayControl, theirControl)
	defer r.RenderFlow()

	// Start the servers
	myControl.Start()
	relayControl.Start()
	theirControl.Start()

	t.Log("Stand up a tunnel between me and them via relay")
	assertTunnel(t, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl, r)

	r.Log("Renew certificate and spin until their sees my new certificate")
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

	for {
		assertTunnel(t, myVpnIpNet.IP, theirVpnIpNet.IP, myControl, theirControl, r)
		c := theirControl.GetHostInfoByVpnIp(iputil.Ip2VpnIp(myVpnIpNet.IP), false)
		if len(c.Cert.Details.Groups) != 0 {
			t.Log(c.LocalIndex, c.RemoteIndex, c.Cert.Details.Groups)
			break
		}

		time.Sleep(time.Second)

		//TODO: assert new index ids and correct mapping to the new cert based on the index id
		//TODO: do a final udp send to ensure the new group is respected by the firewall
	}

	myControl.Stop()
	theirControl.Stop()
	relayControl.Stop()
}
