package nebula

import (
	"github.com/slackhq/nebula/test"
	"github.com/stretchr/testify/assert"
	"net"
	"testing"
)

func TestHostMap_MakePrimary(t *testing.T) {
	l := test.NewLogger()
	hm := NewHostMap(
		l, "test",
		&net.IPNet{
			IP:   net.IP{10, 0, 0, 1},
			Mask: net.IPMask{255, 255, 255, 0},
		},
		[]*net.IPNet{},
	)

	f := &Interface{}

	h1 := &HostInfo{vpnIp: 1, localIndexId: 1}
	h2 := &HostInfo{vpnIp: 1, localIndexId: 2}
	h3 := &HostInfo{vpnIp: 1, localIndexId: 3}
	h4 := &HostInfo{vpnIp: 1, localIndexId: 4}

	hm.unlockedAddHostInfo(h4, f)
	hm.unlockedAddHostInfo(h3, f)
	hm.unlockedAddHostInfo(h2, f)
	hm.unlockedAddHostInfo(h1, f)

	// Make sure we go h1 -> h2 -> h3 -> h4
	prim, _ := hm.QueryVpnIp(1)
	assert.Equal(t, h1.localIndexId, prim.localIndexId)
	assert.Equal(t, h2.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Equal(t, h3.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h2.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h4.prev.localIndexId)
	assert.Nil(t, h4.next)

	// Swap h3/middle to primary
	hm.MakePrimary(h3)

	// Make sure we go h3 -> h1 -> h2 -> h4
	prim, _ = hm.QueryVpnIp(1)
	assert.Equal(t, h3.localIndexId, prim.localIndexId)
	assert.Equal(t, h1.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h2.localIndexId, h1.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h1.prev.localIndexId)
	assert.Equal(t, h4.localIndexId, h2.next.localIndexId)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Equal(t, h2.localIndexId, h4.prev.localIndexId)
	assert.Nil(t, h4.next)

	// Swap h4/tail to primary
	hm.MakePrimary(h4)

	// Make sure we go h4 -> h3 -> h1 -> h2
	prim, _ = hm.QueryVpnIp(1)
	assert.Equal(t, h4.localIndexId, prim.localIndexId)
	assert.Equal(t, h3.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h2.localIndexId, h1.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h1.prev.localIndexId)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Nil(t, h2.next)

	// Swap h4 again should be no-op
	hm.MakePrimary(h4)

	// Make sure we go h4 -> h3 -> h1 -> h2
	prim, _ = hm.QueryVpnIp(1)
	assert.Equal(t, h4.localIndexId, prim.localIndexId)
	assert.Equal(t, h3.localIndexId, prim.next.localIndexId)
	assert.Nil(t, prim.prev)
	assert.Equal(t, h1.localIndexId, h3.next.localIndexId)
	assert.Equal(t, h4.localIndexId, h3.prev.localIndexId)
	assert.Equal(t, h2.localIndexId, h1.next.localIndexId)
	assert.Equal(t, h3.localIndexId, h1.prev.localIndexId)
	assert.Equal(t, h1.localIndexId, h2.prev.localIndexId)
	assert.Nil(t, h2.next)
}
