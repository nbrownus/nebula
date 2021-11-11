package overlay

import (
	"io"
	"net"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/config"
	"github.com/slackhq/nebula/iputil"
	"github.com/slackhq/nebula/util"
)

const DefaultMTU = 1300

type Device interface {
	io.ReadWriteCloser
	Activate() error
	CidrNet() *net.IPNet
	DeviceName() string
	WriteRaw([]byte) error
	RouteFor(iputil.VpnIp) iputil.VpnIp
	NewMultiQueueReader() (io.ReadWriteCloser, error)
}

func NewTunFromConfig(c *config.C, l *logrus.Logger, tunCidr *net.IPNet, fd *int, routines int) (Device, error) {
	routes, err := parseRoutes(c, tunCidr)
	if err != nil {
		return nil, util.NewContextualError("Could not parse tun.routes", nil, err)
	}

	unsafeRoutes, err := parseUnsafeRoutes(c, tunCidr)
	if err != nil {
		return nil, util.NewContextualError("Could not parse tun.unsafe_routes", nil, err)
	}
	routes = append(routes, unsafeRoutes...)

	switch {
	case c.GetBool("tun.disabled", false):
		return newDisabledTun(tunCidr, c.GetInt("tun.tx_queue", 500), c.GetBool("stats.message_metrics", false), l)

	case fd != nil:
		return newTunFromFd(
			l,
			*fd,
			tunCidr,
			c.GetInt("tun.mtu", DefaultMTU),
			routes,
			c.GetInt("tun.tx_queue", 500),
		)

	default:
		return newTun(
			l,
			c.GetString("tun.dev", ""),
			tunCidr,
			c.GetInt("tun.mtu", DefaultMTU),
			routes,
			c.GetInt("tun.tx_queue", 500),
			routines > 1,
		)
	}
}
