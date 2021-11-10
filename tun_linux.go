//go:build !android && !e2e_testing
// +build !android,!e2e_testing

package nebula

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync/atomic"
	"unsafe"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/cidr"
	"github.com/slackhq/nebula/iputil"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type Tun struct {
	io.ReadWriteCloser
	fd         int
	Device     string
	Cidr       *net.IPNet
	MaxMTU     int
	DefaultMTU int
	TXQueueLen int
	Routes     []route
	cidrTree   *cidr.Tree4
	routeChan  chan netlink.RouteUpdate
	l          *logrus.Logger
}

type ifReq struct {
	Name  [16]byte
	Flags uint16
	pad   [8]byte
}

func ioctl(a1, a2, a3 uintptr) error {
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, a1, a2, a3)
	if errno != 0 {
		return errno
	}
	return nil
}

type ifreqAddr struct {
	Name [16]byte
	Addr unix.RawSockaddrInet4
	pad  [8]byte
}

type ifreqMTU struct {
	Name [16]byte
	MTU  int32
	pad  [8]byte
}

type ifreqQLEN struct {
	Name  [16]byte
	Value int32
	pad   [8]byte
}

func newTunFromFd(l *logrus.Logger, deviceFd int, certCIDR *net.IPNet, defaultMTU int, routes []route, txQueueLen int) (ifce *Tun, err error) {
	file := os.NewFile(uintptr(deviceFd), "/dev/net/tun")

	cidrTree := cidr.NewTree4()
	for _, r := range routes {
		if r.via != nil {
			cidrTree.AddCIDR(r.route, r.via)
		}
	}

	ifce = &Tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          "tun0",
		Cidr:            certCIDR,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		cidrTree:        cidrTree,
		l:               l,
	}
	return
}

func newTun(l *logrus.Logger, deviceName string, certCIDR *net.IPNet, defaultMTU int, routes []route, txQueueLen int, multiqueue bool) (ifce *Tun, err error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI)
	if multiqueue {
		req.Flags |= unix.IFF_MULTI_QUEUE
	}

	copy(req.Name[:], deviceName)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}
	name := strings.Trim(string(req.Name[:]), "\x00")

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	cidrTree := cidr.NewTree4()
	maxMTU := defaultMTU
	for _, r := range routes {
		if r.mtu > maxMTU {
			maxMTU = r.mtu
		}

		if r.via != nil {
			cidrTree.AddCIDR(r.route, r.via)
		}
	}

	ifce = &Tun{
		ReadWriteCloser: file,
		fd:              int(file.Fd()),
		Device:          name,
		Cidr:            certCIDR,
		MaxMTU:          maxMTU,
		DefaultMTU:      defaultMTU,
		TXQueueLen:      txQueueLen,
		Routes:          routes,
		cidrTree:        cidrTree,
		l:               l,
	}
	return
}

func (c *Tun) NewMultiQueueReader() (io.ReadWriteCloser, error) {
	fd, err := unix.Open("/dev/net/tun", os.O_RDWR, 0)
	if err != nil {
		return nil, err
	}

	var req ifReq
	req.Flags = uint16(unix.IFF_TUN | unix.IFF_NO_PI | unix.IFF_MULTI_QUEUE)
	copy(req.Name[:], c.Device)
	if err = ioctl(uintptr(fd), uintptr(unix.TUNSETIFF), uintptr(unsafe.Pointer(&req))); err != nil {
		return nil, err
	}

	file := os.NewFile(uintptr(fd), "/dev/net/tun")

	return file, nil
}

func (c *Tun) Close() error {
	if c.ReadWriteCloser != nil {
		c.ReadWriteCloser.Close()
	}

	if c.routeChan != nil {
		close(c.routeChan)
	}

	return nil
}

func (c *Tun) WriteRaw(b []byte) error {
	var nn int
	for {
		max := len(b)
		n, err := unix.Write(c.fd, b[nn:max])
		if n > 0 {
			nn += n
		}
		if nn == len(b) {
			return err
		}

		if err != nil {
			return err
		}

		if n == 0 {
			return io.ErrUnexpectedEOF
		}
	}
}

func (c *Tun) Write(b []byte) (int, error) {
	return len(b), c.WriteRaw(b)
}

func (c Tun) deviceBytes() (o [16]byte) {
	for i, c := range c.Device {
		o[i] = byte(c)
	}
	return
}

func (c Tun) Activate() error {
	devName := c.deviceBytes()

	c.watchRoutes()
	var addr, mask [4]byte

	copy(addr[:], c.Cidr.IP.To4())
	copy(mask[:], c.Cidr.Mask)

	s, err := unix.Socket(
		unix.AF_INET,
		unix.SOCK_DGRAM,
		unix.IPPROTO_IP,
	)
	if err != nil {
		return err
	}
	fd := uintptr(s)

	ifra := ifreqAddr{
		Name: devName,
		Addr: unix.RawSockaddrInet4{
			Family: unix.AF_INET,
			Addr:   addr,
		},
	}

	// Set the device ip address
	if err = ioctl(fd, unix.SIOCSIFADDR, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set tun address: %s", err)
	}

	// Set the device network
	ifra.Addr.Addr = mask
	if err = ioctl(fd, unix.SIOCSIFNETMASK, uintptr(unsafe.Pointer(&ifra))); err != nil {
		return fmt.Errorf("failed to set tun netmask: %s", err)
	}

	// Set the device name
	ifrf := ifReq{Name: devName}
	if err = ioctl(fd, unix.SIOCGIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to set tun device name: %s", err)
	}

	// Set the MTU on the device
	ifm := ifreqMTU{Name: devName, MTU: int32(c.MaxMTU)}
	if err = ioctl(fd, unix.SIOCSIFMTU, uintptr(unsafe.Pointer(&ifm))); err != nil {
		// This is currently a non fatal condition because the route table must have the MTU set appropriately as well
		c.l.WithError(err).Error("Failed to set tun mtu")
	}

	// Set the transmit queue length
	ifrq := ifreqQLEN{Name: devName, Value: int32(c.TXQueueLen)}
	if err = ioctl(fd, unix.SIOCSIFTXQLEN, uintptr(unsafe.Pointer(&ifrq))); err != nil {
		// If we can't set the queue length nebula will still work but it may lead to packet loss
		c.l.WithError(err).Error("Failed to set tun tx queue length")
	}

	// Bring up the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to bring the tun device up: %s", err)
	}

	// Set the routes
	link, err := netlink.LinkByName(c.Device)
	if err != nil {
		return fmt.Errorf("failed to get tun device link: %s", err)
	}

	// Default route
	dr := &net.IPNet{IP: c.Cidr.IP.Mask(c.Cidr.Mask), Mask: c.Cidr.Mask}
	nr := netlink.Route{
		LinkIndex: link.Attrs().Index,
		Dst:       dr,
		MTU:       c.DefaultMTU,
		AdvMSS:    c.advMSS(route{}),
		Scope:     unix.RT_SCOPE_LINK,
		Src:       c.Cidr.IP,
		Protocol:  unix.RTPROT_KERNEL,
		Table:     unix.RT_TABLE_MAIN,
		Type:      unix.RTN_UNICAST,
	}
	err = netlink.RouteReplace(&nr)
	if err != nil {
		return fmt.Errorf("failed to set mtu %v on the default route %v; %v", c.DefaultMTU, dr, err)
	}

	// Path routes
	for _, r := range c.Routes {
		nr := netlink.Route{
			LinkIndex: link.Attrs().Index,
			Dst:       r.route,
			MTU:       r.mtu,
			Priority:  r.metric,
			AdvMSS:    c.advMSS(r),
			Scope:     unix.RT_SCOPE_LINK,
		}

		err = netlink.RouteAdd(&nr)
		if err != nil {
			return fmt.Errorf("failed to set mtu %v on route %v; %v", r.mtu, r.route, err)
		}
	}

	// Run the interface
	ifrf.Flags = ifrf.Flags | unix.IFF_UP | unix.IFF_RUNNING
	if err = ioctl(fd, unix.SIOCSIFFLAGS, uintptr(unsafe.Pointer(&ifrf))); err != nil {
		return fmt.Errorf("failed to run tun device: %s", err)
	}

	return nil
}

func (c *Tun) CidrNet() *net.IPNet {
	return c.Cidr
}

func (c *Tun) DeviceName() string {
	return c.Device
}

func (c Tun) advMSS(r route) int {
	mtu := c.DefaultMTU

	if r.mtu != 0 {
		mtu = r.mtu
	}

	// We only need to set advmss if the route MTU does not match the device MTU
	if mtu != c.MaxMTU {
		return mtu - 40
	}

	return 0
}

func (c *Tun) RouteFor(ip iputil.VpnIp) iputil.VpnIp {
	r := c.cidrTree.MostSpecificContains(ip)
	if r != nil {
		return r.(iputil.VpnIp)
	}

	return 0
}

func (c *Tun) watchRoutes() {
	rch := make(chan netlink.RouteUpdate)
	dch := make(chan struct{})

	if err := netlink.RouteSubscribe(rch, dch); err != nil {
		c.l.WithError(err).Errorf("failed to subscribe to system route changes")
		return
	}

	c.routeChan = rch

	go func() {
		for {
			select {
			case r := <-rch:
				c.updateRoutes(r)
			case <-dch:
				close(rch)
				break
			}
		}
	}()
}

func (c *Tun) updateRoutes(r netlink.RouteUpdate) {
	if r.Gw == nil {
		// Not a gateway route, ignore
		c.l.WithField("route", r).Debug("Ignoring route update, not a gateway route")
		return
	}

	if !c.Cidr.Contains(r.Gw) {
		// Gateway isn't in our network, ignore
		c.l.WithField("route", r).Debug("Ignoring route update, not in our network")
		return
	}

	if x := r.Dst.IP.To4(); x == nil {
		c.l.WithField("route", r).Debug("Ignoring route update, destination is not ipv4")
		return
	}

	newTree := cidr.NewTree4()
	if r.Type == unix.RTM_NEWROUTE {
		//TODO: come up with a way to support priority/metrics
		for _, oldR := range c.cidrTree.List() {
			newTree.AddCIDR(oldR.CIDR, oldR.Value)
		}

		c.l.WithField("destination", r.Dst).WithField("via", r.Gw).Info("Adding route")
		newTree.AddCIDR(r.Dst, iputil.Ip2VpnIp(r.Gw))

	} else {
		gw := iputil.Ip2VpnIp(r.Gw)
		for _, oldR := range c.cidrTree.List() {
			if bytes.Equal(oldR.CIDR.IP, r.Dst.IP) && bytes.Equal(oldR.CIDR.Mask, r.Dst.Mask) && *oldR.Value != nil && (*oldR.Value).(iputil.VpnIp) == gw {
				// This is the record to delete
				c.l.WithField("destination", r.Dst).WithField("via", r.Gw).Info("Removing route")
				continue
			}

			newTree.AddCIDR(oldR.CIDR, oldR.Value)
		}
	}

	atomic.SwapPointer((*unsafe.Pointer)(unsafe.Pointer(&c.cidrTree)), (unsafe.Pointer)(newTree))
}
