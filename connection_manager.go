package nebula

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/slackhq/nebula/header"
)

// TODO: incount and outcount are intended as a shortcut to locking the mutexes for every single packet
// and something like every 10 packets we could lock, send 10, then unlock for a moment

type connectionManager struct {
	hostMap      *HostMap
	in           map[uint32]struct{}
	inLock       *sync.RWMutex
	out          map[uint32]struct{}
	outLock      *sync.RWMutex
	TrafficTimer *LockingTimerWheel[uint32]
	intf         *Interface

	pendingDeletion      map[uint32]int
	pendingDeletionLock  *sync.RWMutex
	pendingDeletionTimer *LockingTimerWheel[uint32]

	checkInterval           int
	pendingDeletionInterval int

	l *logrus.Logger
	// I wanted to call one matLock
}

func newConnectionManager(ctx context.Context, l *logrus.Logger, intf *Interface, checkInterval, pendingDeletionInterval int) *connectionManager {
	nc := &connectionManager{
		hostMap:                 intf.hostMap,
		in:                      make(map[uint32]struct{}),
		inLock:                  &sync.RWMutex{},
		out:                     make(map[uint32]struct{}),
		outLock:                 &sync.RWMutex{},
		TrafficTimer:            NewLockingTimerWheel[uint32](time.Millisecond*500, time.Second*60),
		intf:                    intf,
		pendingDeletion:         make(map[uint32]int),
		pendingDeletionLock:     &sync.RWMutex{},
		pendingDeletionTimer:    NewLockingTimerWheel[uint32](time.Millisecond*500, time.Second*60),
		checkInterval:           checkInterval,
		pendingDeletionInterval: pendingDeletionInterval,
		l:                       l,
	}
	nc.Start(ctx)
	return nc
}

func (n *connectionManager) In(localIndex uint32) {
	n.inLock.RLock()
	// If this already exists, return
	if _, ok := n.in[localIndex]; ok {
		n.inLock.RUnlock()
		return
	}
	n.inLock.RUnlock()
	n.inLock.Lock()
	n.in[localIndex] = struct{}{}
	n.inLock.Unlock()
}

func (n *connectionManager) Out(localIndex uint32) {
	n.outLock.RLock()
	// If this already exists, return
	if _, ok := n.out[localIndex]; ok {
		n.outLock.RUnlock()
		return
	}
	n.outLock.RUnlock()
	n.outLock.Lock()
	// double check since we dropped the lock temporarily
	if _, ok := n.out[localIndex]; ok {
		n.outLock.Unlock()
		return
	}
	n.out[localIndex] = struct{}{}
	n.AddTrafficWatch(localIndex, n.checkInterval)
	n.outLock.Unlock()
}

func (n *connectionManager) CheckIn(localIndex uint32) bool {
	n.inLock.RLock()
	if _, ok := n.in[localIndex]; ok {
		n.inLock.RUnlock()
		return true
	}
	n.inLock.RUnlock()
	return false
}

func (n *connectionManager) ClearLocalIndex(localIndex uint32) {
	n.inLock.Lock()
	n.outLock.Lock()
	delete(n.in, localIndex)
	delete(n.out, localIndex)
	n.inLock.Unlock()
	n.outLock.Unlock()
}

func (n *connectionManager) ClearPendingDeletion(localIndex uint32) {
	n.pendingDeletionLock.Lock()
	delete(n.pendingDeletion, localIndex)
	n.pendingDeletionLock.Unlock()
}

func (n *connectionManager) AddPendingDeletion(localIndex uint32) {
	n.pendingDeletionLock.Lock()
	if _, ok := n.pendingDeletion[localIndex]; ok {
		n.pendingDeletion[localIndex] += 1
	} else {
		n.pendingDeletion[localIndex] = 0
	}
	n.pendingDeletionTimer.Add(localIndex, time.Second*time.Duration(n.pendingDeletionInterval))
	n.pendingDeletionLock.Unlock()
}

func (n *connectionManager) checkPendingDeletion(localIndex uint32) bool {
	n.pendingDeletionLock.RLock()
	if _, ok := n.pendingDeletion[localIndex]; ok {

		n.pendingDeletionLock.RUnlock()
		return true
	}
	n.pendingDeletionLock.RUnlock()
	return false
}

func (n *connectionManager) AddTrafficWatch(localIndex uint32, seconds int) {
	n.TrafficTimer.Add(localIndex, time.Second*time.Duration(seconds))
}

func (n *connectionManager) Start(ctx context.Context) {
	go n.Run(ctx)
}

func (n *connectionManager) Run(ctx context.Context) {
	clockSource := time.NewTicker(500 * time.Millisecond)
	defer clockSource.Stop()

	p := []byte("")
	nb := make([]byte, 12, 12)
	out := make([]byte, mtu)

	for {
		select {
		case <-ctx.Done():
			return
		case now := <-clockSource.C:
			n.HandleMonitorTick(now, p, nb, out)
			n.HandleDeletionTick(now)
		}
	}
}

func (n *connectionManager) HandleMonitorTick(now time.Time, p, nb, out []byte) {
	n.TrafficTimer.Advance(now)
	for {
		localIndex, has := n.TrafficTimer.Purge()
		if !has {
			break
		}

		// Check for traffic coming back in from this host.
		traf := n.CheckIn(localIndex)

		hostinfo, err := n.hostMap.QueryIndex(localIndex)
		if err != nil {
			n.l.WithField("localIndex", localIndex).Debugf("Not found in hostmap")
			n.ClearLocalIndex(localIndex)
			n.ClearPendingDeletion(localIndex)
			continue
		}

		if n.handleInvalidCertificate(now, hostinfo) {
			continue
		}

		// Does the vpnIp point to this hostinfo or is it ancillary? If we have ancillary hostinfos then we need to
		// decide if this should be the main hostinfo if we are seeing traffic on it
		primary, _ := n.hostMap.QueryVpnIp(hostinfo.vpnIp)
		mainHostInfo := true
		if primary != nil && primary != hostinfo {
			mainHostInfo = false
		}

		// If we saw an incoming packets from this ip and peer's certificate is not
		// expired, just ignore.
		if traf {
			if n.l.Level >= logrus.DebugLevel {
				hostinfo.logger(n.l).
					WithField("tunnelCheck", m{"state": "alive", "method": "passive"}).
					Debug("Tunnel status")
			}
			n.ClearLocalIndex(localIndex)
			n.ClearPendingDeletion(localIndex)

			if !mainHostInfo {
				newPeerCert := hostinfo.ConnectionState.peerCert.Details.NotBefore.After(primary.ConnectionState.peerCert.Details.NotBefore)
				newLocalCert := hostinfo.ConnectionState.certState.certificate.Details.NotBefore.After(primary.ConnectionState.certState.certificate.Details.NotBefore)
				if hostinfo.vpnIp > n.intf.myVpnIp && (newPeerCert || newLocalCert) {
					// We are receiving traffic on the non primary hostinfo and we really just want 1 tunnel. Make
					// This the primary and prime the old primary hostinfo for testing
					n.l.Error("***************************** SWAPPING PRIMARY", hostinfo.vpnIp)
					n.l.Error("***************************** SWAPPING PRIMARY", hostinfo.vpnIp)
					n.l.Error("***************************** SWAPPING PRIMARY", hostinfo.vpnIp)
					n.l.Error("***************************** SWAPPING PRIMARY", hostinfo.vpnIp)
					n.l.Error("***************************** SWAPPING PRIMARY", hostinfo.vpnIp)
					n.hostMap.MakePrimary(hostinfo)
					n.Out(primary.localIndexId)
				} else {
					// This hostinfo is still being used despite not being the primary hostinfo for this vpn ip
					// Keep tracking so that we can tear it down when it goes away
					n.Out(hostinfo.localIndexId)
				}

			} else {
				n.handleRehandshake(hostinfo)
			}

			continue
		}

		hostinfo.logger(n.l).
			WithField("tunnelCheck", m{"state": "testing", "method": "active"}).
			Debug("Tunnel status")

		if hostinfo != nil && hostinfo.ConnectionState != nil && mainHostInfo {
			// Send a test packet to trigger an authenticated tunnel test, this should suss out any lingering tunnel issues
			n.intf.sendMessageToVpnIp(header.Test, header.TestRequest, hostinfo, p, nb, out)

		} else {
			hostinfo.logger(n.l).Debugf("Hostinfo sadness")
		}
		n.AddPendingDeletion(localIndex)
	}

}

func (n *connectionManager) HandleDeletionTick(now time.Time) {
	n.pendingDeletionTimer.Advance(now)
	for {
		localIndex, has := n.pendingDeletionTimer.Purge()
		if !has {
			break
		}

		hostinfo, err := n.hostMap.QueryIndex(localIndex)
		if err != nil {
			n.l.WithField("localIndex", localIndex).Debugf("Not found in hostmap")
			n.ClearLocalIndex(localIndex)
			n.ClearPendingDeletion(localIndex)
			continue
		}

		if n.handleInvalidCertificate(now, hostinfo) {
			continue
		}

		// If we saw an incoming packets from this ip and peer's certificate is not
		// expired, just ignore.
		traf := n.CheckIn(localIndex)
		if traf {
			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "alive", "method": "active"}).
				Debug("Tunnel status")

			primary, _ := n.hostMap.QueryVpnIp(hostinfo.vpnIp)
			if primary != nil && primary != hostinfo {
				// Keep tracking non primary host infos
				n.Out(localIndex)
			} else {
				n.ClearLocalIndex(localIndex)
				n.ClearPendingDeletion(localIndex)
			}

			continue
		}

		// If it comes around on deletion wheel and hasn't resolved itself, delete
		if n.checkPendingDeletion(localIndex) {
			cn := ""
			if hostinfo.ConnectionState != nil && hostinfo.ConnectionState.peerCert != nil {
				cn = hostinfo.ConnectionState.peerCert.Details.Name
			}

			hostinfo.logger(n.l).
				WithField("tunnelCheck", m{"state": "dead", "method": "active"}).
				WithField("certName", cn).
				Info("Tunnel status")

			n.hostMap.DeleteHostInfo(hostinfo)
		}

		n.ClearLocalIndex(localIndex)
		n.ClearPendingDeletion(localIndex)
	}
}

func (n *connectionManager) handleRehandshake(hostinfo *HostInfo) {
	certState := n.intf.certState.Load()
	if hostinfo.ConnectionState.certState == certState {
		return
	}

	for _, relayIdx := range hostinfo.relayState.CopyRelayToIndexes() {
		relayHi, _ := n.hostMap.QueryIndex(relayIdx)
		if relayHi == nil {
			// This relay doesn't exist, something else should clean it up
			continue
		}

		primaryHi, _ := n.hostMap.QueryVpnIp(relayHi.vpnIp)
		if primaryHi != nil && primaryHi != relayHi {
			// The relay in use here is non primary, assume we have upgraded it
			continue
		}

		if relayHi.ConnectionState.certState != certState {
			// Can't upgrade the relayed tunnel until we upgrade the relays
			return
		}
	}

	n.l.WithField("vpnIp", hostinfo.vpnIp).
		WithField("reason", "my certificate changed").
		Info("Re-handshaking with remote")

	//TODO: this is copied from getOrHandshake to keep the extra checks out of the hot path, figure it out
	fmt.Println("**********************************************************************************************")
	fmt.Println("**********************************************************************************************")
	fmt.Println("**********************************************************************************************")
	newHostinfo := n.intf.handshakeManager.AddVpnIp(hostinfo.vpnIp, n.intf.initHostInfo)
	if !newHostinfo.HandshakeReady {
		ixHandshakeStage0(n.intf, newHostinfo.vpnIp, newHostinfo)
	}

	//If this is a static host, we don't need to wait for the HostQueryReply
	//We can trigger the handshake right now
	if _, ok := n.intf.lightHouse.GetStaticHostList()[hostinfo.vpnIp]; ok {
		select {
		case n.intf.handshakeManager.trigger <- hostinfo.vpnIp:
		default:
		}
	}
}

// handleInvalidCertificates will destroy a tunnel if pki.disconnect_invalid is true and the certificate is no longer valid
func (n *connectionManager) handleInvalidCertificate(now time.Time, hostinfo *HostInfo) bool {
	if !n.intf.disconnectInvalid {
		return false
	}

	remoteCert := hostinfo.GetCert()
	if remoteCert == nil {
		return false
	}

	valid, err := remoteCert.Verify(now, n.intf.caPool)
	if valid {
		return false
	}

	fingerprint, _ := remoteCert.Sha256Sum()
	hostinfo.logger(n.l).WithError(err).
		WithField("fingerprint", fingerprint).
		Info("Remote certificate is no longer valid, tearing down the tunnel")

	// Inform the remote and close the tunnel locally
	n.intf.sendCloseTunnel(hostinfo)
	n.intf.closeTunnel(hostinfo)

	n.ClearLocalIndex(hostinfo.localIndexId)
	n.ClearPendingDeletion(hostinfo.localIndexId)
	return true
}
