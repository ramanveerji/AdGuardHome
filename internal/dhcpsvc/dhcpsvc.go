// Package dhcpsvc contains the AdGuard Home DHCP service.
//
// TODO(e.burkov): Add tests.
package dhcpsvc

import (
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/next/agh"
)

type Lease struct {
	// IP is the IP address leased to the client.
	IP netip.Addr

	// Expiry is the expiration time of the lease.
	Expiry time.Time

	// Hostname of the client.
	Hostname string

	// HWAddr is the physical hardware address (MAC address).
	HWAddr net.HardwareAddr

	// IsStatic defines if the lease is static.
	IsStatic bool
}

type Leaser interface {
	Leases() (leases []*Lease)
	LeaseByIP(ip netip.Addr) (l *Lease)
	LeaseByHostname(hostname string) (l *Lease)

	AddLease(l *Lease) (err error)
	RemoveLease(l *Lease) (err error)
	Reset() (err error)
}

type Interface interface {
	agh.ServiceWithConfig[Config]
	Leaser
}

type Empty struct {
	*agh.EmptyServiceWithConfig[*Config]
}

// type check
var _ agh.ServiceWithConfig[*Config] = Empty{}

// Leases implements the [Interface] interface for Empty.
func (e Empty) Leases() (leases []*Lease) {
	return nil
}

// LeaseByIP implements the [Interface] interface for Empty.
func (e Empty) LeaseByIP(ip netip.Addr) (l *Lease) {
	return nil
}

// LeaseByHostname implements the [Interface] interface for Empty.
func (e Empty) LeaseByHostname(hostname string) (l *Lease) {
	return nil
}

// AddLease implements the [Interface] interface for Empty.
func (e Empty) AddLease(l *Lease) (err error) {
	return nil
}
