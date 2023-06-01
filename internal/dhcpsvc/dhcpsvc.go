package dhcpsvc

import (
	"context"
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

type Interface interface {
	agh.Service

	Leases() (leases []*Lease)
	LeaseByIP(ip netip.Addr) (l *Lease)
	LeaseByHostname(hostname string) (l *Lease)
}

type Empty struct{}

// type check
var _ agh.Service = Empty{}

// Start implements the [agh.Service] interface for Empty.
func (e Empty) Start() (err error) {
	return nil
}

// Shutdown implements the [agh.Service] interface for Empty.
func (e Empty) Shutdown(_ context.Context) (err error) {
	return nil
}

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
