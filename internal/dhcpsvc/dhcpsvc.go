// Package dhcpsvc contains the AdGuard Home DHCP service.
//
// TODO(e.burkov): Add tests.
package dhcpsvc

import (
	"context"
	"net"
	"net/netip"
	"time"

	"github.com/AdguardTeam/AdGuardHome/internal/next/agh"
)

// Lease is a DHCP lease.
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
	agh.ServiceWithConfig[*Config]

	// HostByIP returns the hostname of the DHCP client with the given IP
	// address, if any.
	HostByIP(ip netip.Addr) (host string, ok bool)

	// MACByIP returns the MAC address of the DHCP client with the given IP
	// address, if any.
	MACByIP(ip netip.Addr) (mac net.HardwareAddr)

	// IPByHost returns the IP address of the DHCP client with the given
	// hostname, if any.
	IPByHost(host string) (ip netip.Addr, ok bool)

	// Leases returns all the DHCP leases.
	Leases() (leases []*Lease)

	// AddLease adds a new DHCP lease.  It returns an error if the lease is
	// invalid or already exists.
	AddLease(l *Lease) (err error)

	// EditLease changes an existing DHCP lease.  It returns an error if there
	// is no lease equal to old or if new is invalid or already exists.
	EditLease(old, new *Lease) (err error)

	// RemoveLease removes an existing DHCP lease.  It returns an error if there
	// is no lease equal to l.
	RemoveLease(l *Lease) (err error)

	// Reset removes all the DHCP leases.
	Reset() (err error)
}

// Empty is an [Interface] implementation that does nothing.
type Empty struct{}

// type check
var _ Interface = Empty{}

// Start implements the [Service] interface for Empty.
func (Empty) Start() (err error) { return nil }

// Shutdown implements the [Service] interface for Empty.
func (Empty) Shutdown(_ context.Context) (err error) { return nil }

var _ agh.ServiceWithConfig[*Config] = Empty{}

// Config implements the [ServiceWithConfig] interface for Empty.
func (Empty) Config() (conf *Config) { return nil }

// HostByIP implements the [Interface] interface for Empty.
func (Empty) HostByIP(_ netip.Addr) (host string, ok bool) { return "", false }

// MACByIP implements the [Interface] interface for Empty.
func (Empty) MACByIP(_ netip.Addr) (mac net.HardwareAddr) { return nil }

// IPByHost implements the [Interface] interface for Empty.
func (Empty) IPByHost(_ string) (ip netip.Addr, ok bool) { return netip.Addr{}, false }

// Leases implements the [Interface] interface for Empty.
func (Empty) Leases() (leases []*Lease) { return nil }

// AddLease implements the [Interface] interface for Empty.
func (Empty) AddLease(_ *Lease) (err error) { return nil }

// EditLease implements the [Interface] interface for Empty.
func (Empty) EditLease(_, _ *Lease) (err error) { return nil }

// RemoveLease implements the [Interface] interface for Empty.
func (Empty) RemoveLease(_ *Lease) (err error) { return nil }

// Reset implements the [Interface] interface for Empty.
func (Empty) Reset() (err error) { return nil }
